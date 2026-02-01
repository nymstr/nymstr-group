//! PGP-based key management and signing utilities using the pgp crate (0.16).
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use pgp::composed::{
    Deserializable, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    StandaloneSignature,
};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{Password, KeyDetails};
use rand::thread_rng;
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use zeroize::Zeroize;

/// Utility for PGP key generation, signing, and signature verification.
/// Password is stored securely and zeroed from memory when dropped.
pub struct CryptoUtils {
    key_dir: PathBuf,
    username: String,
    password: SecretString,
}

impl Clone for CryptoUtils {
    fn clone(&self) -> Self {
        Self {
            key_dir: self.key_dir.clone(),
            username: self.username.clone(),
            password: SecretString::new(self.password.expose_secret().clone()),
        }
    }
}

impl CryptoUtils {
    /// Initialize with the key directory, server username, and passphrase.
    /// The password is stored securely and will be zeroed from memory when dropped.
    pub fn new(key_dir: PathBuf, username: String, mut password: String) -> Result<Self> {
        if !key_dir.exists() {
            fs::create_dir_all(&key_dir)?;
        }
        // Convert to SecretString and zeroize the original
        let secret_password = SecretString::new(password.clone());
        password.zeroize();
        Ok(Self {
            key_dir,
            username,
            password: secret_password,
        })
    }

    fn derive_key(&self, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        pbkdf2_hmac(
            self.password.expose_secret().as_bytes(),
            salt,
            100_000,
            MessageDigest::sha256(),
            &mut key,
        )?;
        Ok(key)
    }

    fn encrypt_private_key(&self, private_key_pem: &[u8]) -> Result<String> {
        let mut salt = [0u8; 16];
        rand_bytes(&mut salt)?;
        let mut iv = [0u8; 12];
        rand_bytes(&mut iv)?;
        let key = self.derive_key(&salt)?;
        let cipher = Cipher::aes_256_gcm();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;
        let mut ciphertext = vec![0; private_key_pem.len() + cipher.block_size()];
        let mut count = crypter.update(private_key_pem, &mut ciphertext)?;
        count += crypter.finalize(&mut ciphertext[count..])?;
        ciphertext.truncate(count);
        let mut tag = [0u8; 16];
        crypter.get_tag(&mut tag)?;
        let mut data = Vec::new();
        data.extend_from_slice(&salt);
        data.extend_from_slice(&iv);
        data.extend_from_slice(&tag);
        data.extend_from_slice(&ciphertext);
        Ok(general_purpose::STANDARD.encode(data))
    }

    fn decrypt_private_key(&self, encrypted_data: &str) -> Result<Vec<u8>> {
        let data = general_purpose::STANDARD.decode(encrypted_data)?;
        let (salt, rest) = data.split_at(16);
        let (iv, rest) = rest.split_at(12);
        let (tag, ciphertext) = rest.split_at(16);
        let key = self.derive_key(salt)?;
        let cipher = Cipher::aes_256_gcm();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(iv))?;
        crypter.set_tag(tag)?;
        let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
        let mut count = crypter.update(ciphertext, &mut plaintext)?;
        count += crypter.finalize(&mut plaintext[count..])?;
        plaintext.truncate(count);
        Ok(plaintext)
    }

    /// Convert password to PGP Password type
    fn to_pgp_password(&self) -> Password {
        Password::from(self.password.expose_secret().as_str())
    }

    /// Generate and store a new PGP key pair using Ed25519.
    /// Returns the ASCII-armored public key.
    pub fn generate_key_pair(&self, _username: &str) -> Result<String> {
        log::info!("Generating Ed25519 PGP keypair for user: {}", self.username);

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id(self.username.clone())
            .build()?;

        let secret_key = key_params.generate(thread_rng())?;
        let signed_secret_key = secret_key.sign(&mut thread_rng(), &self.to_pgp_password())?;
        let public_key = SignedPublicKey::from(signed_secret_key.clone());

        let secret_key_armored = signed_secret_key.to_armored_string(Default::default())?;
        let public_key_armored = public_key.to_armored_string(Default::default())?;

        // Encrypt and store the private key
        let encrypted = self.encrypt_private_key(secret_key_armored.as_bytes())?;
        let priv_path = self.key_dir.join(format!("{}_private_key.enc", self.username));
        let pub_path = self.key_dir.join(format!("{}_public.asc", self.username));
        fs::write(priv_path, encrypted)?;
        fs::write(&pub_path, &public_key_armored)?;
        log::info!("Generated PGP keypair for '{}'", self.username);
        Ok(public_key_armored)
    }

    /// Load and decrypt the private key.
    fn load_private_key(&self) -> Result<SignedSecretKey> {
        let path = self.key_dir.join(format!("{}_private_key.enc", self.username));
        let encrypted = fs::read_to_string(path)?;
        let decrypted = self.decrypt_private_key(&encrypted)?;
        let armored_key = String::from_utf8(decrypted)?;
        let (secret_key, _headers) = SignedSecretKey::from_string(&armored_key)?;
        Ok(secret_key)
    }

    /// Sign a message and return an ASCII-armored signature.
    pub fn sign_message(&self, _username: &str, message: &str) -> Result<String> {
        log::info!(
            "Signing message for '{}' (length: {} bytes)",
            self.username,
            message.len()
        );
        let secret_key = self.load_private_key()?;

        // Create signature using SignatureConfig (pgp 0.16 API)
        let mut config = SignatureConfig::from_key(
            thread_rng(),
            &secret_key.primary_key,
            SignatureType::Binary,
        )?;

        // Add required subpackets
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret_key.primary_key.fingerprint(),
            ))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(
                SystemTime::now().into(),
            ))?,
        ];

        config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::Issuer(secret_key.primary_key.key_id()))?
        ];

        let signature = config.sign(
            &secret_key.primary_key,
            &self.to_pgp_password(),
            message.as_bytes(),
        )?;

        // Wrap in StandaloneSignature and return armored string
        let standalone = StandaloneSignature::new(signature);
        let armored = standalone.to_armored_string(Default::default())?;

        log::info!("Successfully signed message for '{}'", self.username);
        Ok(armored)
    }

    /// Verify a PGP signature against a public key.
    pub fn verify_pgp_signature(
        &self,
        public_key_armored: &str,
        message: &str,
        signature_str: &str,
    ) -> bool {
        match self.verify_signature_inner(public_key_armored, message, signature_str) {
            Ok(valid) => valid,
            Err(e) => {
                log::error!("verify_pgp_signature failed: {}", e);
                false
            }
        }
    }

    fn verify_signature_inner(
        &self,
        public_key_armored: &str,
        message: &str,
        signature_str: &str,
    ) -> Result<bool> {
        let signature = if signature_str.starts_with("-----BEGIN PGP SIGNATURE-----") {
            let (sig, _headers) = StandaloneSignature::from_string(signature_str)?;
            sig
        } else {
            let signature_bytes = general_purpose::STANDARD.decode(signature_str)?;
            StandaloneSignature::from_bytes(signature_bytes.as_slice())?
        };

        let (public_key, _headers) = SignedPublicKey::from_string(public_key_armored)?;

        match signature.verify(&public_key.primary_key, message.as_bytes()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use tempfile::tempdir;

    #[test]
    fn test_generate_sign_verify() -> Result<()> {
        let tmp = tempdir()?;
        let cu = CryptoUtils::new(tmp.path().into(), "tester".into(), "testpass".into())?;
        let public = cu.generate_key_pair("tester")?;
        let msg = "hello";
        let sig = cu.sign_message("tester", msg)?;
        assert!(cu.verify_pgp_signature(&public, msg, &sig));
        assert!(!cu.verify_pgp_signature(&public, "bad", &sig));
        Ok(())
    }
}
