# nymstr-group

Group chat server with MLS encryption for the Nymstr messaging system, built on the [Nym mixnet](https://nymtech.net/).

## What it does

- Group membership with admin approval workflow
- MLS (RFC 9420) for forward-secret group encryption
- Pull-based message delivery
- Key package and Welcome message storage

## Quick Start

```bash
cp .env.example .env
mkdir -p secrets && echo "your_password" > secrets/encryption_password
cargo run --release
```

First run prompts for group configuration interactively.

### Setup Commands

```bash
# Set admin public key
cargo run --release -- --set-admin /path/to/admin.asc

# Register with discovery server
cargo run --release -- --register
```

## Configuration

See `.env.example` for all options. Key variables:

- `CONFIG_PATH` - TOML config file (default: `config/group.toml`)
- `DATABASE_PATH` - SQLite database (default: `storage/groupd.db`)
- `KEYS_DIR` - PGP keys directory (default: `storage/keys`)

## License

GNU GPLv3.0
