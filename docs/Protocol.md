# Nymstr Group Server Protocol

This document specifies the JSON-based message protocol over the Nym mixnet between
clients and the group server (`nymstr-group`). The server operates as a **store-and-fetch**
service with **MLS (Message Layer Security)** integration for end-to-end encrypted group messaging.

---

## Table of Contents

1. [Message Format](#message-format)
2. [Authentication](#authentication)
3. [Core Actions](#core-actions)
   - [register](#1-register---join-request)
   - [approveGroup](#2-approvegroup---admin-approval)
   - [sendGroup](#3-sendgroup---send-encrypted-message)
   - [fetchGroup](#4-fetchgroup---fetch-messages)
4. [MLS Delivery Service Actions](#mls-delivery-service-actions)
   - [storeWelcome](#5-storewelcome---store-mls-welcome)
   - [fetchWelcome](#6-fetchwelcome---fetch-mls-welcomes)
   - [syncEpoch](#7-syncepoch---synchronize-mls-epoch)
   - [bufferCommit](#8-buffercommit---buffer-mls-commit)
5. [Security](#security)
6. [Error Handling](#error-handling)

---

## Message Format

### Unified Format (Recommended)

All messages use a unified JSON envelope:

```json
{
  "type": "message",
  "action": "<action_name>",
  "sender": "<username>",
  "recipient": "group-server",
  "payload": { /* action-specific data */ },
  "signature": "<PGP_detached_signature>",
  "timestamp": "2026-01-21T12:00:00Z"
}
```

### Response Format

Server responses follow the same envelope structure:

```json
{
  "type": "response",
  "action": "<action_name>Response",
  "sender": "group-server",
  "recipient": "client",
  "payload": {
    "content": "<response_data_or_error>"
  },
  "signature": "<server_PGP_signature>",
  "timestamp": "2026-01-21T12:00:01Z"
}
```

### Legacy Format (Deprecated)

For backward compatibility, the server also accepts flat JSON:

```json
{
  "action": "<action_name>",
  "username": "<username>",
  "signature": "<signature>",
  /* ...other fields at root level */
}
```

---

## Authentication

All requests require PGP signature verification:

1. **Signature Content**: What gets signed varies by action (documented below)
2. **Signature Format**: Detached PGP signature (ASCII-armored)
3. **Key Lookup**: Server verifies against the user's registered public key

### Rate Limiting

- **Limit**: 10 requests per sender within 60 seconds
- **Scope**: Registration endpoint
- **Response**: `"error: rate limit exceeded, please try again later"`

### Input Validation

- **Usernames**: 1-64 characters, alphanumeric plus `-` and `_` only
- **Group IDs**: 1-128 characters, alphanumeric plus `-` and `_` only

---

## Core Actions

### 1. register - Join Request

Register a username with PGP public key and request group membership.

**Request** (`action = "register"`):

```json
{
  "type": "message",
  "action": "register",
  "sender": "<username>",
  "payload": {
    "username": "<username>",
    "publicKey": "<ASCII-armored PGP public key>",
    "serverAddress": "<group_server_nym_address>",
    "timestamp": 1705842000,
    "keyPackage": "<base64-encoded MLS KeyPackage>"  // Optional
  },
  "signature": "<signature over 'register:{username}:{serverAddress}:{timestamp}'>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `username` | Yes | Desired username (1-64 chars, alphanumeric/-/_) |
| `publicKey` | Yes | ASCII-armored PGP public key |
| `serverAddress` | Yes | Group server's Nym address |
| `timestamp` | Yes | Unix timestamp (must be within ±5 minutes of server time) |
| `keyPackage` | No | Base64-encoded MLS KeyPackage for group encryption |

**Response** (`action = "registerResponse"`):

| Status | Description |
|--------|-------------|
| `"pending"` | Join request recorded, awaiting admin approval |
| `"approved"` | Admin auto-approved (matching admin key) |
| `"error: user already registered"` | Username already exists |
| `"error: invalid username format"` | Username validation failed |
| `"error: timestamp expired"` | Timestamp outside ±5 minute window |
| `"error: bad signature"` | Signature verification failed |
| `"error: rate limit exceeded..."` | Too many registration attempts |

---

### 2. approveGroup - Admin Approval

Admin approves a pending user's join request.

**Request** (`action = "approveGroup"`):

```json
{
  "type": "message",
  "action": "approveGroup",
  "sender": "<admin_username>",
  "payload": {
    "username": "<username_to_approve>"
  },
  "signature": "<admin signature over username_to_approve>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `username` | Yes | Username of the pending user to approve |

**Signature**: Admin must sign the target username with their admin private key.

**Response** (`action = "approveGroupResponse"`):

Success response includes the user's KeyPackage if one was provided during registration:

```json
{
  "payload": {
    "content": {
      "status": "success",
      "username": "<approved_username>",
      "keyPackage": "<base64-encoded KeyPackage>"  // If available
    }
  }
}
```

| Status | Description |
|--------|-------------|
| `{"status": "success", ...}` | User approved and moved to active members |
| `"error: no admin configured"` | Server has no admin key configured |
| `"error: unauthorized or bad signature"` | Invalid admin signature |
| `"error: user not in pending list"` | User has no pending registration |
| `"error: approve failed"` | Database error during approval |

---

### 3. sendGroup - Send Encrypted Message

Send an MLS-encrypted message to the group. Messages are stored with sequential IDs.

**Request** (`action = "sendGroup"`):

```json
{
  "type": "message",
  "action": "sendGroup",
  "sender": "<username>",
  "payload": {
    "ciphertext": "<MLS-encrypted message>"
  },
  "signature": "<signature over ciphertext>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `ciphertext` | Yes | MLS-encrypted message (base64 or hex encoded) |

**Signature**: User must sign the ciphertext.

**Response** (`action = "sendGroupResponse"`):

```json
{
  "payload": {
    "content": {
      "status": "success",
      "messageId": 42
    }
  }
}
```

| Status | Description |
|--------|-------------|
| `{"status": "success", "messageId": <id>}` | Message stored successfully |
| `"error: missing ciphertext"` | No ciphertext provided |
| `"error: user not registered"` | Sender not a group member |
| `"error: bad signature"` | Signature verification failed |
| `"error: failed to store message"` | Database error |

---

### 4. fetchGroup - Fetch Messages

Fetch new messages since a given cursor (message ID).

**Request** (`action = "fetchGroup"`):

```json
{
  "type": "message",
  "action": "fetchGroup",
  "sender": "<username>",
  "payload": {
    "lastSeenId": 40
  },
  "signature": "<signature over lastSeenId as string>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `lastSeenId` | No | Last message ID seen (default: 0) |

**Signature**: User must sign the `lastSeenId` value as a string (e.g., `"40"`).

**Response** (`action = "fetchGroupResponse"`):

```json
{
  "payload": {
    "content": {
      "messages": [
        {
          "id": 41,
          "sender": "alice",
          "ciphertext": "<encrypted_content>",
          "timestamp": "2026-01-21T12:00:00Z"
        },
        {
          "id": 42,
          "sender": "bob",
          "ciphertext": "<encrypted_content>",
          "timestamp": "2026-01-21T12:00:05Z"
        }
      ]
    }
  }
}
```

| Status | Description |
|--------|-------------|
| `{"messages": [...]}` | Array of messages since lastSeenId |
| `"error: user not registered"` | Requester not a group member |
| `"error: bad signature"` | Signature verification failed |
| `"error: failed to fetch messages"` | Database error |

---

## MLS Delivery Service Actions

These actions support MLS protocol operations for group key management.

### 5. storeWelcome - Store MLS Welcome

Store an MLS Welcome message for a user who is being added to the group. The Welcome
contains the group's current state and allows the new member to join.

**Request** (`action = "storeWelcome"`):

```json
{
  "type": "message",
  "action": "storeWelcome",
  "sender": "<admin_username>",
  "payload": {
    "groupId": "<mls_group_id>",
    "targetUsername": "<new_member_username>",
    "welcome": "<base64-encoded MLS Welcome>"
  },
  "signature": "<signature over '{groupId}:{targetUsername}'>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `groupId` | Yes | MLS group identifier (1-128 chars) |
| `targetUsername` | Yes | Username of the new member (1-64 chars) |
| `welcome` | Yes | Base64-encoded MLS Welcome message |

**Signature**: Sender must sign `"{groupId}:{targetUsername}"`.

**Response** (`action = "storeWelcomeResponse"`):

| Status | Description |
|--------|-------------|
| `{"status": "success"}` | Welcome stored successfully |
| `"error: missing or invalid groupId"` | Invalid group ID |
| `"error: missing or invalid targetUsername"` | Invalid target username |
| `"error: missing welcome"` | No welcome data provided |
| `"error: invalid base64 welcome"` | Welcome is not valid base64 |
| `"error: failed to store welcome"` | Database error |

---

### 6. fetchWelcome - Fetch MLS Welcomes

Fetch pending MLS Welcome messages for the requesting user.

**Request** (`action = "fetchWelcome"`):

```json
{
  "type": "message",
  "action": "fetchWelcome",
  "sender": "<username>",
  "payload": {
    "groupId": "<mls_group_id>"  // Optional: filter by group
  },
  "signature": "<signature over 'fetchWelcome:{username}'>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `groupId` | No | Filter to specific group (omit for all pending welcomes) |

**Signature**: User must sign `"fetchWelcome:{username}"`.

**Response** (`action = "fetchWelcomeResponse"`):

```json
{
  "payload": {
    "content": {
      "welcomes": [
        {
          "groupId": "<mls_group_id>",
          "welcome": "<base64-encoded MLS Welcome>"
        }
      ]
    }
  }
}
```

**Note**: Welcomes are automatically deleted after being fetched (one-time retrieval).

| Status | Description |
|--------|-------------|
| `{"welcomes": [...]}` | Array of pending welcomes (may be empty) |
| `"error: user not registered"` | Requester not registered |
| `"error: bad signature"` | Signature verification failed |
| `"error: failed to fetch welcome"` | Database error |

---

### 7. syncEpoch - Synchronize MLS Epoch

Request MLS commit messages since a given epoch. This allows clients who missed
commits (due to mixnet latency/reordering) to catch up to the current group state.

**Request** (`action = "syncEpoch"`):

```json
{
  "type": "message",
  "action": "syncEpoch",
  "sender": "<username>",
  "payload": {
    "groupId": "<mls_group_id>",
    "sinceEpoch": 5
  },
  "signature": "<signature over '{groupId}:{sinceEpoch}'>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `groupId` | Yes | MLS group identifier |
| `sinceEpoch` | No | Epoch to sync from (default: 0) |

**Signature**: User must sign `"{groupId}:{sinceEpoch}"`.

**Response** (`action = "syncEpochResponse"`):

```json
{
  "payload": {
    "content": {
      "currentEpoch": 10,
      "commits": [
        {
          "epoch": 6,
          "commit": "<base64-encoded MLS Commit>",
          "sender": "alice"
        },
        {
          "epoch": 7,
          "commit": "<base64-encoded MLS Commit>",
          "sender": "bob"
        }
      ]
    }
  }
}
```

| Status | Description |
|--------|-------------|
| `{"currentEpoch": N, "commits": [...]}` | Current epoch and commits since requested epoch |
| `"error: missing or invalid groupId"` | Invalid group ID |
| `"error: user not registered"` | Requester not registered |
| `"error: bad signature"` | Signature verification failed |
| `"error: failed to sync epoch"` | Database error |

---

### 8. bufferCommit - Buffer MLS Commit

Store an MLS commit message for epoch synchronization. Called by group members when
they send commits, allowing late joiners or offline members to catch up.

**Request** (`action = "bufferCommit"`):

```json
{
  "type": "message",
  "action": "bufferCommit",
  "sender": "<username>",
  "payload": {
    "groupId": "<mls_group_id>",
    "epoch": 6,
    "commit": "<base64-encoded MLS Commit>"
  },
  "signature": "<signature over '{groupId}:{epoch}'>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `groupId` | Yes | MLS group identifier |
| `epoch` | Yes | Epoch number for this commit |
| `commit` | Yes | Base64-encoded MLS Commit message |

**Signature**: User must sign `"{groupId}:{epoch}"`.

**Response** (`action = "bufferCommitResponse"`):

```json
{
  "payload": {
    "content": {
      "status": "success",
      "epoch": 6
    }
  }
}
```

**Note**: The server automatically cleans up old commits, keeping only the last 100 epochs.

| Status | Description |
|--------|-------------|
| `{"status": "success", "epoch": N}` | Commit buffered successfully |
| `"error: missing or invalid groupId"` | Invalid group ID |
| `"error: missing epoch"` | No epoch provided |
| `"error: missing commit"` | No commit data provided |
| `"error: invalid base64 commit"` | Commit is not valid base64 |
| `"error: user not registered"` | Sender not registered |
| `"error: bad signature"` | Signature verification failed |
| `"error: failed to buffer commit"` | Database error |

---

## Security

### Signature Requirements

| Action | Signed Content |
|--------|---------------|
| `register` | `"register:{username}:{serverAddress}:{timestamp}"` |
| `approveGroup` | `"{username_to_approve}"` |
| `sendGroup` | `"{ciphertext}"` |
| `fetchGroup` | `"{lastSeenId}"` |
| `storeWelcome` | `"{groupId}:{targetUsername}"` |
| `fetchWelcome` | `"fetchWelcome:{username}"` |
| `syncEpoch` | `"{groupId}:{sinceEpoch}"` |
| `bufferCommit` | `"{groupId}:{epoch}"` |

### Transport Security

- All messages are routed through the **Nym mixnet** for network-level anonymity
- Replies use **SURBs** (Single-Use Reply Blocks) for anonymous responses
- Server signs all responses for authenticity verification

### MLS Security Properties

- **Forward Secrecy**: Compromise of current keys doesn't reveal past messages
- **Post-Compromise Security**: Recovery after key compromise through epoch advancement
- **Epoch Buffering**: Server buffers commits to handle mixnet message reordering

---

## Error Handling

All errors are returned in the response payload:

```json
{
  "payload": {
    "content": "error: <error_message>"
  }
}
```

### Common Errors

| Error | Cause |
|-------|-------|
| `"error: missing required fields"` | Required payload fields not provided |
| `"error: user not registered"` | Username not in approved members |
| `"error: bad signature"` | PGP signature verification failed |
| `"error: rate limit exceeded..."` | Too many requests in time window |
| `"error: invalid username format"` | Username contains invalid characters or too long |
| `"error: timestamp expired"` | Registration timestamp outside ±5 minute window |

---

## Database Schema Reference

The group server uses SQLite with the following tables:

| Table | Purpose |
|-------|---------|
| `users` | Approved group members (username, publicKey) |
| `pending_users` | Pending registration requests |
| `messages` | Stored encrypted messages (id, sender, ciphertext, timestamp) |
| `key_packages` | MLS KeyPackages per user |
| `pending_welcomes` | Pending MLS Welcome messages |
| `group_epochs` | Current epoch per group |
| `buffered_commits` | MLS commits for epoch sync |
| `member_epochs` | Per-member epoch tracking |

---

*Last updated: 2026-01-21*
