-- Add up migration script here
CREATE TABLE IF NOT EXISTS client_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    email TEXT NOT NULL,
    local_verifier BLOB NOT NULL,
    master_salt TEXT NOT NULL,
    last_sync_at INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY, -- Storing UUID as TEXT
    encrypted_name BLOB NOT NULL,
    encrypted_vsk BLOB NOT NULL,
    server_revision INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    encrypted_payload BLOB NOT NULL,
    server_revision INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
) STRICT;
