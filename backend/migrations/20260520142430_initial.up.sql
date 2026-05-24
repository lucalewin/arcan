-- Add up migration script here
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_file BYTEA NOT NULL,
    master_key_salt TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vaults (
    id UUID PRIMARY KEY,
    -- When we implement sharing, we will drop this column
    -- and replace it with a vault_users joining table.
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_name BYTEA NOT NULL,
    encrypted_vsk BYTEA NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    next_revision BIGINT NOT NULL DEFAULT 1,   -- The timeline for this specific vault
    server_revision BIGINT NOT NULL DEFAULT 0, -- When the vault's OWN metadata was last updated
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE items (
    id UUID PRIMARY KEY,
    vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    encrypted_payload BYTEA NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    server_revision BIGINT NOT NULL DEFAULT 0, -- Tied to the vault's next_revision
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Index for fast per-vault sync pulls
CREATE INDEX idx_items_sync ON items(vault_id, server_revision);
