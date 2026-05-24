-- Add down migration script here
DROP INDEX IF EXISTS idx_items_sync;
DROP TABLE IF EXISTS items;
DROP TABLE IF EXISTS vaults;
DROP TABLE IF EXISTS users;
