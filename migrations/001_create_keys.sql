CREATE TABLE IF NOT EXISTS keys (
    id          SERIAL PRIMARY KEY,
    hwid        TEXT NOT NULL UNIQUE,
    key_value   TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    ip_address  TEXT
);

CREATE INDEX IF NOT EXISTS idx_keys_hwid ON keys (hwid);
CREATE INDEX IF NOT EXISTS idx_keys_key_value ON keys (key_value);
CREATE INDEX IF NOT EXISTS idx_keys_expires_at ON keys (expires_at);

CREATE TABLE IF NOT EXISTS used_tokens (
    token_hash  TEXT NOT NULL PRIMARY KEY,
    used_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
