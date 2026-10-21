-- 用户自愿迁移的待认领、授权、实时余额与审计数据。
-- 注意：本迁移不创建正式用户、不写入 users.balance，也不复制源站 API Key。

CREATE TABLE IF NOT EXISTS user_migrations (
    id BIGSERIAL PRIMARY KEY,
    migration_id TEXT NOT NULL UNIQUE,
    source_system TEXT NOT NULL,
    source_user_id TEXT NOT NULL,
    target_user_id BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    source_email TEXT NOT NULL DEFAULT '',
    source_username TEXT NOT NULL DEFAULT '',
    source_group TEXT NOT NULL DEFAULT '',
    source_password_hash TEXT NOT NULL DEFAULT '',
    password_compatible BOOLEAN NOT NULL DEFAULT FALSE,
    static_snapshot_id BIGINT,
    authorization_token_hash TEXT NOT NULL DEFAULT '',
    authorization_redirect_url TEXT NOT NULL DEFAULT '',
    authorization_state TEXT NOT NULL DEFAULT '',
    authorization_expires_at TIMESTAMPTZ,
    source_locked_at TIMESTAMPTZ,
    source_lock_expires_at TIMESTAMPTZ,
    live_balance_read_at TIMESTAMPTZ,
    source_quota NUMERIC(30, 0),
    source_used_quota NUMERIC(30, 0),
    source_available_quota NUMERIC(30, 0),
    conversion_factor NUMERIC(30, 12),
    converted_balance NUMERIC(20, 8),
    credited_balance NUMERIC(20, 8),
    generated_api_key_id BIGINT,
    failure_code TEXT NOT NULL DEFAULT '',
    failure_message TEXT NOT NULL DEFAULT '',
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_migrations_status_check CHECK (
        status IN ('pending', 'authorizing', 'authorized', 'locked', 'processing', 'completed', 'failed', 'manual_review')
    ),
    CONSTRAINT user_migrations_source_check CHECK (length(trim(source_system)) > 0),
    CONSTRAINT user_migrations_target_user_check CHECK (target_user_id > 0),
    CONSTRAINT user_migrations_source_user_check CHECK (length(trim(source_user_id)) > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS user_migrations_source_identity_idx
    ON user_migrations (source_system, source_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS user_migrations_active_target_idx
    ON user_migrations (target_user_id)
    WHERE status IN ('pending', 'authorizing', 'authorized', 'locked', 'processing');
CREATE UNIQUE INDEX IF NOT EXISTS user_migrations_authorization_state_idx
    ON user_migrations (authorization_state)
    WHERE authorization_state <> '';
CREATE INDEX IF NOT EXISTS user_migrations_target_user_idx
    ON user_migrations (target_user_id);
CREATE INDEX IF NOT EXISTS user_migrations_status_idx
    ON user_migrations (status);

CREATE TABLE IF NOT EXISTS user_migration_snapshots (
    id BIGSERIAL PRIMARY KEY,
    migration_id BIGINT NOT NULL REFERENCES user_migrations(id) ON DELETE CASCADE,
    source_system TEXT NOT NULL,
    source_user_id TEXT NOT NULL,
    snapshot_version INTEGER NOT NULL DEFAULT 1,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_group TEXT NOT NULL DEFAULT '',
    source_email TEXT NOT NULL DEFAULT '',
    source_username TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    password_compatible BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS user_migration_snapshots_migration_idx
    ON user_migration_snapshots (migration_id, captured_at DESC);

ALTER TABLE user_migrations
    ADD CONSTRAINT user_migrations_snapshot_fk
    FOREIGN KEY (static_snapshot_id) REFERENCES user_migration_snapshots(id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE IF NOT EXISTS user_migration_key_map (
    id BIGSERIAL PRIMARY KEY,
    migration_id BIGINT NOT NULL UNIQUE REFERENCES user_migrations(id) ON DELETE CASCADE,
    source_key_fingerprint TEXT NOT NULL DEFAULT '',
    target_api_key_id BIGINT,
    target_key_fingerprint TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_migration_events (
    id BIGSERIAL PRIMARY KEY,
    migration_id BIGINT NOT NULL REFERENCES user_migrations(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    request_id TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS user_migration_events_migration_idx
    ON user_migration_events (migration_id, created_at);

CREATE TABLE IF NOT EXISTS user_migration_balance_ledger (
    id BIGSERIAL PRIMARY KEY,
    migration_id BIGINT NOT NULL UNIQUE REFERENCES user_migrations(id) ON DELETE CASCADE,
    target_user_id BIGINT NOT NULL,
    source_quota NUMERIC(30, 0) NOT NULL,
    source_used_quota NUMERIC(30, 0) NOT NULL,
    source_available_quota NUMERIC(30, 0) NOT NULL,
    conversion_factor NUMERIC(30, 12) NOT NULL,
    converted_balance NUMERIC(20, 8) NOT NULL,
    credited_balance NUMERIC(20, 8) NOT NULL,
    source_read_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS user_migration_balance_ledger_target_idx
    ON user_migration_balance_ledger (target_user_id);

COMMENT ON TABLE user_migrations IS '用户自愿迁移主记录，按源系统和源用户幂等。';
COMMENT ON TABLE user_migration_snapshots IS '源站静态数据快照，仅用于待认领展示，不代表正式用户数据。';
COMMENT ON TABLE user_migration_key_map IS '源站 Key 与美国站新 Key 的审计映射，只保存指纹，不保存明文。';
COMMENT ON TABLE user_migration_events IS '迁移状态和外部交互审计事件。';
COMMENT ON TABLE user_migration_balance_ledger IS '迁移实时余额计算与入账账本。';
