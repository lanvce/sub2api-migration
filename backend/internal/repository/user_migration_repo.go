package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type userMigrationRepository struct{ db *sql.DB }

func NewUserMigrationRepository(db *sql.DB) service.UserMigrationRepository {
	return &userMigrationRepository{db: db}
}

const migrationSelect = `SELECT id, migration_id, source_system, source_user_id, target_user_id, status,
 source_email, source_username, source_group, password_compatible, authorization_redirect_url,
 authorization_expires_at, source_locked_at, source_lock_expires_at, live_balance_read_at,
 source_quota, source_used_quota, source_available_quota, conversion_factor, converted_balance,
 credited_balance, generated_api_key_id, failure_code, failure_message, completed_at, created_at, updated_at
 FROM user_migrations`

func scanMigration(row interface{ Scan(...any) error }) (*service.UserMigration, error) {
	m := new(service.UserMigration)
	var (
		sourceEmail, sourceUsername, sourceGroup sql.NullString
		redirectURL, failureCode, failureMessage sql.NullString
	)
	err := row.Scan(&m.ID, &m.MigrationID, &m.SourceSystem, &m.SourceUserID, &m.TargetUserID, &m.Status,
		&sourceEmail, &sourceUsername, &sourceGroup, &m.PasswordCompatible, &redirectURL,
		&m.AuthorizationExpiresAt, &m.SourceLockedAt, &m.SourceLockExpiresAt, &m.LiveBalanceReadAt,
		&m.SourceQuota, &m.SourceUsedQuota, &m.SourceAvailableQuota, &m.ConversionFactor, &m.ConvertedBalance,
		&m.CreditedBalance, &m.GeneratedAPIKeyID, &failureCode, &failureMessage, &m.CompletedAt, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return m, err
	}
	m.SourceEmail = sourceEmail.String
	m.SourceUsername = sourceUsername.String
	m.SourceGroup = sourceGroup.String
	m.AuthorizationRedirectURL = redirectURL.String
	m.FailureCode = failureCode.String
	m.FailureMessage = failureMessage.String
	return m, err
}

func (r *userMigrationRepository) GetByMigrationID(ctx context.Context, id string) (*service.UserMigration, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("nil migration repository")
	}
	row := r.db.QueryRowContext(ctx, migrationSelect+` WHERE migration_id = $1`, id)
	m, err := scanMigration(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrMigrationNotFound
	}
	return m, err
}

// GetByMigrationIDForUser scopes the lookup to the owning target user, so a
// user can never read (or act on) someone else's migration record.
func (r *userMigrationRepository) GetByMigrationIDForUser(ctx context.Context, id string, targetUserID int64) (*service.UserMigration, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("nil migration repository")
	}
	row := r.db.QueryRowContext(ctx, migrationSelect+` WHERE migration_id = $1 AND target_user_id = $2`, id, targetUserID)
	m, err := scanMigration(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrMigrationNotFound
	}
	return m, err
}

// GetActiveByTargetUserID returns the target user's current migration. It uses
// the same status set as user_migrations_active_target_idx, allowing Start to
// resume the row that would otherwise make a new insert fail with a conflict.
func (r *userMigrationRepository) GetActiveByTargetUserID(ctx context.Context, targetUserID int64) (*service.UserMigration, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("nil migration repository")
	}
	row := r.db.QueryRowContext(ctx, migrationSelect+` WHERE target_user_id = $1 AND status IN ('pending', 'authorizing', 'authorized', 'locked', 'processing') ORDER BY updated_at DESC LIMIT 1`, targetUserID)
	m, err := scanMigration(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrMigrationNotFound
	}
	return m, err
}

// GetLatestByTargetUserID returns the target user's most recently updated
// migration of any status. Used by Current when no active row exists.
func (r *userMigrationRepository) GetLatestByTargetUserID(ctx context.Context, targetUserID int64) (*service.UserMigration, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("nil migration repository")
	}
	row := r.db.QueryRowContext(ctx, migrationSelect+` WHERE target_user_id = $1 ORDER BY updated_at DESC LIMIT 1`, targetUserID)
	m, err := scanMigration(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrMigrationNotFound
	}
	return m, err
}

func (r *userMigrationRepository) RecoverStaleProcessing(ctx context.Context, id string, staleBefore time.Time) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("nil migration repository")
	}
	res, err := r.db.ExecContext(ctx, `UPDATE user_migrations
 SET status = $2, failure_code = 'processing_timeout',
     failure_message = 'migration processing expired; restart authorization', updated_at = NOW()
 WHERE migration_id = $1 AND status = 'processing' AND updated_at < $3`,
		id, service.MigrationStatusFailed, staleBefore)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	return affected > 0, err
}

func (r *userMigrationRepository) Create(ctx context.Context, input *service.UserMigration) (*service.UserMigration, error) {
	if r == nil || r.db == nil || input == nil {
		return nil, errors.New("invalid migration repository input")
	}
	const q = `INSERT INTO user_migrations (migration_id, source_system, source_user_id, target_user_id, status)
 VALUES ($1, $2, $3, $4, $5)
 RETURNING id, migration_id, source_system, source_user_id, target_user_id, status, source_email, source_username, source_group,
 password_compatible, authorization_redirect_url, authorization_expires_at, source_locked_at, source_lock_expires_at,
 live_balance_read_at, source_quota, source_used_quota, source_available_quota, conversion_factor, converted_balance,
 credited_balance, generated_api_key_id, failure_code, failure_message, completed_at, created_at, updated_at`
	m, err := scanMigration(r.db.QueryRowContext(ctx, q, input.MigrationID, input.SourceSystem, input.SourceUserID, input.TargetUserID, input.Status))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, service.ErrMigrationConflict
		}
		return nil, fmt.Errorf("create user migration: %w", err)
	}
	return m, nil
}

func (r *userMigrationRepository) UpdateAuthorization(ctx context.Context, id string, session service.HKAuthorizationSession) error {
	_, err := r.db.ExecContext(ctx, `UPDATE user_migrations SET status = $2, authorization_redirect_url = $3, authorization_state = $4, authorization_expires_at = $5, failure_code = '', failure_message = '', updated_at = NOW() WHERE migration_id = $1`, id, service.MigrationStatusAuthorizing, session.AuthorizationURL, session.State, session.ExpiresAt)
	return err
}

// BindSourceIdentity stores the real source identity resolved from the HK
// grant. The unique index on (source_system, source_user_id) turns a second
// bind of the same source account into ErrMigrationConflict.
func (r *userMigrationRepository) BindSourceIdentity(ctx context.Context, id, sourceUserID, sourceUsername, sourceEmail string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE user_migrations SET source_user_id = $2, source_username = $3, source_email = $4, updated_at = NOW() WHERE migration_id = $1`, id, sourceUserID, sourceUsername, sourceEmail)
	if err != nil && isUniqueViolation(err) {
		return service.ErrMigrationConflict
	}
	return err
}

// ClaimForConfirm is the single-winner gate for Confirm: it only succeeds when
// the row is still in a claimable state, so two concurrent confirms can never
// both proceed to the credit step.
func (r *userMigrationRepository) ClaimForConfirm(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE user_migrations
 SET status = $2, failure_code = '', failure_message = '', updated_at = NOW()
 WHERE migration_id = $1 AND status IN ('pending', 'authorizing', 'authorized', 'failed')`,
		id, service.MigrationStatusProcessing)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return service.ErrMigrationConflict
	}
	return nil
}

func (r *userMigrationRepository) SetLocked(ctx context.Context, id string, lockedAt, lockExpiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE user_migrations SET source_locked_at = $2, source_lock_expires_at = $3, updated_at = NOW() WHERE migration_id = $1`, id, lockedAt, lockExpiresAt)
	return err
}

func (r *userMigrationRepository) SetStatus(ctx context.Context, id, status, code, message string) error {
	return r.setStatus(ctx, id, status, code, message)
}
func (r *userMigrationRepository) setStatus(ctx context.Context, id, status, code, message string) error {
	completed := any(nil)
	if status == service.MigrationStatusCompleted {
		completed = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx, `UPDATE user_migrations SET status = $2, failure_code = $3, failure_message = $4, completed_at = COALESCE($5, completed_at), updated_at = NOW() WHERE migration_id = $1`, id, status, code, message, completed)
	return err
}

// SetBalance records the live balance read. It intentionally does NOT touch
// credited_balance: that column is only written by CreditAndComplete, in the
// same transaction that actually credits users.balance.
func (r *userMigrationRepository) SetBalance(ctx context.Context, id string, b service.HKBalanceSnapshot, factor, converted float64) error {
	// users.quota is already the REMAINING quota in new-api; used_quota is the
	// lifetime spend and must never be subtracted again.
	available := b.Quota
	if b.AvailableQuota > 0 {
		available = b.AvailableQuota
	}
	if available < 0 {
		available = 0
	}
	_, err := r.db.ExecContext(ctx, `UPDATE user_migrations SET live_balance_read_at = $2, source_quota = $3, source_used_quota = $4, source_available_quota = $5, conversion_factor = $6, converted_balance = $7, updated_at = NOW() WHERE migration_id = $1`, id, b.ReadAt, b.Quota, b.UsedQuota, available, factor, converted)
	return err
}

// CreditAndComplete performs the money movement of a migration atomically:
//  1. insert the balance ledger row — its UNIQUE(migration_id) constraint is
//     the idempotency guard against double-crediting;
//  2. credit users.balance;
//  3. record the key map entry (fingerprints only, never plaintext);
//  4. transition the migration to 'completed'.
//
// All four statements share one transaction: either the user is credited and
// the migration is completed, or nothing happened at all.
func (r *userMigrationRepository) CreditAndComplete(ctx context.Context, credit service.MigrationCredit) error {
	if r == nil || r.db == nil {
		return errors.New("nil migration repository")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration credit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the row and re-check the state inside the transaction.
	var (
		rowID  int64
		status string
	)
	err = tx.QueryRowContext(ctx, `SELECT id, status FROM user_migrations WHERE migration_id = $1 FOR UPDATE`, credit.MigrationID).Scan(&rowID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return service.ErrMigrationNotFound
	}
	if err != nil {
		return err
	}
	if status != service.MigrationStatusProcessing {
		return service.ErrMigrationConflict
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO user_migration_balance_ledger
 (migration_id, target_user_id, source_quota, source_used_quota, source_available_quota,
  conversion_factor, converted_balance, credited_balance, source_read_at)
 SELECT id, target_user_id, COALESCE(source_quota, 0), COALESCE(source_used_quota, 0), COALESCE(source_available_quota, 0),
  COALESCE(conversion_factor, 0), COALESCE(converted_balance, 0), $2, COALESCE(live_balance_read_at, NOW())
 FROM user_migrations WHERE id = $1`, rowID, credit.CreditedBalance)
	if err != nil {
		if isUniqueViolation(err) {
			return service.ErrMigrationConflict
		}
		return fmt.Errorf("insert migration balance ledger: %w", err)
	}

	if credit.CreditedBalance > 0 {
		res, execErr := tx.ExecContext(ctx, `UPDATE users SET balance = balance + $2, updated_at = NOW() WHERE id = $1`, credit.TargetUserID, credit.CreditedBalance)
		if execErr != nil {
			return fmt.Errorf("credit user balance: %w", execErr)
		}
		affected, execErr := res.RowsAffected()
		if execErr != nil {
			return execErr
		}
		if affected == 0 {
			return fmt.Errorf("credit user balance: user %d not found", credit.TargetUserID)
		}
	}

	apiKeyID := sql.NullInt64{Int64: credit.APIKeyID, Valid: credit.APIKeyID > 0}
	_, err = tx.ExecContext(ctx, `INSERT INTO user_migration_key_map (migration_id, target_api_key_id, target_key_fingerprint)
 VALUES ($1, $2, $3)
 ON CONFLICT (migration_id) DO UPDATE SET target_api_key_id = EXCLUDED.target_api_key_id, target_key_fingerprint = EXCLUDED.target_key_fingerprint`,
		rowID, apiKeyID, credit.APIKeyFingerprint)
	if err != nil {
		return fmt.Errorf("insert migration key map: %w", err)
	}

	_, err = tx.ExecContext(ctx, `UPDATE user_migrations
 SET status = $2, credited_balance = $3, generated_api_key_id = $4, failure_code = '', failure_message = '',
     completed_at = NOW(), updated_at = NOW()
 WHERE id = $1`, rowID, service.MigrationStatusCompleted, credit.CreditedBalance, apiKeyID)
	if err != nil {
		return fmt.Errorf("complete migration: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migration credit transaction: %w", err)
	}
	return nil
}

func (r *userMigrationRepository) AddEvent(ctx context.Context, id, eventType, actor string, details map[string]any) error {
	data, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO user_migration_events (migration_id, event_type, actor, details) SELECT id, $2, $3, $4::jsonb FROM user_migrations WHERE migration_id = $1`, id, eventType, actor, string(data))
	return err
}
