package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MigrationStatusPending      = "pending"
	MigrationStatusAuthorizing  = "authorizing"
	MigrationStatusAuthorized   = "authorized"
	MigrationStatusLocked       = "locked"
	MigrationStatusProcessing   = "processing"
	MigrationStatusCompleted    = "completed"
	MigrationStatusFailed       = "failed"
	MigrationStatusManualReview = "manual_review"
)

var (
	ErrMigrationNotFound = errors.New("migration not found")
	ErrMigrationConflict = errors.New("migration already exists for source or target user")
	ErrMigrationInvalid  = errors.New("invalid migration request")
	ErrMigrationDisabled = errors.New("migration confirmation is disabled")
)

// UserMigration is the public-safe projection of user_migrations. Secrets and
// password hashes are intentionally not exposed by this structure.
type UserMigration struct {
	ID                       int64      `json:"id"`
	MigrationID              string     `json:"migration_id"`
	SourceSystem             string     `json:"source_system"`
	SourceUserID             string     `json:"source_user_id"`
	TargetUserID             int64      `json:"target_user_id"`
	Status                   string     `json:"status"`
	SourceEmail              string     `json:"source_email,omitempty"`
	SourceUsername           string     `json:"source_username,omitempty"`
	SourceGroup              string     `json:"source_group,omitempty"`
	PasswordCompatible       bool       `json:"password_compatible"`
	AuthorizationRedirectURL string     `json:"authorization_redirect_url,omitempty"`
	AuthorizationExpiresAt   *time.Time `json:"authorization_expires_at,omitempty"`
	SourceLockedAt           *time.Time `json:"source_locked_at,omitempty"`
	SourceLockExpiresAt      *time.Time `json:"source_lock_expires_at,omitempty"`
	LiveBalanceReadAt        *time.Time `json:"live_balance_read_at,omitempty"`
	SourceQuota              *int64     `json:"source_quota,omitempty"`
	SourceUsedQuota          *int64     `json:"source_used_quota,omitempty"`
	SourceAvailableQuota     *int64     `json:"source_available_quota,omitempty"`
	ConversionFactor         *float64   `json:"conversion_factor,omitempty"`
	ConvertedBalance         *float64   `json:"converted_balance,omitempty"`
	CreditedBalance          *float64   `json:"credited_balance,omitempty"`
	GeneratedAPIKeyID        *int64     `json:"generated_api_key_id,omitempty"`
	FailureCode              string     `json:"failure_code,omitempty"`
	FailureMessage           string     `json:"failure_message,omitempty"`
	CompletedAt              *time.Time `json:"completed_at,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

// MigrationStartRequest carries client input for starting a migration.
// TargetUserID is never read from the request body: the handler fills it from
// the authenticated session so a user can only migrate into their own account.
type MigrationStartRequest struct {
	MigrationID  string `json:"migration_id"`
	SourceSystem string `json:"source_system"`
	RedirectURL  string `json:"redirect_url"`
	TargetUserID int64  `json:"-"`
}

type MigrationStartResponse struct {
	Migration *UserMigration         `json:"migration"`
	Session   HKAuthorizationSession `json:"session"`
}

type MigrationPreview struct {
	Migration  *UserMigration `json:"migration"`
	CanConfirm bool           `json:"can_confirm"`
	Warnings   []string       `json:"warnings,omitempty"`
}

// MigrationConfirmRequest carries client input for confirming a migration.
// TargetUserID is filled by the handler from the authenticated session; the
// source user identity always comes from the HK authorization grant, never
// from the client.
type MigrationConfirmRequest struct {
	MigrationID        string `json:"migration_id"`
	AuthorizationState string `json:"authorization_state"`
	TargetUserID       int64  `json:"-"`
}

// MigrationConfirmResult returns the completed migration and, when a new API
// key was generated during this call, its plaintext value (shown exactly once).
type MigrationConfirmResult struct {
	Migration *UserMigration `json:"migration"`
	APIKey    string         `json:"api_key,omitempty"`
}

// MigrationCredit is the input for the atomic credit-and-complete step.
type MigrationCredit struct {
	MigrationID       string
	TargetUserID      int64
	CreditedBalance   float64
	APIKeyID          int64
	APIKeyFingerprint string
}

type UserMigrationRepository interface {
	Create(context.Context, *UserMigration) (*UserMigration, error)
	GetByMigrationID(context.Context, string) (*UserMigration, error)
	GetByMigrationIDForUser(ctx context.Context, migrationID string, targetUserID int64) (*UserMigration, error)
	GetActiveByTargetUserID(ctx context.Context, targetUserID int64) (*UserMigration, error)
	GetLatestByTargetUserID(ctx context.Context, targetUserID int64) (*UserMigration, error)
	// RecoverStaleProcessing releases a crashed confirm claim only when the
	// processing row has not been updated since staleBefore.
	RecoverStaleProcessing(ctx context.Context, migrationID string, staleBefore time.Time) (bool, error)
	UpdateAuthorization(context.Context, string, HKAuthorizationSession) error
	// BindSourceIdentity stores the real source identity resolved from the HK
	// grant. Returns ErrMigrationConflict when that source account is already
	// bound to another migration.
	BindSourceIdentity(ctx context.Context, migrationID, sourceUserID, sourceUsername, sourceEmail string) error
	// ClaimForConfirm atomically transitions the migration into 'processing'
	// so concurrent Confirm calls cannot both credit the balance. Returns
	// ErrMigrationConflict when the migration is not in a claimable state.
	ClaimForConfirm(ctx context.Context, migrationID string) error
	SetLocked(ctx context.Context, migrationID string, lockedAt, lockExpiresAt time.Time) error
	SetBalance(context.Context, string, HKBalanceSnapshot, float64, float64) error
	// CreditAndComplete performs, in one database transaction: the balance
	// ledger insert (idempotency guard), the users.balance credit, the key
	// map insert and the final status transition to 'completed'. Returns
	// ErrMigrationConflict if the migration was already credited.
	CreditAndComplete(ctx context.Context, credit MigrationCredit) error
	SetStatus(context.Context, string, string, string, string) error
	AddEvent(context.Context, string, string, string, map[string]any) error
}

// MigrationAPIKeyIssuer is the narrow slice of APIKeyService the migration
// flow needs: creating the replacement key and invalidating auth caches.
type MigrationAPIKeyIssuer interface {
	Create(ctx context.Context, userID int64, req CreateAPIKeyRequest) (*APIKey, error)
	InvalidateAuthCacheByUserID(ctx context.Context, userID int64)
}

// MigrationBalanceCacheInvalidator invalidates the cached balance after credit.
type MigrationBalanceCacheInvalidator interface {
	InvalidateUserBalance(ctx context.Context, userID int64) error
}

type MigrationOptions struct {
	AuthorizationTTL time.Duration
	LockTTL          time.Duration
	ConversionFactor float64
	PreviewOnly      bool
}

type MigrationService struct {
	repo         UserMigrationRepository
	client       HKNewAPIClient
	keyIssuer    MigrationAPIKeyIssuer
	balanceCache MigrationBalanceCacheInvalidator
	opts         MigrationOptions
}

func NewMigrationService(repo UserMigrationRepository, client HKNewAPIClient, keyIssuer MigrationAPIKeyIssuer, balanceCache MigrationBalanceCacheInvalidator, opts MigrationOptions) *MigrationService {
	if opts.AuthorizationTTL <= 0 {
		opts.AuthorizationTTL = 30 * time.Minute
	}
	if opts.LockTTL <= 0 {
		opts.LockTTL = 24 * time.Hour
	}
	// Never silently fall back to 1:1. The business conversion factor must be
	// explicitly configured before a migration can credit a real balance.
	return &MigrationService{repo: repo, client: client, keyIssuer: keyIssuer, balanceCache: balanceCache, opts: opts}
}

// confirmDisabled reports whether the credit step is allowed to run at all.
func (s *MigrationService) confirmDisabled() bool {
	return s.opts.PreviewOnly || s.opts.ConversionFactor <= 0
}

func isClaimableStatus(status string) bool {
	switch status {
	case MigrationStatusPending, MigrationStatusAuthorizing, MigrationStatusAuthorized, MigrationStatusFailed:
		return true
	}
	return false
}

// remainingQuota returns the HK-side remaining balance. In new-api semantics
// users.quota IS the remaining quota and used_quota is the lifetime spend, so
// subtracting used_quota again would double-charge the user.
func remainingQuota(b HKBalanceSnapshot) int64 {
	if b.AvailableQuota > 0 {
		return b.AvailableQuota
	}
	// Older sidecar builds did not return available_quota; fall back to the
	// raw quota field, never quota - used_quota.
	if b.Quota > 0 {
		return b.Quota
	}
	return 0
}

func (s *MigrationService) Start(ctx context.Context, req MigrationStartRequest) (*MigrationStartResponse, error) {
	if s == nil || s.repo == nil || s.client == nil {
		return nil, errors.New("migration service is not configured")
	}
	req.MigrationID = strings.TrimSpace(req.MigrationID)
	req.SourceSystem = strings.TrimSpace(req.SourceSystem)
	if req.MigrationID == "" || req.SourceSystem == "" || req.TargetUserID <= 0 {
		return nil, ErrMigrationInvalid
	}
	existing, err := s.repo.GetByMigrationID(ctx, req.MigrationID)
	if err == nil {
		if existing, err = s.recoverStaleProcessing(ctx, existing); err != nil {
			return nil, err
		}
		if existing.TargetUserID != req.TargetUserID {
			return nil, ErrMigrationConflict
		}
		if existing.Status == MigrationStatusCompleted {
			return &MigrationStartResponse{Migration: existing}, nil
		}
		return s.restartAuthorization(ctx, existing, req.RedirectURL)
	}
	if !errors.Is(err, ErrMigrationNotFound) {
		return nil, err
	}

	// A client may generate a fresh migration id when retrying Start. Resume the
	// target user's existing active row instead of colliding with the partial
	// unique index on target_user_id, and issue a fresh HK authorization session.
	existing, err = s.repo.GetActiveByTargetUserID(ctx, req.TargetUserID)
	if err == nil {
		if existing, err = s.recoverStaleProcessing(ctx, existing); err != nil {
			return nil, err
		}
		return s.restartAuthorization(ctx, existing, req.RedirectURL)
	}
	if !errors.Is(err, ErrMigrationNotFound) {
		return nil, err
	}

	// The real source user id is only known after HK completes authorization;
	// until then a per-migration placeholder keeps the unique index satisfied.
	m, err := s.repo.Create(ctx, &UserMigration{
		MigrationID:  req.MigrationID,
		SourceSystem: req.SourceSystem,
		SourceUserID: "pending:" + req.MigrationID,
		TargetUserID: req.TargetUserID,
		Status:       MigrationStatusPending,
	})
	if err != nil {
		return nil, err
	}
	return s.restartAuthorization(ctx, m, req.RedirectURL)
}

func (s *MigrationService) recoverStaleProcessing(ctx context.Context, m *UserMigration) (*UserMigration, error) {
	if m == nil || m.Status != MigrationStatusProcessing || m.UpdatedAt.IsZero() {
		return m, nil
	}
	staleBefore := time.Now().UTC().Add(-s.opts.LockTTL)
	if !m.UpdatedAt.Before(staleBefore) {
		return m, nil
	}
	recovered, err := s.repo.RecoverStaleProcessing(ctx, m.MigrationID, staleBefore)
	if err != nil || !recovered {
		return m, err
	}
	// The sidecar accepts migration_id + source_user_id for recovery, including
	// after grant expiry. Do not restart authorization while the source may
	// still be locked; surface the case for operator reconciliation instead.
	if err = s.client.UnlockAccount(ctx, HKGrant{MigrationID: m.MigrationID, SourceUserID: m.SourceUserID}); err != nil {
		_ = s.repo.SetStatus(ctx, m.MigrationID, MigrationStatusManualReview, "source_unlock_failed", err.Error())
	}
	return s.repo.GetByMigrationID(ctx, m.MigrationID)
}

func (s *MigrationService) restartAuthorization(ctx context.Context, m *UserMigration, redirectURL string) (*MigrationStartResponse, error) {
	if m == nil || m.MigrationID == "" || m.TargetUserID <= 0 {
		return nil, ErrMigrationInvalid
	}
	if m.Status == MigrationStatusLocked || m.Status == MigrationStatusProcessing || m.Status == MigrationStatusManualReview {
		return nil, fmt.Errorf("%w: migration is %s", ErrMigrationConflict, m.Status)
	}
	session, err := s.client.StartAuthorization(ctx, HKStartAuthorizationRequest{MigrationID: m.MigrationID, TargetUserID: m.TargetUserID, RedirectURL: redirectURL, ExpiresAt: time.Now().Add(s.opts.AuthorizationTTL)})
	if err != nil {
		_ = s.repo.SetStatus(ctx, m.MigrationID, MigrationStatusFailed, "authorization_start_failed", err.Error())
		return nil, err
	}
	if err = s.repo.UpdateAuthorization(ctx, m.MigrationID, session); err != nil {
		return nil, err
	}
	m.AuthorizationRedirectURL, m.AuthorizationExpiresAt, m.Status = session.AuthorizationURL, &session.ExpiresAt, MigrationStatusAuthorizing
	m.FailureCode, m.FailureMessage = "", ""
	return &MigrationStartResponse{Migration: m, Session: session}, nil
}

func (s *MigrationService) Status(ctx context.Context, migrationID string, targetUserID int64) (*UserMigration, error) {
	if s == nil || s.repo == nil {
		return nil, errors.New("migration service is not configured")
	}
	return s.repo.GetByMigrationIDForUser(ctx, strings.TrimSpace(migrationID), targetUserID)
}

// Current returns the authenticated user's current migration so the frontend
// can restore the page after a refresh or a lost localStorage pending id.
// Active rows take precedence; otherwise the most recently updated row is
// returned (completed / failed / manual_review).
func (s *MigrationService) Current(ctx context.Context, targetUserID int64) (*UserMigration, error) {
	if s == nil || s.repo == nil {
		return nil, errors.New("migration service is not configured")
	}
	if targetUserID <= 0 {
		return nil, ErrMigrationInvalid
	}
	existing, err := s.repo.GetActiveByTargetUserID(ctx, targetUserID)
	if err == nil {
		return s.recoverStaleProcessing(ctx, existing)
	}
	if !errors.Is(err, ErrMigrationNotFound) {
		return nil, err
	}
	return s.repo.GetLatestByTargetUserID(ctx, targetUserID)
}

func (s *MigrationService) Preview(ctx context.Context, migrationID string, targetUserID int64, authorizationState string) (*MigrationPreview, error) {
	m, err := s.Status(ctx, migrationID, targetUserID)
	if err != nil {
		return nil, err
	}

	// After the browser returns from HK, exchange the one-time authorization
	// state for a short-lived grant and persist only public source identity and
	// a display-only balance snapshot. Confirm still locks the source account
	// and reads the live balance again before crediting.
	if isClaimableStatus(m.Status) && strings.TrimSpace(authorizationState) != "" {
		grant, completeErr := s.client.CompleteAuthorization(ctx, HKCompleteAuthorizationRequest{
			MigrationID:        m.MigrationID,
			SourceUserID:       m.SourceUserID,
			AuthorizationState: strings.TrimSpace(authorizationState),
		})
		if completeErr != nil {
			return nil, completeErr
		}
		if err = s.repo.BindSourceIdentity(ctx, m.MigrationID, strings.TrimSpace(grant.SourceUserID), strings.TrimSpace(grant.SourceUsername), strings.TrimSpace(grant.SourceEmail)); err != nil {
			return nil, err
		}
		balance, balanceErr := s.client.ReadLiveBalance(ctx, grant)
		if balanceErr != nil {
			return nil, balanceErr
		}
		available := remainingQuota(balance)
		converted := float64(available) * s.opts.ConversionFactor
		if converted < 0 {
			converted = 0
		}
		if err = s.repo.SetBalance(ctx, m.MigrationID, balance, s.opts.ConversionFactor, converted); err != nil {
			return nil, err
		}
		if err = s.repo.SetStatus(ctx, m.MigrationID, MigrationStatusAuthorized, "", ""); err != nil {
			return nil, err
		}
		m, err = s.Status(ctx, migrationID, targetUserID)
		if err != nil {
			return nil, err
		}
	}

	p := &MigrationPreview{Migration: m, CanConfirm: m.Status == MigrationStatusAuthorized && !s.confirmDisabled()}
	if s.confirmDisabled() {
		p.Warnings = append(p.Warnings, "migration confirmation is currently disabled (preview only)")
	}
	if m.Status == MigrationStatusCompleted {
		p.Warnings = append(p.Warnings, "migration is already completed")
	}
	if m.Status == MigrationStatusFailed || m.Status == MigrationStatusManualReview {
		p.Warnings = append(p.Warnings, m.FailureMessage)
	}
	return p, nil
}

// Confirm completes authorization with the HK side, locks the source account,
// reads the live balance and atomically credits it to the target user while
// generating a replacement API key. The credit itself (ledger insert, balance
// update, key map, status transition) happens in a single database
// transaction, so a crash or concurrent confirm can never double-credit.
func (s *MigrationService) Confirm(ctx context.Context, req MigrationConfirmRequest) (*MigrationConfirmResult, error) {
	if s == nil || s.repo == nil || s.client == nil {
		return nil, errors.New("migration service is not configured")
	}
	if s.keyIssuer == nil {
		return nil, errors.New("migration service is missing the api key issuer")
	}
	if s.confirmDisabled() {
		return nil, ErrMigrationDisabled
	}
	req.MigrationID = strings.TrimSpace(req.MigrationID)
	if req.MigrationID == "" || req.TargetUserID <= 0 {
		return nil, ErrMigrationInvalid
	}
	m, err := s.repo.GetByMigrationIDForUser(ctx, req.MigrationID, req.TargetUserID)
	if err != nil {
		return nil, err
	}
	if m.Status == MigrationStatusCompleted {
		return &MigrationConfirmResult{Migration: m}, nil
	}
	if !isClaimableStatus(m.Status) {
		return nil, fmt.Errorf("%w: migration is %s", ErrMigrationConflict, m.Status)
	}

	grant, err := s.client.CompleteAuthorization(ctx, HKCompleteAuthorizationRequest{MigrationID: m.MigrationID, SourceUserID: m.SourceUserID, AuthorizationState: req.AuthorizationState})
	if err != nil {
		_ = s.repo.SetStatus(ctx, m.MigrationID, MigrationStatusFailed, "authorization_failed", err.Error())
		return nil, err
	}
	if sid := strings.TrimSpace(grant.SourceUserID); sid != "" {
		if err = s.repo.BindSourceIdentity(ctx, m.MigrationID, sid, strings.TrimSpace(grant.SourceUsername), strings.TrimSpace(grant.SourceEmail)); err != nil {
			if errors.Is(err, ErrMigrationConflict) {
				_ = s.repo.SetStatus(ctx, m.MigrationID, MigrationStatusFailed, "source_already_migrated", "source account is already bound to another migration")
			}
			return nil, err
		}
	}

	// Single-winner gate: only one concurrent Confirm can move the row into
	// 'processing'; every other caller gets ErrMigrationConflict here.
	if err = s.repo.ClaimForConfirm(ctx, m.MigrationID); err != nil {
		return nil, err
	}

	if err = s.client.LockAccount(ctx, grant); err != nil {
		_ = s.repo.SetStatus(ctx, m.MigrationID, MigrationStatusFailed, "lock_failed", err.Error())
		return nil, err
	}
	lockedAt := time.Now().UTC()
	_ = s.repo.SetLocked(ctx, m.MigrationID, lockedAt, lockedAt.Add(s.opts.LockTTL))

	balance, err := s.client.ReadLiveBalance(ctx, grant)
	if err != nil {
		s.failAndUnlock(ctx, grant, m.MigrationID, "balance_read_failed", err)
		return nil, err
	}
	available := remainingQuota(balance)
	converted := float64(available) * s.opts.ConversionFactor
	if converted < 0 {
		converted = 0
	}
	if err = s.repo.SetBalance(ctx, m.MigrationID, balance, s.opts.ConversionFactor, converted); err != nil {
		s.failAndUnlock(ctx, grant, m.MigrationID, "balance_store_failed", err)
		return nil, err
	}

	apiKey, err := s.keyIssuer.Create(ctx, m.TargetUserID, CreateAPIKeyRequest{Name: "Migrated " + m.MigrationID})
	if err != nil {
		s.failAndUnlock(ctx, grant, m.MigrationID, "api_key_failed", err)
		return nil, err
	}

	err = s.repo.CreditAndComplete(ctx, MigrationCredit{
		MigrationID:       m.MigrationID,
		TargetUserID:      m.TargetUserID,
		CreditedBalance:   converted,
		APIKeyID:          apiKey.ID,
		APIKeyFingerprint: fingerprintKey(apiKey.Key),
	})
	if err != nil {
		if errors.Is(err, ErrMigrationConflict) {
			// Another confirm already credited this migration; report its
			// final state instead of failing. The plaintext key from the
			// losing attempt is not returned.
			if current, readErr := s.repo.GetByMigrationIDForUser(ctx, m.MigrationID, m.TargetUserID); readErr == nil && current.Status == MigrationStatusCompleted {
				return &MigrationConfirmResult{Migration: current}, nil
			}
		}
		s.failAndUnlock(ctx, grant, m.MigrationID, "credit_failed", err)
		return nil, err
	}

	s.keyIssuer.InvalidateAuthCacheByUserID(ctx, m.TargetUserID)
	if s.balanceCache != nil {
		_ = s.balanceCache.InvalidateUserBalance(ctx, m.TargetUserID)
	}

	// The credit is already committed; a MarkMigrated failure must not undo
	// it. The source account stays locked, so we only record the incident
	// for operators to reconcile.
	if err = s.client.MarkMigrated(ctx, grant, m.MigrationID); err != nil {
		_ = s.repo.AddEvent(ctx, m.MigrationID, "mark_migrated_failed", "system", map[string]any{"error": err.Error()})
	}
	_ = s.repo.AddEvent(ctx, m.MigrationID, "completed", "system", map[string]any{"credited_balance": converted, "api_key_id": apiKey.ID})

	final, err := s.repo.GetByMigrationIDForUser(ctx, m.MigrationID, m.TargetUserID)
	if err != nil {
		return nil, err
	}
	return &MigrationConfirmResult{Migration: final, APIKey: apiKey.Key}, nil
}

func (s *MigrationService) failAndUnlock(ctx context.Context, grant HKGrant, migrationID, code string, cause error) {
	_ = s.client.UnlockAccount(ctx, grant)
	_ = s.repo.SetStatus(ctx, migrationID, MigrationStatusFailed, code, cause.Error())
}

func fingerprintKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
