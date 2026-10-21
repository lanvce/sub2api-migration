package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// fakeMigrationRepo is an in-memory UserMigrationRepository that mirrors the
// semantics of the SQL implementation: unique migration_id, unique source
// identity, single-winner claim and idempotent credit.
type fakeMigrationRepo struct {
	byMigrationID map[string]*UserMigration
	credited      map[string]bool
	events        []string
	nextID        int64
}

func newFakeMigrationRepo() *fakeMigrationRepo {
	return &fakeMigrationRepo{byMigrationID: map[string]*UserMigration{}, credited: map[string]bool{}}
}

func (f *fakeMigrationRepo) Create(_ context.Context, m *UserMigration) (*UserMigration, error) {
	if _, ok := f.byMigrationID[m.MigrationID]; ok {
		return nil, ErrMigrationConflict
	}
	for _, existing := range f.byMigrationID {
		if existing.SourceSystem == m.SourceSystem && existing.SourceUserID == m.SourceUserID {
			return nil, ErrMigrationConflict
		}
	}
	f.nextID++
	stored := *m
	stored.ID = f.nextID
	stored.CreatedAt = time.Now()
	stored.UpdatedAt = stored.CreatedAt
	f.byMigrationID[m.MigrationID] = &stored
	copied := stored
	return &copied, nil
}

func (f *fakeMigrationRepo) GetByMigrationID(_ context.Context, id string) (*UserMigration, error) {
	m, ok := f.byMigrationID[id]
	if !ok {
		return nil, ErrMigrationNotFound
	}
	copied := *m
	return &copied, nil
}

func (f *fakeMigrationRepo) GetByMigrationIDForUser(_ context.Context, id string, targetUserID int64) (*UserMigration, error) {
	m, ok := f.byMigrationID[id]
	if !ok || m.TargetUserID != targetUserID {
		return nil, ErrMigrationNotFound
	}
	copied := *m
	return &copied, nil
}

func (f *fakeMigrationRepo) GetActiveByTargetUserID(_ context.Context, targetUserID int64) (*UserMigration, error) {
	for _, m := range f.byMigrationID {
		if m.TargetUserID == targetUserID && (m.Status == MigrationStatusPending || m.Status == MigrationStatusAuthorizing || m.Status == MigrationStatusAuthorized || m.Status == MigrationStatusLocked || m.Status == MigrationStatusProcessing) {
			copied := *m
			return &copied, nil
		}
	}
	return nil, ErrMigrationNotFound
}

func (f *fakeMigrationRepo) GetLatestByTargetUserID(_ context.Context, targetUserID int64) (*UserMigration, error) {
	var latest *UserMigration
	for _, m := range f.byMigrationID {
		if m.TargetUserID != targetUserID {
			continue
		}
		if latest == nil || m.UpdatedAt.After(latest.UpdatedAt) {
			copied := *m
			latest = &copied
		}
	}
	if latest == nil {
		return nil, ErrMigrationNotFound
	}
	return latest, nil
}

func (f *fakeMigrationRepo) RecoverStaleProcessing(_ context.Context, id string, staleBefore time.Time) (bool, error) {
	m, ok := f.byMigrationID[id]
	if !ok || m.Status != MigrationStatusProcessing || !m.UpdatedAt.Before(staleBefore) {
		return false, nil
	}
	m.Status = MigrationStatusFailed
	m.FailureCode = "processing_timeout"
	m.FailureMessage = "migration processing expired; restart authorization"
	m.UpdatedAt = time.Now()
	return true, nil
}

func (f *fakeMigrationRepo) UpdateAuthorization(_ context.Context, id string, session HKAuthorizationSession) error {
	m, ok := f.byMigrationID[id]
	if !ok {
		return ErrMigrationNotFound
	}
	m.Status = MigrationStatusAuthorizing
	m.AuthorizationRedirectURL = session.AuthorizationURL
	expires := session.ExpiresAt
	m.AuthorizationExpiresAt = &expires
	return nil
}

func (f *fakeMigrationRepo) BindSourceIdentity(_ context.Context, id, sourceUserID, sourceUsername, sourceEmail string) error {
	target, ok := f.byMigrationID[id]
	if !ok {
		return ErrMigrationNotFound
	}
	for _, existing := range f.byMigrationID {
		if existing.MigrationID != id && existing.SourceSystem == target.SourceSystem && existing.SourceUserID == sourceUserID {
			return ErrMigrationConflict
		}
	}
	target.SourceUserID = sourceUserID
	target.SourceUsername = sourceUsername
	target.SourceEmail = sourceEmail
	return nil
}

func (f *fakeMigrationRepo) ClaimForConfirm(_ context.Context, id string) error {
	m, ok := f.byMigrationID[id]
	if !ok {
		return ErrMigrationNotFound
	}
	if !isClaimableStatus(m.Status) {
		return ErrMigrationConflict
	}
	m.Status = MigrationStatusProcessing
	m.FailureCode, m.FailureMessage = "", ""
	return nil
}

func (f *fakeMigrationRepo) SetLocked(_ context.Context, id string, lockedAt, lockExpiresAt time.Time) error {
	m, ok := f.byMigrationID[id]
	if !ok {
		return ErrMigrationNotFound
	}
	m.SourceLockedAt, m.SourceLockExpiresAt = &lockedAt, &lockExpiresAt
	return nil
}

func (f *fakeMigrationRepo) SetBalance(_ context.Context, id string, b HKBalanceSnapshot, factor, converted float64) error {
	m, ok := f.byMigrationID[id]
	if !ok {
		return ErrMigrationNotFound
	}
	// Mirror the SQL repo: quota is already the remaining quota.
	available := b.Quota
	if b.AvailableQuota > 0 {
		available = b.AvailableQuota
	}
	if available < 0 {
		available = 0
	}
	readAt := b.ReadAt
	m.LiveBalanceReadAt = &readAt
	m.SourceQuota, m.SourceUsedQuota, m.SourceAvailableQuota = &b.Quota, &b.UsedQuota, &available
	m.ConversionFactor, m.ConvertedBalance = &factor, &converted
	return nil
}

func (f *fakeMigrationRepo) CreditAndComplete(_ context.Context, credit MigrationCredit) error {
	m, ok := f.byMigrationID[credit.MigrationID]
	if !ok {
		return ErrMigrationNotFound
	}
	if f.credited[credit.MigrationID] || m.Status != MigrationStatusProcessing {
		return ErrMigrationConflict
	}
	f.credited[credit.MigrationID] = true
	m.Status = MigrationStatusCompleted
	balance := credit.CreditedBalance
	m.CreditedBalance = &balance
	keyID := credit.APIKeyID
	m.GeneratedAPIKeyID = &keyID
	now := time.Now()
	m.CompletedAt = &now
	m.FailureCode, m.FailureMessage = "", ""
	return nil
}

func (f *fakeMigrationRepo) SetStatus(_ context.Context, id, status, code, message string) error {
	m, ok := f.byMigrationID[id]
	if !ok {
		return ErrMigrationNotFound
	}
	m.Status, m.FailureCode, m.FailureMessage = status, code, message
	return nil
}

func (f *fakeMigrationRepo) AddEvent(_ context.Context, id, eventType, _ string, _ map[string]any) error {
	f.events = append(f.events, id+":"+eventType)
	return nil
}

type fakeKeyIssuer struct {
	created            []int64
	invalidatedUserIDs []int64
	err                error
}

func (f *fakeKeyIssuer) Create(_ context.Context, userID int64, _ CreateAPIKeyRequest) (*APIKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.created = append(f.created, userID)
	return &APIKey{ID: 101, UserID: userID, Key: "sk-migrated-test-key"}, nil
}

func (f *fakeKeyIssuer) InvalidateAuthCacheByUserID(_ context.Context, userID int64) {
	f.invalidatedUserIDs = append(f.invalidatedUserIDs, userID)
}

type fakeBalanceCache struct{ invalidated []int64 }

func (f *fakeBalanceCache) InvalidateUserBalance(_ context.Context, userID int64) error {
	f.invalidated = append(f.invalidated, userID)
	return nil
}

type recoveringHKClient struct {
	*FakeHKNewAPIClient
	recovered []string
	unlockErr error
}

func (f *recoveringHKClient) UnlockAccount(_ context.Context, grant HKGrant) error {
	migrationID, sourceUserID := grant.MigrationID, grant.SourceUserID
	f.recovered = append(f.recovered, migrationID+":"+sourceUserID)
	return f.unlockErr
}

// failingBalanceClient overrides ReadLiveBalance to simulate an HK-side outage
// after the account has already been locked.
type failingBalanceClient struct{ *FakeHKNewAPIClient }

func (f *failingBalanceClient) ReadLiveBalance(context.Context, HKGrant) (HKBalanceSnapshot, error) {
	return HKBalanceSnapshot{}, fmt.Errorf("hk sidecar unavailable")
}

type recordingStartClient struct {
	*FakeHKNewAPIClient
	starts []HKStartAuthorizationRequest
}

func (f *recordingStartClient) StartAuthorization(_ context.Context, req HKStartAuthorizationRequest) (HKAuthorizationSession, error) {
	f.starts = append(f.starts, req)
	return HKAuthorizationSession{
		AuthorizationURL: fmt.Sprintf("https://hk.test/authorize/%d", len(f.starts)),
		State:            fmt.Sprintf("state-%d", len(f.starts)),
		ExpiresAt:        req.ExpiresAt,
	}, nil
}

func startTestMigration(t *testing.T, svc *MigrationService, migrationID string, targetUserID int64) {
	t.Helper()
	_, err := svc.Start(context.Background(), MigrationStartRequest{MigrationID: migrationID, SourceSystem: "hk-newapi", TargetUserID: targetUserID})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
}

func TestMigrationConfirmDisabledByPreviewOnly(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{Grant: HKGrant{SourceUserID: "hk-user-1"}}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01, PreviewOnly: true})
	startTestMigration(t, svc, "mig-1", 7)

	_, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7})
	if !errors.Is(err, ErrMigrationDisabled) {
		t.Fatalf("expected ErrMigrationDisabled, got %v", err)
	}
	if len(repo.credited) != 0 {
		t.Fatal("preview-only mode must never credit a balance")
	}
}

func TestMigrationConfirmDisabledByMissingFactor(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{Grant: HKGrant{SourceUserID: "hk-user-1"}}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0})
	startTestMigration(t, svc, "mig-1", 7)

	_, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7})
	if !errors.Is(err, ErrMigrationDisabled) {
		t.Fatalf("expected ErrMigrationDisabled when factor is unset, got %v", err)
	}
}

func TestMigrationConfirmHappyPath(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{
		Grant:   HKGrant{MigrationID: "mig-1", SourceUserID: "hk-user-1"},
		Balance: HKBalanceSnapshot{Quota: 1000, UsedQuota: 250},
	}
	issuer := &fakeKeyIssuer{}
	cache := &fakeBalanceCache{}
	svc := NewMigrationService(repo, client, issuer, cache, MigrationOptions{ConversionFactor: 0.01})
	startTestMigration(t, svc, "mig-1", 7)

	result, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7, AuthorizationState: "state"})
	if err != nil {
		t.Fatalf("Confirm failed: %v", err)
	}
	if result.APIKey != "sk-migrated-test-key" {
		t.Fatalf("expected plaintext key in result, got %q", result.APIKey)
	}
	if result.Migration.Status != MigrationStatusCompleted {
		t.Fatalf("expected completed, got %s", result.Migration.Status)
	}
	// users.quota is already the remaining quota: 1000 * 0.01 = 10.0.
	// used_quota (250) is the lifetime spend and must NOT be subtracted again.
	if result.Migration.CreditedBalance == nil || *result.Migration.CreditedBalance != 10.0 {
		t.Fatalf("expected credited balance 10.0, got %v", result.Migration.CreditedBalance)
	}
	if result.Migration.SourceAvailableQuota == nil || *result.Migration.SourceAvailableQuota != 1000 {
		t.Fatalf("expected source available quota 1000, got %v", result.Migration.SourceAvailableQuota)
	}
	if result.Migration.SourceUsedQuota == nil || *result.Migration.SourceUsedQuota != 250 {
		t.Fatalf("expected source used quota 250, got %v", result.Migration.SourceUsedQuota)
	}
	if result.Migration.SourceUserID != "hk-user-1" {
		t.Fatalf("expected bound source user hk-user-1, got %s", result.Migration.SourceUserID)
	}
	if !client.Locked {
		t.Fatal("source account must remain locked after migration")
	}
	if len(client.Marked) != 1 || client.Marked[0] != "mig-1" {
		t.Fatalf("expected MarkMigrated for mig-1, got %v", client.Marked)
	}
	if len(issuer.invalidatedUserIDs) != 1 || issuer.invalidatedUserIDs[0] != 7 {
		t.Fatalf("expected auth cache invalidation for user 7, got %v", issuer.invalidatedUserIDs)
	}
	if len(cache.invalidated) != 1 || cache.invalidated[0] != 7 {
		t.Fatalf("expected balance cache invalidation for user 7, got %v", cache.invalidated)
	}
}

func TestMigrationConfirmIsIdempotent(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{
		Grant:   HKGrant{MigrationID: "mig-1", SourceUserID: "hk-user-1"},
		Balance: HKBalanceSnapshot{Quota: 1000, UsedQuota: 0},
	}
	issuer := &fakeKeyIssuer{}
	svc := NewMigrationService(repo, client, issuer, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})
	startTestMigration(t, svc, "mig-1", 7)

	first, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7})
	if err != nil {
		t.Fatalf("first Confirm failed: %v", err)
	}
	second, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7})
	if err != nil {
		t.Fatalf("second Confirm failed: %v", err)
	}
	if second.APIKey != "" {
		t.Fatal("repeat confirm must not return a plaintext key again")
	}
	if second.Migration.Status != MigrationStatusCompleted {
		t.Fatalf("expected completed on repeat confirm, got %s", second.Migration.Status)
	}
	if len(issuer.created) != 1 {
		t.Fatalf("expected exactly one API key creation, got %d", len(issuer.created))
	}
	if *first.Migration.CreditedBalance != *second.Migration.CreditedBalance {
		t.Fatal("credited balance must not change on repeat confirm")
	}
}

func TestMigrationConfirmBalanceReadFailureUnlocks(t *testing.T) {
	repo := newFakeMigrationRepo()
	inner := &FakeHKNewAPIClient{Grant: HKGrant{MigrationID: "mig-1", SourceUserID: "hk-user-1"}}
	client := &failingBalanceClient{FakeHKNewAPIClient: inner}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})
	startTestMigration(t, svc, "mig-1", 7)

	_, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7})
	if err == nil {
		t.Fatal("expected balance read failure")
	}
	if inner.Locked {
		t.Fatal("source account must be unlocked after a failed confirm")
	}
	m, _ := repo.GetByMigrationID(context.Background(), "mig-1")
	if m.Status != MigrationStatusFailed || m.FailureCode != "balance_read_failed" {
		t.Fatalf("expected failed/balance_read_failed, got %s/%s", m.Status, m.FailureCode)
	}
	if len(repo.credited) != 0 {
		t.Fatal("failed confirm must never credit a balance")
	}
}

func TestMigrationConfirmRetryAfterFailure(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{
		Grant:   HKGrant{MigrationID: "mig-1", SourceUserID: "hk-user-1"},
		Balance: HKBalanceSnapshot{Quota: 500, UsedQuota: 100},
	}
	issuer := &fakeKeyIssuer{err: fmt.Errorf("key store down")}
	svc := NewMigrationService(repo, client, issuer, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})
	startTestMigration(t, svc, "mig-1", 7)

	if _, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7}); err == nil {
		t.Fatal("expected key creation failure")
	}
	issuer.err = nil
	result, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7})
	if err != nil {
		t.Fatalf("retry after failure should succeed, got %v", err)
	}
	if result.Migration.Status != MigrationStatusCompleted {
		t.Fatalf("expected completed after retry, got %s", result.Migration.Status)
	}
}

func TestMigrationStartResumesExistingTargetMigrationAndReissuesSession(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &recordingStartClient{FakeHKNewAPIClient: &FakeHKNewAPIClient{}}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})

	first, err := svc.Start(context.Background(), MigrationStartRequest{MigrationID: "mig-1", SourceSystem: "hk-newapi", TargetUserID: 7, RedirectURL: "https://us.test/first"})
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	second, err := svc.Start(context.Background(), MigrationStartRequest{MigrationID: "mig-2", SourceSystem: "hk-newapi", TargetUserID: 7, RedirectURL: "https://us.test/retry"})
	if err != nil {
		t.Fatalf("retry Start should resume existing target migration: %v", err)
	}
	if second.Migration.MigrationID != first.Migration.MigrationID || second.Migration.MigrationID != "mig-1" {
		t.Fatalf("expected existing migration mig-1, got %q", second.Migration.MigrationID)
	}
	if second.Session.State != "state-2" || second.Session.AuthorizationURL == first.Session.AuthorizationURL {
		t.Fatalf("expected a newly issued HK session, got %+v", second.Session)
	}
	if len(client.starts) != 2 || client.starts[1].MigrationID != "mig-1" || client.starts[1].RedirectURL != "https://us.test/retry" {
		t.Fatalf("expected retry to authorize existing migration with new redirect, got %+v", client.starts)
	}
	if len(repo.byMigrationID) != 1 {
		t.Fatalf("expected no duplicate migration row, got %d", len(repo.byMigrationID))
	}
}

func TestMigrationStartSameMigrationReissuesSession(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &recordingStartClient{FakeHKNewAPIClient: &FakeHKNewAPIClient{}}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})
	startTestMigration(t, svc, "mig-1", 7)

	result, err := svc.Start(context.Background(), MigrationStartRequest{MigrationID: "mig-1", SourceSystem: "hk-newapi", TargetUserID: 7})
	if err != nil {
		t.Fatalf("repeat Start failed: %v", err)
	}
	if result.Session.State != "state-2" || len(client.starts) != 2 {
		t.Fatalf("expected repeat Start to reissue HK session, got %+v", result.Session)
	}
}

func TestMigrationStartRejectsForeignMigrationID(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})
	startTestMigration(t, svc, "mig-1", 7)

	_, err := svc.Start(context.Background(), MigrationStartRequest{MigrationID: "mig-1", SourceSystem: "hk-newapi", TargetUserID: 8})
	if !errors.Is(err, ErrMigrationConflict) {
		t.Fatalf("expected conflict when migration id belongs to another user, got %v", err)
	}
}

func TestMigrationCurrentPrefersActiveThenLatest(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})

	if _, err := svc.Current(context.Background(), 7); !errors.Is(err, ErrMigrationNotFound) {
		t.Fatalf("expected not found when user has no migration, got %v", err)
	}

	startTestMigration(t, svc, "mig-active", 7)
	current, err := svc.Current(context.Background(), 7)
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}
	if current.MigrationID != "mig-active" {
		t.Fatalf("expected active migration, got %q", current.MigrationID)
	}

	completed := repo.byMigrationID["mig-active"]
	completed.Status = MigrationStatusCompleted
	completed.UpdatedAt = time.Now().Add(time.Minute)
	current, err = svc.Current(context.Background(), 7)
	if err != nil {
		t.Fatalf("Current should fall back to completed migration: %v", err)
	}
	if current.Status != MigrationStatusCompleted {
		t.Fatalf("expected completed fallback, got %s", current.Status)
	}
}

func TestMigrationCurrentRecoversStaleProcessingAndUnlocksSource(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &recoveringHKClient{FakeHKNewAPIClient: &FakeHKNewAPIClient{}}
	started, err := repo.Create(context.Background(), &UserMigration{
		MigrationID: "stale-processing", SourceSystem: "hk-newapi", SourceUserID: "42",
		TargetUserID: 7, Status: MigrationStatusProcessing,
	})
	if err != nil {
		t.Fatal(err)
	}
	repo.byMigrationID[started.MigrationID].UpdatedAt = time.Now().Add(-time.Hour)
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, nil, MigrationOptions{ConversionFactor: 0.01, LockTTL: time.Minute})

	got, err := svc.Current(context.Background(), 7)
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}
	if got.Status != MigrationStatusFailed || got.FailureCode != "processing_timeout" {
		t.Fatalf("expected stale processing to become failed, got %s/%s", got.Status, got.FailureCode)
	}
	if len(client.recovered) != 1 || client.recovered[0] != "stale-processing:42" {
		t.Fatalf("expected stale source lock recovery, got %v", client.recovered)
	}
}

func TestMigrationCurrentKeepsRecentProcessingInFlight(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &recoveringHKClient{FakeHKNewAPIClient: &FakeHKNewAPIClient{}}
	started, err := repo.Create(context.Background(), &UserMigration{
		MigrationID: "recent-processing", SourceSystem: "hk-newapi", SourceUserID: "42",
		TargetUserID: 7, Status: MigrationStatusProcessing,
	})
	if err != nil {
		t.Fatal(err)
	}
	repo.byMigrationID[started.MigrationID].UpdatedAt = time.Now()
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, nil, MigrationOptions{ConversionFactor: 0.01, LockTTL: time.Minute})

	got, err := svc.Current(context.Background(), 7)
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}
	if got.Status != MigrationStatusProcessing {
		t.Fatalf("expected recent processing state to remain active, got %s", got.Status)
	}
	if len(client.recovered) != 0 {
		t.Fatalf("recent processing state must not be recovered, got %v", client.recovered)
	}
}

func TestMigrationCurrentRequiresManualReviewWhenStaleSourceUnlockFails(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &recoveringHKClient{
		FakeHKNewAPIClient: &FakeHKNewAPIClient{},
		unlockErr:          fmt.Errorf("sidecar database unavailable"),
	}
	started, err := repo.Create(context.Background(), &UserMigration{
		MigrationID: "stale-unlock-failed", SourceSystem: "hk-newapi", SourceUserID: "42",
		TargetUserID: 7, Status: MigrationStatusProcessing,
	})
	if err != nil {
		t.Fatal(err)
	}
	repo.byMigrationID[started.MigrationID].UpdatedAt = time.Now().Add(-time.Hour)
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, nil, MigrationOptions{ConversionFactor: 0.01, LockTTL: time.Minute})

	got, err := svc.Current(context.Background(), 7)
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}
	if got.Status != MigrationStatusManualReview || got.FailureCode != "source_unlock_failed" {
		t.Fatalf("failed source unlock must require manual review, got %s/%s", got.Status, got.FailureCode)
	}
	if len(client.recovered) != 1 {
		t.Fatalf("expected one unlock attempt, got %v", client.recovered)
	}
}

func TestMigrationStatusScopedToOwner(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})
	startTestMigration(t, svc, "mig-1", 7)

	if _, err := svc.Status(context.Background(), "mig-1", 7); err != nil {
		t.Fatalf("owner must see own migration, got %v", err)
	}
	if _, err := svc.Status(context.Background(), "mig-1", 8); !errors.Is(err, ErrMigrationNotFound) {
		t.Fatalf("foreign user must get not found, got %v", err)
	}
}

func TestMigrationPreviewWarnsWhenDisabled(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01, PreviewOnly: true})
	startTestMigration(t, svc, "mig-1", 7)

	preview, err := svc.Preview(context.Background(), "mig-1", 7, "")
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}
	if preview.CanConfirm {
		t.Fatal("CanConfirm must be false in preview-only mode")
	}
	if len(preview.Warnings) == 0 {
		t.Fatal("expected a preview-only warning")
	}
}

// TestMigrationPreviewExchangesAuthorizationState verifies the post-redirect
// flow: Preview exchanges the one-time state, persists the full source
// identity, records a display-only balance snapshot with the remaining-quota
// semantics, and flips the migration into 'authorized' so the confirm page has
// real data to show.
func TestMigrationPreviewExchangesAuthorizationState(t *testing.T) {
	repo := newFakeMigrationRepo()
	client := &FakeHKNewAPIClient{
		Grant: HKGrant{
			MigrationID:    "mig-1",
			SourceUserID:   "hk-user-1",
			SourceUsername: "alice_with_a_very_long_name",
			SourceEmail:    "alice@example.com",
		},
		Balance: HKBalanceSnapshot{Quota: 3_000_000, UsedQuota: 500_000, AvailableQuota: 3_000_000, QuotaPerUnit: 500_000},
	}
	svc := NewMigrationService(repo, client, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.000002})
	startTestMigration(t, svc, "mig-1", 7)

	preview, err := svc.Preview(context.Background(), "mig-1", 7, "state")
	if err != nil {
		t.Fatalf("Preview failed: %v", err)
	}
	m := preview.Migration
	if m.Status != MigrationStatusAuthorized {
		t.Fatalf("expected authorized after state exchange, got %s", m.Status)
	}
	if !preview.CanConfirm {
		t.Fatal("CanConfirm must be true once authorized")
	}
	if m.SourceUsername != "alice_with_a_very_long_name" {
		t.Fatalf("expected full source username, got %q", m.SourceUsername)
	}
	if m.SourceEmail != "alice@example.com" {
		t.Fatalf("expected full source email, got %q", m.SourceEmail)
	}
	if m.SourceAvailableQuota == nil || *m.SourceAvailableQuota != 3_000_000 {
		t.Fatalf("expected available quota 3000000, got %v", m.SourceAvailableQuota)
	}
	if m.ConvertedBalance == nil || *m.ConvertedBalance != 6.0 {
		t.Fatalf("expected preview converted balance 6.0, got %v", m.ConvertedBalance)
	}
	// The preview must not lock the account or credit anything yet.
	if client.Locked {
		t.Fatal("preview must not lock the source account")
	}
	if len(repo.credited) != 0 {
		t.Fatal("preview must never credit a balance")
	}

	// Confirm afterwards still works and credits the full remaining quota.
	result, err := svc.Confirm(context.Background(), MigrationConfirmRequest{MigrationID: "mig-1", TargetUserID: 7, AuthorizationState: "state"})
	if err != nil {
		t.Fatalf("Confirm after preview failed: %v", err)
	}
	if result.Migration.CreditedBalance == nil || *result.Migration.CreditedBalance != 6.0 {
		t.Fatalf("expected credited balance 6.0, got %v", result.Migration.CreditedBalance)
	}
}

func TestMigrationStartDisabledClientReturnsErrMigrationDisabled(t *testing.T) {
	repo := newFakeMigrationRepo()
	svc := NewMigrationService(repo, &disabledHKNewAPIClient{}, &fakeKeyIssuer{}, &fakeBalanceCache{}, MigrationOptions{ConversionFactor: 0.01})

	_, err := svc.Start(context.Background(), MigrationStartRequest{
		MigrationID:  "mig-disabled",
		SourceSystem: "hk-newapi",
		TargetUserID: 7,
	})
	if !errors.Is(err, ErrMigrationDisabled) {
		t.Fatalf("expected ErrMigrationDisabled, got %v", err)
	}

	m, getErr := repo.GetByMigrationID(context.Background(), "mig-disabled")
	if getErr != nil {
		t.Fatalf("Start still creates the row before sidecar failure, got %v", getErr)
	}
	if m.Status != MigrationStatusFailed || m.FailureCode != "authorization_start_failed" {
		t.Fatalf("expected failed/authorization_start_failed, got %s/%s", m.Status, m.FailureCode)
	}
	if m.TargetUserID != 7 {
		t.Fatalf("expected target user 7, got %d", m.TargetUserID)
	}
}
