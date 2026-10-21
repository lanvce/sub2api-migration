package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type memUsers struct {
	byID       map[int64]*UserRecord
	byLogin    map[string]*UserRecord
	restoreErr error
}

func (m *memUsers) FindByLogin(_ context.Context, identifier string) (*UserRecord, error) {
	u, ok := m.byLogin[identifier]
	if !ok {
		return nil, errUserNotFound
	}
	cp := *u
	return &cp, nil
}
func (m *memUsers) FindByID(_ context.Context, id int64) (*UserRecord, error) {
	u, ok := m.byID[id]
	if !ok {
		return nil, errUserNotFound
	}
	cp := *u
	return &cp, nil
}
func (m *memUsers) UpdateStatus(_ context.Context, id, status int64) error {
	u, ok := m.byID[id]
	if !ok {
		return errUserNotFound
	}
	u.Status = status
	now := time.Now().UTC()
	if !now.After(u.UpdatedAt) {
		now = u.UpdatedAt.Add(time.Microsecond)
	}
	u.UpdatedAt = now
	return nil
}
func (m *memUsers) LockStatus(_ context.Context, id int64, expectedUpdatedAt time.Time) (time.Time, bool, error) {
	u, ok := m.byID[id]
	if !ok {
		return time.Time{}, false, errUserNotFound
	}
	if u.Status != userStatusEnabled || !u.UpdatedAt.Equal(expectedUpdatedAt) {
		return time.Time{}, false, nil
	}
	now := time.Now().UTC()
	if !now.After(u.UpdatedAt) {
		now = u.UpdatedAt.Add(time.Microsecond)
	}
	u.Status = userStatusLocked
	u.UpdatedAt = now
	return now, true, nil
}
func (m *memUsers) MarkMigrated(_ context.Context, id int64, expectedUpdatedAt time.Time) (time.Time, bool, error) {
	u, ok := m.byID[id]
	if !ok {
		return time.Time{}, false, errUserNotFound
	}
	if u.Status != userStatusLocked || !u.UpdatedAt.Equal(expectedUpdatedAt) {
		return time.Time{}, false, nil
	}
	now := time.Now().UTC()
	if !now.After(u.UpdatedAt) {
		now = u.UpdatedAt.Add(time.Microsecond)
	}
	u.UpdatedAt = now
	return now, true, nil
}
func (m *memUsers) RestoreStatus(_ context.Context, id int64, expectedUpdatedAt time.Time, status int64) (bool, error) {
	if m.restoreErr != nil {
		return false, m.restoreErr
	}
	u, ok := m.byID[id]
	if !ok {
		return false, errUserNotFound
	}
	if u.Status != userStatusLocked || !u.UpdatedAt.Equal(expectedUpdatedAt) {
		return false, nil
	}
	u.Status = status
	now := time.Now().UTC()
	if !now.After(u.UpdatedAt) {
		now = u.UpdatedAt.Add(time.Microsecond)
	}
	u.UpdatedAt = now
	return true, nil
}
func (m *memUsers) Ping(context.Context) error { return nil }

func newTestServer(t *testing.T) (*server, *memUsers) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("passw0rd"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := &UserRecord{ID: 42, Username: "alice", Email: "alice@example.com", Password: string(hash), Status: 1, Quota: 1_000_000, UsedQuota: 250_000, UpdatedAt: time.Now().UTC()}
	users := &memUsers{byID: map[int64]*UserRecord{42: u}, byLogin: map[string]*UserRecord{"alice": u, "alice@example.com": u}}
	store, err := newSessionStore(t.TempDir() + "/sessions.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server{
		cfg: &config{
			ListenAddr:    ":0",
			PublicBaseURL: "https://api.example.com/migration",
			SharedSecret:  []byte("0123456789abcdef"),
			AuthFallback:  10 * time.Minute,
			GrantTTL:      2 * time.Hour,
			QuotaPerUnit:  500000,
		},
		users: users,
		store: store,
		ips:   newIPLimiter(100, time.Minute),
	}
	return srv, users
}

func sign(secret []byte, method, path string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(method + "\n" + path))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func doJSON(t *testing.T, srv *server, method, path string, body any, signed bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if signed {
		req.Header.Set("X-Migration-Signature", sign(srv.cfg.SharedSecret, method, path))
	}
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/authorize", srv.handleAuthorizePage)
	mux.HandleFunc("/api/session", srv.handleSessionInfo)
	mux.HandleFunc("/api/login", srv.handleLogin)
	mux.HandleFunc("/api/approve", srv.handleApprove)
	mux.HandleFunc("/internal/migration/authorize/start", srv.requireInternal(srv.handleInternalStart))
	mux.HandleFunc("/internal/migration/authorize/complete", srv.requireInternal(srv.handleInternalComplete))
	mux.HandleFunc("/internal/migration/lock", srv.requireInternal(srv.handleInternalLock))
	mux.HandleFunc("/internal/migration/unlock", srv.requireInternal(srv.handleInternalUnlock))
	mux.HandleFunc("/internal/migration/balance", srv.requireInternal(srv.handleInternalBalance))
	mux.HandleFunc("/internal/migration/mark-migrated", srv.requireInternal(srv.handleInternalMarkMigrated))
	mux.ServeHTTP(rr, req)
	return rr
}

func TestHappyPath(t *testing.T) {
	srv, users := newTestServer(t)

	// 1. start
	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/start", map[string]any{
		"migration_id":   "mig-1",
		"target_user_id": 7,
		"redirect_url":   "https://us.example.com/migration",
		"expires_at":     time.Now().Add(5 * time.Minute),
	}, true)
	if rr.Code != 200 {
		t.Fatalf("start: %d %s", rr.Code, rr.Body.String())
	}
	var startOut map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &startOut)
	state, _ := startOut["state"].(string)
	authURL, _ := startOut["authorization_url"].(string)
	if state == "" || authURL == "" {
		t.Fatalf("missing state/url: %#v", startOut)
	}

	sess, ok := srv.store.Get("mig-1")
	if !ok {
		t.Fatal("session missing")
	}
	pageToken := sess.PageToken

	// 2. login
	rr = doJSON(t, srv, http.MethodPost, "/api/login", map[string]any{
		"migration_id": "mig-1",
		"page_token":   pageToken,
		"identifier":   "alice",
		"password":     "passw0rd",
	}, false)
	if rr.Code != 200 {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	var loginOut map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &loginOut)
	// Full identity is returned to the page_token holder (no masking).
	if loginOut["username"] != "alice" || loginOut["email"] != "alice@example.com" {
		t.Fatalf("login identity must be unmasked, got %#v", loginOut)
	}

	// 3. approve
	rr = doJSON(t, srv, http.MethodPost, "/api/approve", map[string]any{
		"migration_id": "mig-1",
		"page_token":   pageToken,
	}, false)
	if rr.Code != 200 {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	var approveOut map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &approveOut)
	redirect, _ := approveOut["redirect_url"].(string)
	if redirect == "" || !bytes.Contains([]byte(redirect), []byte("state="+state)) {
		t.Fatalf("bad redirect: %q", redirect)
	}

	// 4. complete
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/complete", map[string]any{
		"migration_id":        "mig-1",
		"source_user_id":      "pending:mig-1",
		"authorization_state": state,
	}, true)
	if rr.Code != 200 {
		t.Fatalf("complete: %d %s", rr.Code, rr.Body.String())
	}
	var grant map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &grant)
	if grant["source_user_id"] != "42" {
		t.Fatalf("source id: %#v", grant)
	}
	// The grant carries the full source identity so the US side can bind and
	// display it on the confirm page.
	if grant["username"] != "alice" || grant["email"] != "alice@example.com" {
		t.Fatalf("grant identity: %#v", grant)
	}

	// 5. lock
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id":   "mig-1",
		"source_user_id": "42",
	}, true)
	if rr.Code != 200 {
		t.Fatalf("lock: %d %s", rr.Code, rr.Body.String())
	}
	if users.byID[42].Status != userStatusLocked {
		t.Fatalf("user not locked: %d", users.byID[42].Status)
	}

	// 6. balance
	balPath := "/internal/migration/balance?migration_id=mig-1&source_user_id=42"
	rr = doJSON(t, srv, http.MethodGet, balPath, nil, true)
	if rr.Code != 200 {
		t.Fatalf("balance: %d %s", rr.Code, rr.Body.String())
	}
	var bal map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &bal)
	if int64(bal["quota"].(float64)) != 1_000_000 || int64(bal["used_quota"].(float64)) != 250_000 {
		t.Fatalf("balance: %#v", bal)
	}
	// available_quota is the remaining quota (never quota - used_quota) and
	// quota_per_unit lets the US side audit the conversion config.
	if int64(bal["available_quota"].(float64)) != 1_000_000 {
		t.Fatalf("available quota: %#v", bal)
	}
	if int64(bal["quota_per_unit"].(float64)) != 500_000 {
		t.Fatalf("quota per unit: %#v", bal)
	}

	// 7. mark migrated
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/mark-migrated", map[string]any{
		"migration_id":   "mig-1",
		"source_user_id": "42",
	}, true)
	if rr.Code != 200 {
		t.Fatalf("mark: %d %s", rr.Code, rr.Body.String())
	}

	// unlock must fail after migrated
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/unlock", map[string]any{
		"migration_id":   "mig-1",
		"source_user_id": strconv.FormatInt(42, 10),
	}, true)
	if rr.Code != http.StatusConflict {
		t.Fatalf("unlock after migrate should conflict, got %d", rr.Code)
	}
}

func TestRejectBadSignature(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/internal/migration/authorize/start", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Migration-Signature", "deadbeef")
	rr := httptest.NewRecorder()
	srv.requireInternal(srv.handleInternalStart)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rr.Code)
	}
}

// driveToApproved walks a fresh migration through start → login → approve and
// returns (state, pageToken).
func driveToApproved(t *testing.T, srv *server, migrationID string) (string, string) {
	t.Helper()
	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/start", map[string]any{
		"migration_id":   migrationID,
		"target_user_id": 7,
		"redirect_url":   "https://us.example.com/migration",
		"expires_at":     time.Now().Add(5 * time.Minute),
	}, true)
	if rr.Code != 200 {
		t.Fatalf("start: %d %s", rr.Code, rr.Body.String())
	}
	var startOut map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &startOut)
	state, _ := startOut["state"].(string)

	sess, ok := srv.store.Get(migrationID)
	if !ok {
		t.Fatal("session missing")
	}
	pageToken := sess.PageToken

	rr = doJSON(t, srv, http.MethodPost, "/api/login", map[string]any{
		"migration_id": migrationID,
		"page_token":   pageToken,
		"identifier":   "alice",
		"password":     "passw0rd",
	}, false)
	if rr.Code != 200 {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, srv, http.MethodPost, "/api/approve", map[string]any{
		"migration_id": migrationID,
		"page_token":   pageToken,
	}, false)
	if rr.Code != 200 {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	return state, pageToken
}

// An admin-disabled account (manual migration marker) must be rejected at
// login time.
func TestLoginRejectsAdminDisabledUser(t *testing.T) {
	srv, users := newTestServer(t)
	users.byID[42].Status = 2 // admin disabled

	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/start", map[string]any{
		"migration_id":   "mig-d1",
		"target_user_id": 7,
		"redirect_url":   "https://us.example.com/migration",
	}, true)
	if rr.Code != 200 {
		t.Fatalf("start: %d %s", rr.Code, rr.Body.String())
	}
	sess, ok := srv.store.Get("mig-d1")
	if !ok {
		t.Fatal("session missing")
	}
	rr = doJSON(t, srv, http.MethodPost, "/api/login", map[string]any{
		"migration_id": "mig-d1",
		"page_token":   sess.PageToken,
		"identifier":   "alice",
		"password":     "passw0rd",
	}, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("login must be forbidden, got %d %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("account_")) {
		t.Fatalf("expected account error, got %s", rr.Body.String())
	}
}

// If the admin disables the account after login/approve but before the US
// side completes authorization, complete must refuse to issue a grant.
func TestCompleteRejectsAdminDisabledUser(t *testing.T) {
	srv, users := newTestServer(t)
	state, _ := driveToApproved(t, srv, "mig-d2")

	users.byID[42].Status = 2 // admin disabled after approve

	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/complete", map[string]any{
		"migration_id":        "mig-d2",
		"source_user_id":      "pending:mig-d2",
		"authorization_state": state,
	}, true)
	if rr.Code != http.StatusConflict {
		t.Fatalf("complete must conflict, got %d %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("account_disabled")) {
		t.Fatalf("expected account_disabled, got %s", rr.Body.String())
	}
}

// If the admin disables the account after the grant was issued, lock must
// refuse instead of treating the manual disable as a migration lock (which
// would corrupt OriginalStatus and re-enable the account on unlock).
func TestLockRejectsAdminDisabledUser(t *testing.T) {
	srv, users := newTestServer(t)
	state, _ := driveToApproved(t, srv, "mig-d3")

	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/complete", map[string]any{
		"migration_id":        "mig-d3",
		"source_user_id":      "pending:mig-d3",
		"authorization_state": state,
	}, true)
	if rr.Code != 200 {
		t.Fatalf("complete: %d %s", rr.Code, rr.Body.String())
	}

	users.byID[42].Status = 2 // admin disabled after grant

	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id":   "mig-d3",
		"source_user_id": "42",
	}, true)
	if rr.Code != http.StatusConflict {
		t.Fatalf("lock must conflict, got %d %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("account_disabled")) {
		t.Fatalf("expected account_disabled, got %s", rr.Body.String())
	}

	// The manual-disable marker must survive: no session state was mutated to
	// pretend this migration owns the lock.
	sess, ok := srv.store.Get("mig-d3")
	if !ok || sess.Status != sessionGranted {
		t.Fatalf("session must stay granted, got %#v", sess)
	}

	// A re-lock attempt by the same granted session is still refused.
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id":   "mig-d3",
		"source_user_id": "42",
	}, true)
	if rr.Code != http.StatusConflict {
		t.Fatalf("re-lock must conflict, got %d", rr.Code)
	}
}

// Re-entering lock on a session this migration itself locked stays idempotent.
func TestLockIdempotentAfterOwnLock(t *testing.T) {
	srv, _ := newTestServer(t)
	state, _ := driveToApproved(t, srv, "mig-d4")

	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/complete", map[string]any{
		"migration_id":        "mig-d4",
		"source_user_id":      "pending:mig-d4",
		"authorization_state": state,
	}, true)
	if rr.Code != 200 {
		t.Fatalf("complete: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id":   "mig-d4",
		"source_user_id": "42",
	}, true)
	if rr.Code != 200 {
		t.Fatalf("first lock: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id":   "mig-d4",
		"source_user_id": "42",
	}, true)
	if rr.Code != 200 {
		t.Fatalf("second lock: %d %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("already_locked")) {
		t.Fatalf("expected already_locked, got %s", rr.Body.String())
	}
}

func TestLockIdempotentRejectsSourceUpdatedAfterLock(t *testing.T) {
	srv, users := newTestServer(t)
	state, _ := driveToApproved(t, srv, "mig-d5")
	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/complete", map[string]any{
		"migration_id":        "mig-d5",
		"source_user_id":      "pending:mig-d5",
		"authorization_state": state,
	}, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id": "mig-d5", "source_user_id": "42",
	}, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("first lock: %d %s", rr.Code, rr.Body.String())
	}
	sess, _ := srv.store.Get("mig-d5")
	lockedAt := sess.SourceUpdatedAt
	// An administrator re-enabled the account after the migration lock.
	if err := users.UpdateStatus(context.Background(), 42, userStatusEnabled); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id": "mig-d5", "source_user_id": "42",
	}, true)
	if rr.Code != http.StatusConflict || !bytes.Contains(rr.Body.Bytes(), []byte("source_status_changed")) {
		t.Fatalf("repeat lock must reject changed source state, got %d %s", rr.Code, rr.Body.String())
	}
	sess, _ = srv.store.Get("mig-d5")
	if !sess.SourceUpdatedAt.Equal(lockedAt) {
		t.Fatalf("repeat lock must preserve original CAS timestamp, got %s want %s", sess.SourceUpdatedAt, lockedAt)
	}
}

func TestMarkMigratedRejectsSourceChangedAfterLock(t *testing.T) {
	srv, users := newTestServer(t)
	state, _ := driveToApproved(t, srv, "mig-mark-changed")
	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/complete", map[string]any{
		"migration_id": "mig-mark-changed", "source_user_id": "pending:mig-mark-changed", "authorization_state": state,
	}, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id": "mig-mark-changed", "source_user_id": "42",
	}, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("lock: %d %s", rr.Code, rr.Body.String())
	}
	if err := users.UpdateStatus(context.Background(), 42, userStatusEnabled); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/mark-migrated", map[string]any{
		"migration_id": "mig-mark-changed", "source_user_id": "42",
	}, true)
	if rr.Code != http.StatusConflict || !bytes.Contains(rr.Body.Bytes(), []byte("source_status_changed")) {
		t.Fatalf("mark must reject externally changed source status, got %d %s", rr.Code, rr.Body.String())
	}
	sess, _ := srv.store.Get("mig-mark-changed")
	if sess.Status != sessionLocked {
		t.Fatalf("changed source must not be marked done, got %s", sess.Status)
	}
}

func TestJanitorRetriesExpiredLockAfterDatabaseError(t *testing.T) {
	srv, users := newTestServer(t)
	lockedAt, locked, err := users.LockStatus(context.Background(), 42, users.byID[42].UpdatedAt)
	if err != nil || !locked {
		t.Fatalf("lock source: locked=%v err=%v", locked, err)
	}
	sess := &Session{
		MigrationID: "expired-retry", Status: sessionLocked, SourceUserID: 42,
		SourceUpdatedAt: lockedAt, OriginalStatus: userStatusEnabled,
		GrantExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := srv.store.Put(sess); err != nil {
		t.Fatal(err)
	}
	users.restoreErr = errors.New("temporary database failure")
	srv.cleanupExpiredSessions(time.Now())
	if _, ok := srv.store.Get(sess.MigrationID); !ok {
		t.Fatal("janitor must retain the expired session after a database error")
	}
	if users.byID[42].Status != userStatusLocked {
		t.Fatalf("source account should remain locked until restore succeeds, got %d", users.byID[42].Status)
	}

	users.restoreErr = nil
	srv.cleanupExpiredSessions(time.Now())
	if _, ok := srv.store.Get(sess.MigrationID); ok {
		t.Fatal("janitor must delete the session after a successful restore")
	}
	if users.byID[42].Status != userStatusEnabled {
		t.Fatalf("source account should be restored, got %d", users.byID[42].Status)
	}
}

func TestJanitorPreservesExternallyUpdatedLockedAccount(t *testing.T) {
	srv, users := newTestServer(t)
	lockedAt, locked, err := users.LockStatus(context.Background(), 42, users.byID[42].UpdatedAt)
	if err != nil || !locked {
		t.Fatalf("lock source: locked=%v err=%v", locked, err)
	}
	// An admin update leaves the disabled status value unchanged but advances
	// updated_at, so cleanup must not restore the account to enabled.
	if err := users.UpdateStatus(context.Background(), 42, userStatusLocked); err != nil {
		t.Fatal(err)
	}
	sess := &Session{
		MigrationID: "expired-admin-update", Status: sessionLocked, SourceUserID: 42,
		SourceUpdatedAt: lockedAt, OriginalStatus: userStatusEnabled,
		GrantExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := srv.store.Put(sess); err != nil {
		t.Fatal(err)
	}
	srv.cleanupExpiredSessions(time.Now())
	if users.byID[42].Status != userStatusLocked {
		t.Fatalf("janitor must preserve externally updated disabled status, got %d", users.byID[42].Status)
	}
	if _, ok := srv.store.Get(sess.MigrationID); ok {
		t.Fatal("janitor should discard the session after detecting an external update")
	}
}

func TestUnlockAllowsExpiredGrantForRecovery(t *testing.T) {
	srv, users := newTestServer(t)
	state, _ := driveToApproved(t, srv, "mig-expired-unlock")
	rr := doJSON(t, srv, http.MethodPost, "/internal/migration/authorize/complete", map[string]any{
		"migration_id": "mig-expired-unlock", "source_user_id": "pending:mig-expired-unlock", "authorization_state": state,
	}, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/lock", map[string]any{
		"migration_id": "mig-expired-unlock", "source_user_id": "42",
	}, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("lock: %d %s", rr.Code, rr.Body.String())
	}
	_, _, err := srv.store.Update("mig-expired-unlock", func(s *Session) {
		s.GrantExpiresAt = time.Now().Add(-time.Minute)
	})
	if err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, srv, http.MethodPost, "/internal/migration/unlock", map[string]any{
		"migration_id": "mig-expired-unlock", "source_user_id": "42",
	}, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("expired grant must still be recoverable, got %d %s", rr.Code, rr.Body.String())
	}
	if users.byID[42].Status != userStatusEnabled {
		t.Fatalf("source account must be restored after expired-grant recovery, got %d", users.byID[42].Status)
	}
}
