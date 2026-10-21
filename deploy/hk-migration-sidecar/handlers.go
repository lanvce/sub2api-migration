package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type server struct {
	cfg   *config
	users userStore
	store *sessionStore
	ips   *ipLimiter
}

func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(ww, r)
		log.Printf("%s %s %d %s ip=%s", r.Method, r.URL.Path, ww.code, time.Since(start).Truncate(time.Millisecond), clientIP(r))
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *server) janitor() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		s.cleanupExpiredSessions(time.Now())
	}
}

// cleanupExpiredSessions releases abandoned locks. A database error keeps the
// session so a later janitor pass can retry; a successful CAS miss means an
// external status update won the race and the session can be discarded.
func (s *server) cleanupExpiredSessions(now time.Time) {
	for _, sess := range s.store.Snapshot() {
		if sessionAlive(&sess, now) {
			continue
		}
		if sess.Status == sessionLocked && sess.SourceUserID > 0 {
			restored, err := s.users.RestoreStatus(context.Background(), sess.SourceUserID, sess.SourceUpdatedAt, sess.OriginalStatus)
			if err != nil {
				if errors.Is(err, errUserNotFound) {
					log.Printf("janitor: source user missing source_user=%d migration=%s", sess.SourceUserID, sess.MigrationID)
					_ = s.store.Delete(sess.MigrationID)
					continue
				}
				log.Printf("janitor: unlock failed source_user=%d migration=%s error=%v", sess.SourceUserID, sess.MigrationID, err)
				continue
			}
			if restored {
				log.Printf("janitor: unlocked source_user=%d migration=%s", sess.SourceUserID, sess.MigrationID)
			} else {
				log.Printf("janitor: preserving externally updated source_user=%d migration=%s", sess.SourceUserID, sess.MigrationID)
			}
		}
		_ = s.store.Delete(sess.MigrationID)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.users.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "db_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// HMAC gate for /internal/*
// Signature payload matches the US client: method + "\n" + path (incl. query).
// ---------------------------------------------------------------------------

func (s *server) requireInternal(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sig := strings.TrimSpace(r.Header.Get("X-Migration-Signature"))
		if sig == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_signature"})
			return
		}
		payload := r.Method + "\n" + r.URL.RequestURI()
		mac := hmac.New(sha256.New, s.cfg.SharedSecret)
		_, _ = mac.Write([]byte(payload))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_signature"})
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Internal: authorize/start
// ---------------------------------------------------------------------------

type startRequest struct {
	MigrationID  string    `json:"migration_id"`
	TargetUserID int64     `json:"target_user_id"`
	RedirectURL  string    `json:"redirect_url"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (s *server) handleInternalStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req startRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	req.MigrationID = strings.TrimSpace(req.MigrationID)
	req.RedirectURL = strings.TrimSpace(req.RedirectURL)
	if req.MigrationID == "" || req.TargetUserID <= 0 || req.RedirectURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !strings.HasPrefix(req.RedirectURL, "https://") && !strings.HasPrefix(req.RedirectURL, "http://") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_url"})
		return
	}

	now := time.Now().UTC()
	expires := req.ExpiresAt.UTC()
	if expires.IsZero() || expires.Before(now) {
		expires = now.Add(s.cfg.AuthFallback)
	}
	// Cap auth window so a long US TTL cannot leave an open login forever.
	if expires.After(now.Add(s.cfg.AuthFallback)) {
		expires = now.Add(s.cfg.AuthFallback)
	}

	state, err := randomToken(24)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token_failed"})
		return
	}
	pageToken, err := randomToken(24)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token_failed"})
		return
	}

	sess := &Session{
		MigrationID:   req.MigrationID,
		TargetUserID:  req.TargetUserID,
		RedirectURL:   req.RedirectURL,
		State:         state,
		PageToken:     pageToken,
		Status:        sessionPending,
		CreatedAt:     now,
		AuthExpiresAt: expires,
	}
	if err := s.store.Put(sess); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_failed"})
		return
	}

	authURL := fmt.Sprintf("%s/authorize?migration_id=%s&page_token=%s",
		s.cfg.PublicBaseURL, urlQueryEscape(req.MigrationID), urlQueryEscape(pageToken))
	writeJSON(w, http.StatusOK, map[string]any{
		"authorization_url": authURL,
		"state":             state,
		"expires_at":        expires,
	})
}

// ---------------------------------------------------------------------------
// Internal: authorize/complete
// ---------------------------------------------------------------------------

type completeRequest struct {
	MigrationID        string `json:"migration_id"`
	SourceUserID       string `json:"source_user_id"`
	AuthorizationState string `json:"authorization_state"`
}

func (s *server) handleInternalComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req completeRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	req.MigrationID = strings.TrimSpace(req.MigrationID)
	req.AuthorizationState = strings.TrimSpace(req.AuthorizationState)

	sess, ok := s.store.Get(req.MigrationID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session_not_found"})
		return
	}
	now := time.Now().UTC()
	if !sessionAlive(&sess, now) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "session_expired"})
		return
	}
	if sess.Status != sessionApproved && sess.Status != sessionGranted && sess.Status != sessionLocked {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not_approved", "status": sess.Status})
		return
	}
	if subtle.ConstantTimeCompare([]byte(sess.State), []byte(req.AuthorizationState)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_state"})
		return
	}
	if sess.SourceUserID <= 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_unbound"})
		return
	}

	// Optional consistency check: US may still hold the placeholder pending:ID.
	if sid := strings.TrimSpace(req.SourceUserID); sid != "" &&
		!strings.HasPrefix(sid, "pending:") &&
		sid != strconv.FormatInt(sess.SourceUserID, 10) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_mismatch"})
		return
	}

	// An admin disabling the source account means the user was migrated
	// manually; never hand out a grant for a disabled account.
	u, err := s.users.FindByID(r.Context(), sess.SourceUserID)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if u.Status != userStatusEnabled {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account_disabled"})
		return
	}

	grantToken, err := randomToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token_failed"})
		return
	}
	grantExpires := now.Add(s.cfg.GrantTTL)
	updated, ok, err := s.store.Update(req.MigrationID, func(ss *Session) {
		ss.Status = sessionGranted
		ss.PageToken = grantToken // reuse field to hold grant token after approval
		ss.GrantExpiresAt = grantExpires
	})
	if err != nil || !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_failed"})
		return
	}
	_ = updated

	// HKGrant.Token is json:"-" on the US side; we put it into a custom header
	// AND also return it under "token" so a future US client can pick it up.
	// Current US client does not decode Token from JSON, so grant identity is
	// verified by migration_id + source_user_id match on subsequent calls.
	w.Header().Set("X-Migration-Grant-Token", grantToken)
	writeJSON(w, http.StatusOK, map[string]any{
		"migration_id":   req.MigrationID,
		"source_user_id": strconv.FormatInt(sess.SourceUserID, 10),
		"username":       strings.TrimSpace(sess.SourceUsername),
		"email":          strings.TrimSpace(sess.SourceEmail),
		"token":          grantToken,
		"expires_at":     grantExpires,
	})
}

// ---------------------------------------------------------------------------
// Internal: lock / unlock / balance / mark-migrated
// ---------------------------------------------------------------------------

type grantBody struct {
	MigrationID  string `json:"migration_id"`
	SourceUserID string `json:"source_user_id"`
	Token        string `json:"token"`
	// ExpiresAt is accepted for forward/backward compatibility with the US
	// HKGrant payload. The sidecar session already tracks grant expiry.
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *server) loadGrantedSession(w http.ResponseWriter, r *http.Request, body *grantBody) (*Session, bool) {
	return s.loadGrantedSessionWithExpiry(w, r, body, false)
}

func (s *server) loadGrantedSessionWithExpiry(w http.ResponseWriter, r *http.Request, body *grantBody, allowExpired bool) (*Session, bool) {
	if body.MigrationID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return nil, false
	}
	sess, ok := s.store.Get(body.MigrationID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session_not_found"})
		return nil, false
	}
	switch sess.Status {
	case sessionGranted, sessionLocked, sessionDone, sessionApproved:
		// ok
	default:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not_granted", "status": sess.Status})
		return nil, false
	}
	// Migrated sessions stay loadable so unlock can return already_migrated.
	if sess.Status != sessionDone && !allowExpired && !sessionAlive(&sess, time.Now().UTC()) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "session_expired"})
		return nil, false
	}
	if sess.SourceUserID <= 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_unbound"})
		return nil, false
	}
	if sid := strings.TrimSpace(body.SourceUserID); sid != "" && sid != strconv.FormatInt(sess.SourceUserID, 10) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_mismatch"})
		return nil, false
	}
	// Soft token check: if US client ever starts sending Token, verify it.
	if tok := strings.TrimSpace(body.Token); tok != "" && sess.PageToken != "" {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.PageToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_grant_token"})
			return nil, false
		}
	}
	return &sess, true
}

func (s *server) handleInternalLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var body grantBody
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	sess, ok := s.loadGrantedSession(w, r, &body)
	if !ok {
		return
	}
	if sess.Status == sessionDone {
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_locked"})
		return
	}
	if sess.Status == sessionLocked {
		u, err := s.users.FindByID(r.Context(), sess.SourceUserID)
		if err != nil {
			if errors.Is(err, errUserNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		if u.Status != userStatusLocked || !u.UpdatedAt.Equal(sess.SourceUpdatedAt) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "source_status_changed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "already_locked"})
		return
	}

	u, err := s.users.FindByID(r.Context(), sess.SourceUserID)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if u.Status == userStatusLocked {
		// Status 2 represents both a migration lock and an admin disable. Only
		// an existing session that passed the timestamp check above owns it.
		for _, other := range s.store.Snapshot() {
			if other.MigrationID != sess.MigrationID && other.SourceUserID == sess.SourceUserID &&
				other.Status == sessionLocked && sessionAlive(&other, time.Now().UTC()) {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "source_already_migrating"})
				return
			}
		}
		// Admin disabled the account after login: manual migration marker.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account_disabled"})
		return
	}
	if u.Status != userStatusEnabled {
		// Any other non-enabled status is an admin disable (manual migration).
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account_disabled"})
		return
	}

	orig := u.Status
	lockedAt, locked, err := s.users.LockStatus(r.Context(), sess.SourceUserID, u.UpdatedAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lock_failed"})
		return
	}
	if !locked {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account_status_changed"})
		return
	}
	_, _, _ = s.store.Update(sess.MigrationID, func(ss *Session) {
		ss.Status = sessionLocked
		ss.OriginalStatus = orig
		ss.SourceQuota = u.Quota
		ss.SourceUsedQuota = u.UsedQuota
		ss.SourceUpdatedAt = lockedAt
		ss.LockedAt = time.Now().UTC()
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "locked"})
}

func (s *server) handleInternalUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var body grantBody
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	sess, ok := s.loadGrantedSessionWithExpiry(w, r, &body, true)
	if !ok {
		return
	}
	if sess.Status == sessionDone {
		// Migrated accounts stay locked permanently.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_migrated"})
		return
	}
	restore := sess.OriginalStatus
	if restore == 0 {
		restore = userStatusEnabled
	}
	restored, err := s.users.RestoreStatus(r.Context(), sess.SourceUserID, sess.SourceUpdatedAt, restore)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unlock_failed"})
		return
	}
	if !restored {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_status_changed"})
		return
	}
	_, _, _ = s.store.Update(sess.MigrationID, func(ss *Session) {
		ss.Status = sessionGranted
		ss.LockedAt = time.Time{}
		ss.SourceUpdatedAt = time.Time{}
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

func (s *server) handleInternalBalance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	body := grantBody{
		MigrationID:  strings.TrimSpace(r.URL.Query().Get("migration_id")),
		SourceUserID: strings.TrimSpace(r.URL.Query().Get("source_user_id")),
	}
	sess, ok := s.loadGrantedSession(w, r, &body)
	if !ok {
		return
	}
	u, err := s.users.FindByID(r.Context(), sess.SourceUserID)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	// users.quota is already the remaining quota in new-api; used_quota is the
	// lifetime spend. available_quota makes that contract explicit for the US
	// side so it never subtracts used_quota again.
	available := u.Quota
	if available < 0 {
		available = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"quota":           u.Quota,
		"used_quota":      u.UsedQuota,
		"available_quota": available,
		"quota_per_unit":  s.cfg.QuotaPerUnit,
		"read_at":         time.Now().UTC(),
	})
}

func (s *server) handleInternalMarkMigrated(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var body grantBody
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	sess, ok := s.loadGrantedSession(w, r, &body)
	if !ok {
		return
	}
	if sess.Status == sessionDone {
		writeJSON(w, http.StatusOK, map[string]string{"status": "migrated"})
		return
	}
	if sess.Status != sessionLocked {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_not_locked"})
		return
	}
	markedAt, marked, err := s.users.MarkMigrated(r.Context(), sess.SourceUserID, sess.SourceUpdatedAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "mark_failed"})
		return
	}
	if !marked {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_status_changed"})
		return
	}
	_, _, err = s.store.Update(sess.MigrationID, func(ss *Session) {
		ss.Status = sessionDone
		ss.SourceUpdatedAt = markedAt
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "migrated"})
}

// ---------------------------------------------------------------------------
// Public authorize page + login/approve APIs
// ---------------------------------------------------------------------------

func (s *server) handleAuthorizePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'")
	_, _ = io.WriteString(w, authorizeHTML)
}

func (s *server) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	migrationID := strings.TrimSpace(r.URL.Query().Get("migration_id"))
	pageToken := strings.TrimSpace(r.URL.Query().Get("page_token"))
	sess, ok := s.store.Get(migrationID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session_not_found"})
		return
	}
	// After complete(), PageToken is overwritten with the grant token; the
	// authorize page should treat that session as gone.
	if sess.Status == sessionGranted || sess.Status == sessionLocked || sess.Status == sessionDone {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session_not_found"})
		return
	}
	if pageToken == "" || subtle.ConstantTimeCompare([]byte(sess.PageToken), []byte(pageToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_page_token"})
		return
	}
	if !sessionAlive(&sess, time.Now()) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "session_expired"})
		return
	}
	// Full identity is safe here: the response is scoped to a valid random
	// page_token held only by this authorization session in the user's browser.
	writeJSON(w, http.StatusOK, map[string]any{
		"migration_id": sess.MigrationID,
		"status":       sess.Status,
		"expires_at":   sess.AuthExpiresAt,
		"username":     strings.TrimSpace(sess.SourceUsername),
		"email":        strings.TrimSpace(sess.SourceEmail),
	})
}

type loginRequest struct {
	MigrationID string `json:"migration_id"`
	PageToken   string `json:"page_token"`
	Identifier  string `json:"identifier"`
	Password    string `json:"password"`
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	ip := clientIP(r)
	if !s.ips.Allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	req.MigrationID = strings.TrimSpace(req.MigrationID)
	req.PageToken = strings.TrimSpace(req.PageToken)
	req.Identifier = strings.TrimSpace(req.Identifier)

	sess, ok := s.store.Get(req.MigrationID)
	if !ok || subtle.ConstantTimeCompare([]byte(sess.PageToken), []byte(req.PageToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_page_token"})
		return
	}
	if !sessionAlive(&sess, time.Now()) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "session_expired"})
		return
	}
	if sess.Status != sessionPending && sess.Status != sessionLoggedIn {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already_bound", "status": sess.Status})
		return
	}
	if sess.LoginAttempts >= 8 {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_attempts"})
		return
	}
	_, _, _ = s.store.Update(req.MigrationID, func(ss *Session) { ss.LoginAttempts++ })

	if req.Identifier == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_credentials"})
		return
	}
	u, err := s.users.FindByLogin(r.Context(), req.Identifier)
	if err != nil {
		// Uniform error to avoid user enumeration.
		time.Sleep(200 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(req.Password)); err != nil {
		time.Sleep(200 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if u.Status == userStatusLocked {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account_locked"})
		return
	}
	if u.Status != userStatusEnabled {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account_disabled"})
		return
	}

	// Reject if this source user is already bound to another live migration.
	for _, other := range s.store.Snapshot() {
		if other.MigrationID == req.MigrationID {
			continue
		}
		if other.SourceUserID == u.ID && sessionAlive(&other, time.Now()) &&
			(other.Status == sessionApproved || other.Status == sessionGranted || other.Status == sessionLocked || other.Status == sessionDone) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "source_already_migrating"})
			return
		}
	}

	updated, _, err := s.store.Update(req.MigrationID, func(ss *Session) {
		ss.Status = sessionLoggedIn
		ss.SourceUserID = u.ID
		ss.SourceUsername = u.Username
		ss.SourceEmail = u.Email
		ss.OriginalStatus = u.Status
		ss.SourceQuota = u.Quota
		ss.SourceUsedQuota = u.UsedQuota
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_failed"})
		return
	}
	// Full identity: the caller proved knowledge of the random page_token for
	// this in-flight authorization session (see comment in handleSessionInfo).
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   updated.Status,
		"username": strings.TrimSpace(updated.SourceUsername),
		"email":    strings.TrimSpace(updated.SourceEmail),
	})
}

type approveRequest struct {
	MigrationID string `json:"migration_id"`
	PageToken   string `json:"page_token"`
}

func (s *server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req approveRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	req.MigrationID = strings.TrimSpace(req.MigrationID)
	req.PageToken = strings.TrimSpace(req.PageToken)

	sess, ok := s.store.Get(req.MigrationID)
	if !ok || subtle.ConstantTimeCompare([]byte(sess.PageToken), []byte(req.PageToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_page_token"})
		return
	}
	if !sessionAlive(&sess, time.Now()) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "session_expired"})
		return
	}
	if sess.Status != sessionLoggedIn {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not_logged_in", "status": sess.Status})
		return
	}
	if sess.SourceUserID <= 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "source_unbound"})
		return
	}

	now := time.Now().UTC()
	grantExpires := now.Add(s.cfg.GrantTTL)
	updated, _, err := s.store.Update(req.MigrationID, func(ss *Session) {
		ss.Status = sessionApproved
		ss.ApprovedAt = now
		ss.GrantExpiresAt = grantExpires
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_failed"})
		return
	}

	redirect := updated.RedirectURL
	sep := "?"
	if strings.Contains(redirect, "?") {
		sep = "&"
	}
	redirect = redirect + sep + "migration_id=" + urlQueryEscape(updated.MigrationID) +
		"&state=" + urlQueryEscape(updated.State)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       updated.Status,
		"redirect_url": redirect,
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func randomToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func urlQueryEscape(s string) string {
	// Minimal escape for query values (tokens are hex / UUIDs).
	replacer := strings.NewReplacer(
		" ", "%20",
		"&", "%26",
		"=", "%3D",
		"?", "%3F",
		"#", "%23",
		"+", "%2B",
	)
	return replacer.Replace(s)
}

func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return ""
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return local[:1] + "***" + domain
	}
	return local[:1] + "***" + local[len(local)-1:] + domain
}

func maskName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	r := []rune(name)
	if len(r) <= 2 {
		return string(r[:1]) + "***"
	}
	return string(r[:1]) + "***" + string(r[len(r)-1:])
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
