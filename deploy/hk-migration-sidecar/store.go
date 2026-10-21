package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Session is one migration authorization. It is created when the US site
// calls authorize/start, bound to a source user when the account owner logs
// in on the authorize page, and consumed by the confirm flow
// (complete -> lock -> balance -> mark-migrated).
type Session struct {
	MigrationID     string    `json:"migration_id"`
	TargetUserID    int64     `json:"target_user_id"`
	RedirectURL     string    `json:"redirect_url"`
	State           string    `json:"state"`
	PageToken       string    `json:"page_token,omitempty"`
	Status          string    `json:"status"`
	SourceUserID    int64     `json:"source_user_id,omitempty"`
	SourceUsername  string    `json:"source_username,omitempty"`
	SourceEmail     string    `json:"source_email,omitempty"`
	OriginalStatus  int64     `json:"original_status,omitempty"`
	SourceQuota     int64     `json:"source_quota,omitempty"`
	SourceUsedQuota int64     `json:"source_used_quota,omitempty"`
	SourceUpdatedAt time.Time `json:"source_updated_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	AuthExpiresAt   time.Time `json:"auth_expires_at"`
	GrantExpiresAt  time.Time `json:"grant_expires_at,omitempty"`
	ApprovedAt      time.Time `json:"approved_at,omitempty"`
	LockedAt        time.Time `json:"locked_at,omitempty"`
	LoginAttempts   int       `json:"login_attempts"`
}

// sessionAlive reports whether the session can still make progress.
func sessionAlive(s *Session, now time.Time) bool {
	switch s.Status {
	case sessionPending, sessionLoggedIn:
		return now.Before(s.AuthExpiresAt)
	case sessionApproved, sessionGranted, sessionLocked:
		return s.GrantExpiresAt.IsZero() || now.Before(s.GrantExpiresAt)
	default:
		return false
	}
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	path     string
}

func newSessionStore(path string) (*sessionStore, error) {
	s := &sessionStore{sessions: map[string]*Session{}, path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return s, nil
	}
	var loaded map[string]*Session
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("session store %s is corrupt (%v); starting empty", path, err)
		_ = os.Rename(path, path+".corrupt")
		return s, nil
	}
	s.sessions = loaded
	return s, nil
}

func (s *sessionStore) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	return *sess, true
}

func (s *sessionStore) Put(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.sessions[sess.MigrationID] = &cp
	return s.persistLocked()
}

func (s *sessionStore) Update(id string, fn func(*Session)) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false, nil
	}
	fn(sess)
	cp := *sess
	return cp, true, s.persistLocked()
}

func (s *sessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return s.persistLocked()
}

// Snapshot returns copies of all sessions (used by the janitor and the
// cross-migration binding scan).
func (s *sessionStore) Snapshot() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, *sess)
	}
	return out
}

func (s *sessionStore) persistLocked() error {
	data, err := json.MarshalIndent(s.sessions, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ipLimiter is a fixed-window limiter for the public login endpoint.
type ipLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	l := &ipLimiter{hits: map[string][]time.Time{}, max: max, window: window}
	go func() {
		for range time.Tick(window) {
			l.mu.Lock()
			cutoff := time.Now().Add(-window)
			for ip, ts := range l.hits {
				kept := ts[:0]
				for _, t := range ts {
					if t.After(cutoff) {
						kept = append(kept, t)
					}
				}
				if len(kept) == 0 {
					delete(l.hits, ip)
				} else {
					l.hits[ip] = kept
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

func (l *ipLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	kept := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[ip] = kept
		return false
	}
	l.hits[ip] = append(kept, now)
	return true
}

// clientIP prefers X-Forwarded-For (Caddy/Cloudflare) and falls back to
// RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			if ip := strings.TrimSpace(part); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
