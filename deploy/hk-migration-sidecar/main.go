package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// new-api user status values (one-api/new-api lineage).
const (
	userStatusEnabled = int64(1)
	userStatusLocked  = int64(2)
)

// Session lifecycle states.
const (
	sessionPending  = "pending"
	sessionLoggedIn = "logged_in"
	sessionApproved = "approved"
	sessionGranted  = "granted"
	sessionLocked   = "locked"
	sessionDone     = "done"
	sessionExpired  = "expired"
)

type config struct {
	ListenAddr    string
	PublicBaseURL string
	SharedSecret  []byte
	DatabaseURL   string
	DataDir       string
	AuthFallback  time.Duration
	GrantTTL      time.Duration
	QuotaPerUnit  int64
}

func loadConfig() (*config, error) {
	c := &config{
		ListenAddr:    envOr("HKM_LISTEN_ADDR", ":8290"),
		PublicBaseURL: strings.TrimRight(strings.TrimSpace(os.Getenv("HKM_PUBLIC_BASE_URL")), "/"),
		DatabaseURL:   strings.TrimSpace(os.Getenv("HKM_DATABASE_URL")),
		DataDir:       envOr("HKM_DATA_DIR", "/data"),
		QuotaPerUnit:  envInt64("HKM_QUOTA_PER_UNIT", 500000),
	}
	secret := strings.TrimSpace(os.Getenv("HKM_SHARED_SECRET"))
	if len(secret) < 16 {
		return nil, fmt.Errorf("HKM_SHARED_SECRET is required and must be at least 16 characters")
	}
	c.SharedSecret = []byte(secret)
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("HKM_DATABASE_URL is required")
	}
	if !strings.HasPrefix(c.PublicBaseURL, "http://") && !strings.HasPrefix(c.PublicBaseURL, "https://") {
		return nil, fmt.Errorf("HKM_PUBLIC_BASE_URL must be an absolute http(s) URL")
	}
	if !strings.HasPrefix(c.PublicBaseURL, "https://") {
		log.Printf("WARNING: HKM_PUBLIC_BASE_URL is not https; the authorize page will be served over plaintext")
	}
	var err error
	if c.AuthFallback, err = parseDurationEnv("HKM_AUTH_TTL", 10*time.Minute); err != nil {
		return nil, err
	}
	if c.GrantTTL, err = parseDurationEnv("HKM_GRANT_TTL", 2*time.Hour); err != nil {
		return nil, err
	}
	if c.GrantTTL <= 0 {
		return nil, fmt.Errorf("HKM_GRANT_TTL must be positive")
	}
	if c.QuotaPerUnit <= 0 {
		return nil, fmt.Errorf("HKM_QUOTA_PER_UNIT must be positive (new-api default is 500000)")
	}
	return c, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	users, err := newPostgresUserStore(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	store, err := newSessionStore(cfg.DataDir + "/sessions.json")
	if err != nil {
		log.Fatalf("session store: %v", err)
	}

	srv := &server{
		cfg:   cfg,
		users: users,
		store: store,
		ips:   newIPLimiter(10, 10*time.Minute),
	}

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

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go srv.janitor()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-done
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	log.Printf("hk-migration-sidecar listening on %s (public=%s quota_per_unit=%d grant_ttl=%s)",
		cfg.ListenAddr, cfg.PublicBaseURL, cfg.QuotaPerUnit, cfg.GrantTTL)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
		log.Fatalf("invalid integer for %s: %q", key, v)
	}
	return def
}

func parseDurationEnv(key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s: %w", key, err)
	}
	return d, nil
}
