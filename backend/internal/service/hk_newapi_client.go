package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
)

// HKNewAPIClient is the narrow contract required by the US migration flow.
// Implementations must never return a source API key in plaintext.
type HKNewAPIClient interface {
	StartAuthorization(context.Context, HKStartAuthorizationRequest) (HKAuthorizationSession, error)
	CompleteAuthorization(context.Context, HKCompleteAuthorizationRequest) (HKGrant, error)
	LockAccount(context.Context, HKGrant) error
	UnlockAccount(context.Context, HKGrant) error
	ReadLiveBalance(context.Context, HKGrant) (HKBalanceSnapshot, error)
	MarkMigrated(context.Context, HKGrant, string) error
}

type HKStartAuthorizationRequest struct {
	MigrationID  string    `json:"migration_id"`
	TargetUserID int64     `json:"target_user_id"`
	RedirectURL  string    `json:"redirect_url"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type HKCompleteAuthorizationRequest struct {
	MigrationID        string `json:"migration_id"`
	SourceUserID       string `json:"source_user_id"`
	AuthorizationState string `json:"authorization_state"`
}

type HKAuthorizationSession struct {
	AuthorizationURL string    `json:"authorization_url"`
	State            string    `json:"state"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type HKGrant struct {
	MigrationID    string    `json:"migration_id"`
	SourceUserID   string    `json:"source_user_id"`
	SourceUsername string    `json:"username"`
	SourceEmail    string    `json:"email"`
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type HKBalanceSnapshot struct {
	Quota          int64     `json:"quota"`
	UsedQuota      int64     `json:"used_quota"`
	AvailableQuota int64     `json:"available_quota"`
	QuotaPerUnit   int64     `json:"quota_per_unit"`
	ReadAt         time.Time `json:"read_at"`
}

type hkNewAPIClient struct {
	baseURL string
	secret  []byte
	client  *http.Client
}

// NewHKNewAPIClient constructs the optional sidecar client. The sidecar URL and
// secret are configuration-only values; no source-machine credentials are used.
func NewHKNewAPIClient(cfg *config.Config) (HKNewAPIClient, error) {
	if cfg == nil || !cfg.Migration.Enabled {
		return &disabledHKNewAPIClient{}, nil
	}
	client, err := httpclient.GetClient(httpclient.Options{Timeout: 15 * time.Second, ResponseHeaderTimeout: 10 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("create migration http client: %w", err)
	}
	return &hkNewAPIClient{baseURL: strings.TrimRight(cfg.Migration.HKBaseURL, "/"), secret: []byte(cfg.Migration.SharedSecret), client: client}, nil
}

func (c *hkNewAPIClient) StartAuthorization(ctx context.Context, req HKStartAuthorizationRequest) (HKAuthorizationSession, error) {
	var out HKAuthorizationSession
	return out, c.do(ctx, http.MethodPost, "/internal/migration/authorize/start", req, &out)
}
func (c *hkNewAPIClient) CompleteAuthorization(ctx context.Context, req HKCompleteAuthorizationRequest) (HKGrant, error) {
	var out HKGrant
	return out, c.do(ctx, http.MethodPost, "/internal/migration/authorize/complete", req, &out)
}
func (c *hkNewAPIClient) LockAccount(ctx context.Context, grant HKGrant) error {
	return c.do(ctx, http.MethodPost, "/internal/migration/lock", grant, nil)
}
func (c *hkNewAPIClient) UnlockAccount(ctx context.Context, grant HKGrant) error {
	return c.do(ctx, http.MethodPost, "/internal/migration/unlock", grant, nil)
}
func (c *hkNewAPIClient) ReadLiveBalance(ctx context.Context, grant HKGrant) (HKBalanceSnapshot, error) {
	var out HKBalanceSnapshot
	return out, c.do(ctx, http.MethodGet, "/internal/migration/balance?migration_id="+grant.MigrationID+"&source_user_id="+grant.SourceUserID, nil, &out)
}
func (c *hkNewAPIClient) MarkMigrated(ctx context.Context, grant HKGrant, migrationID string) error {
	return c.do(ctx, http.MethodPost, "/internal/migration/mark-migrated", map[string]string{"migration_id": migrationID, "source_user_id": grant.SourceUserID}, nil)
}

func (c *hkNewAPIClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	requestID, _ := ctx.Value(ctxkey.RequestID).(string)
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	payload := method + "\n" + path
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write([]byte(payload))
	req.Header.Set("X-Migration-Signature", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("migration sidecar request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("migration sidecar returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode migration sidecar response: %w", err)
	}
	return nil
}

type disabledHKNewAPIClient struct{}

func (d *disabledHKNewAPIClient) StartAuthorization(context.Context, HKStartAuthorizationRequest) (HKAuthorizationSession, error) {
	return HKAuthorizationSession{}, ErrMigrationDisabled
}
func (d *disabledHKNewAPIClient) CompleteAuthorization(context.Context, HKCompleteAuthorizationRequest) (HKGrant, error) {
	return HKGrant{}, ErrMigrationDisabled
}
func (d *disabledHKNewAPIClient) LockAccount(context.Context, HKGrant) error {
	return ErrMigrationDisabled
}
func (d *disabledHKNewAPIClient) UnlockAccount(context.Context, HKGrant) error { return nil }
func (d *disabledHKNewAPIClient) ReadLiveBalance(context.Context, HKGrant) (HKBalanceSnapshot, error) {
	return HKBalanceSnapshot{}, ErrMigrationDisabled
}
func (d *disabledHKNewAPIClient) MarkMigrated(context.Context, HKGrant, string) error {
	return ErrMigrationDisabled
}

// FakeHKNewAPIClient is intended for unit tests and local test-user verification.
type FakeHKNewAPIClient struct {
	Grant   HKGrant
	Balance HKBalanceSnapshot
	Locked  bool
	Marked  []string
}

func (f *FakeHKNewAPIClient) StartAuthorization(context.Context, HKStartAuthorizationRequest) (HKAuthorizationSession, error) {
	return HKAuthorizationSession{AuthorizationURL: "https://hk.test/authorize", State: "test-state", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (f *FakeHKNewAPIClient) CompleteAuthorization(context.Context, HKCompleteAuthorizationRequest) (HKGrant, error) {
	return f.Grant, nil
}
func (f *FakeHKNewAPIClient) LockAccount(context.Context, HKGrant) error { f.Locked = true; return nil }
func (f *FakeHKNewAPIClient) UnlockAccount(context.Context, HKGrant) error {
	f.Locked = false
	return nil
}
func (f *FakeHKNewAPIClient) ReadLiveBalance(context.Context, HKGrant) (HKBalanceSnapshot, error) {
	f.Balance.ReadAt = time.Now()
	return f.Balance, nil
}
func (f *FakeHKNewAPIClient) MarkMigrated(_ context.Context, _ HKGrant, id string) error {
	f.Marked = append(f.Marked, id)
	return nil
}
