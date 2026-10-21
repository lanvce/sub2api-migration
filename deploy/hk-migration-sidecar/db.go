package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var errUserNotFound = errors.New("user not found")

// UserRecord is the slice of the new-api users table the migration needs.
type UserRecord struct {
	ID        int64
	Username  string
	Email     string
	Password  string // bcrypt hash
	Status    int64
	Quota     int64
	UsedQuota int64
	UpdatedAt time.Time
}

// userStore abstracts new-api user access so handlers can be tested without
// postgres.
type userStore interface {
	FindByLogin(ctx context.Context, identifier string) (*UserRecord, error)
	FindByID(ctx context.Context, id int64) (*UserRecord, error)
	UpdateStatus(ctx context.Context, id, status int64) error
	LockStatus(ctx context.Context, id int64, expectedUpdatedAt time.Time) (time.Time, bool, error)
	MarkMigrated(ctx context.Context, id int64, expectedUpdatedAt time.Time) (time.Time, bool, error)
	RestoreStatus(ctx context.Context, id int64, expectedUpdatedAt time.Time, status int64) (bool, error)
	Ping(ctx context.Context) error
}

type postgresUserStore struct{ db *sql.DB }

func newPostgresUserStore(dsn string) (*postgresUserStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &postgresUserStore{db: db}, nil
}

func (p *postgresUserStore) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.db.PingContext(ctx)
}

const userColumns = "id, COALESCE(username, ''), COALESCE(email, ''), password, COALESCE(status, 1), COALESCE(quota, 0), COALESCE(used_quota, 0), COALESCE(updated_at, 'epoch'::timestamptz)"

func scanUser(row *sql.Row) (*UserRecord, error) {
	u := &UserRecord{}
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Password, &u.Status, &u.Quota, &u.UsedQuota, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (p *postgresUserStore) FindByLogin(ctx context.Context, identifier string) (*UserRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return scanUser(p.db.QueryRowContext(ctx,
		"SELECT "+userColumns+" FROM users WHERE deleted_at IS NULL AND (username = $1 OR email = $1) LIMIT 1",
		identifier))
}

func (p *postgresUserStore) FindByID(ctx context.Context, id int64) (*UserRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return scanUser(p.db.QueryRowContext(ctx,
		"SELECT "+userColumns+" FROM users WHERE deleted_at IS NULL AND id = $1", id))
}

func (p *postgresUserStore) UpdateStatus(ctx context.Context, id, status int64) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := p.db.ExecContext(ctx, "UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1", id, status)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errUserNotFound
	}
	return nil
}

func (p *postgresUserStore) LockStatus(ctx context.Context, id int64, expectedUpdatedAt time.Time) (time.Time, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var lockedAt time.Time
	err := p.db.QueryRowContext(ctx, `UPDATE users SET status = $2, updated_at = NOW()
 WHERE id = $1 AND status = $3 AND updated_at = $4 RETURNING updated_at`,
		id, userStatusLocked, userStatusEnabled, expectedUpdatedAt).Scan(&lockedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	return lockedAt, err == nil, err
}

func (p *postgresUserStore) MarkMigrated(ctx context.Context, id int64, expectedUpdatedAt time.Time) (time.Time, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var markedAt time.Time
	err := p.db.QueryRowContext(ctx, `UPDATE users SET status = $2, updated_at = NOW()
 WHERE id = $1 AND status = $2 AND updated_at = $3 RETURNING updated_at`,
		id, userStatusLocked, expectedUpdatedAt).Scan(&markedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	return markedAt, err == nil, err
}

func (p *postgresUserStore) RestoreStatus(ctx context.Context, id int64, expectedUpdatedAt time.Time, status int64) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := p.db.ExecContext(ctx, `UPDATE users SET status = $3, updated_at = NOW()
 WHERE id = $1 AND status = $2 AND updated_at = $4`, id, userStatusLocked, status, expectedUpdatedAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
