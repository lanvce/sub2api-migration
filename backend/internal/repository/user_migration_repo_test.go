package repository

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

var migrationColumns = []string{
	"id", "migration_id", "source_system", "source_user_id", "target_user_id", "status",
	"source_email", "source_username", "source_group", "password_compatible", "authorization_redirect_url",
	"authorization_expires_at", "source_locked_at", "source_lock_expires_at", "live_balance_read_at",
	"source_quota", "source_used_quota", "source_available_quota", "conversion_factor", "converted_balance",
	"credited_balance", "generated_api_key_id", "failure_code", "failure_message", "completed_at", "created_at", "updated_at",
}

func migrationRow(now time.Time, stringsAs any) *sqlmock.Rows {
	var sourceEmail, sourceUsername, sourceGroup, redirectURL, failureCode, failureMessage any
	if values, ok := stringsAs.([]string); ok {
		sourceEmail = values[0]
		sourceUsername = values[1]
		sourceGroup = values[2]
		redirectURL = values[3]
		failureCode = values[4]
		failureMessage = values[5]
	}
	return sqlmock.NewRows(migrationColumns).AddRow(
		int64(1), "migration-1", "hk-newapi", "pending:migration-1", int64(7), service.MigrationStatusPending,
		sourceEmail, sourceUsername, sourceGroup, false, redirectURL,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		failureCode, failureMessage, nil, now, now,
	)
}

func TestUserMigrationRepositoryCreateScansNullableStrings(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	mock.ExpectQuery("INSERT INTO user_migrations").
		WithArgs("migration-1", "hk-newapi", "pending:migration-1", int64(7), service.MigrationStatusPending).
		WillReturnRows(migrationRow(now, nil))

	got, err := repo.Create(context.Background(), &service.UserMigration{
		MigrationID:  "migration-1",
		SourceSystem: "hk-newapi",
		SourceUserID: "pending:migration-1",
		TargetUserID: 7,
		Status:       service.MigrationStatusPending,
	})

	require.NoError(t, err)
	require.Empty(t, got.SourceEmail)
	require.Empty(t, got.SourceUsername)
	require.Empty(t, got.SourceGroup)
	require.Empty(t, got.AuthorizationRedirectURL)
	require.Empty(t, got.FailureCode)
	require.Empty(t, got.FailureMessage)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserMigrationRepositoryGetByMigrationIDScansStringValues(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	values := []string{"source@example.com", "source-user", "default", "https://hk.example/authorize", "failed", "reason"}

	mock.ExpectQuery("SELECT id, migration_id, source_system").
		WithArgs("migration-1").
		WillReturnRows(migrationRow(now, values))

	got, err := repo.GetByMigrationID(context.Background(), "migration-1")

	require.NoError(t, err)
	require.Equal(t, values[0], got.SourceEmail)
	require.Equal(t, values[1], got.SourceUsername)
	require.Equal(t, values[2], got.SourceGroup)
	require.Equal(t, values[3], got.AuthorizationRedirectURL)
	require.Equal(t, values[4], got.FailureCode)
	require.Equal(t, values[5], got.FailureMessage)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserMigrationRepositoryGetByMigrationIDForUserScansNullableStrings(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	mock.ExpectQuery("SELECT id, migration_id, source_system").
		WithArgs("migration-1", int64(7)).
		WillReturnRows(migrationRow(now, nil))

	got, err := repo.GetByMigrationIDForUser(context.Background(), "migration-1", 7)

	require.NoError(t, err)
	require.Empty(t, got.SourceEmail)
	require.Empty(t, got.AuthorizationRedirectURL)
	require.Empty(t, got.FailureMessage)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserMigrationRepositoryGetActiveByTargetUserID(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	mock.ExpectQuery("WHERE target_user_id = \\$1 AND status IN").
		WithArgs(int64(7)).
		WillReturnRows(migrationRow(now, nil))

	got, err := repo.GetActiveByTargetUserID(context.Background(), 7)

	require.NoError(t, err)
	require.Equal(t, "migration-1", got.MigrationID)
	require.Equal(t, int64(7), got.TargetUserID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserMigrationRepositoryGetLatestByTargetUserID(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	mock.ExpectQuery("WHERE target_user_id = \\$1 ORDER BY updated_at DESC LIMIT 1").
		WithArgs(int64(7)).
		WillReturnRows(migrationRow(now, nil))

	got, err := repo.GetLatestByTargetUserID(context.Background(), 7)

	require.NoError(t, err)
	require.Equal(t, "migration-1", got.MigrationID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserMigrationRepositoryRecoverStaleProcessingUsesCompareAndSet(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	staleBefore := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	mock.ExpectExec("UPDATE user_migrations SET status = \\$2, failure_code = 'processing_timeout'.*WHERE migration_id = \\$1 AND status = 'processing' AND updated_at < \\$3").
		WithArgs("migration-1", service.MigrationStatusFailed, staleBefore).
		WillReturnResult(sqlmock.NewResult(0, 1))

	recovered, err := repo.RecoverStaleProcessing(context.Background(), "migration-1", staleBefore)

	require.NoError(t, err)
	require.True(t, recovered)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserMigrationRepositoryRecoverStaleProcessingReportsCompareAndSetMiss(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	staleBefore := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	mock.ExpectExec("UPDATE user_migrations SET status = \\$2, failure_code = 'processing_timeout'.*WHERE migration_id = \\$1 AND status = 'processing' AND updated_at < \\$3").
		WithArgs("migration-1", service.MigrationStatusFailed, staleBefore).
		WillReturnResult(sqlmock.NewResult(0, 0))

	recovered, err := repo.RecoverStaleProcessing(context.Background(), "migration-1", staleBefore)

	require.NoError(t, err)
	require.False(t, recovered)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUserMigrationRepositoryUpdateAuthorizationClearsFailure(t *testing.T) {
	db, mock := newSQLMock(t)
	repo := &userMigrationRepository{db: db}
	expiresAt := time.Date(2026, 8, 27, 12, 30, 0, 0, time.UTC)
	session := service.HKAuthorizationSession{AuthorizationURL: "https://hk.example/authorize/new", State: "new-state", ExpiresAt: expiresAt}

	mock.ExpectExec("UPDATE user_migrations SET status = \\$2, authorization_redirect_url = \\$3, authorization_state = \\$4, authorization_expires_at = \\$5, failure_code = '', failure_message = ''").
		WithArgs("migration-1", service.MigrationStatusAuthorizing, session.AuthorizationURL, session.State, expiresAt).
		WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, repo.UpdateAuthorization(context.Background(), "migration-1", session))
	require.NoError(t, mock.ExpectationsWereMet())
}
