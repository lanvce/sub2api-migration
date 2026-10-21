package handler

import (
	"errors"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// MigrationHandler handles user migration requests. Every endpoint scopes the
// migration to the authenticated user: the target user id always comes from
// the session, never from the request body or URL.
type MigrationHandler struct {
	migrationService *service.MigrationService
}

// NewMigrationHandler creates a new MigrationHandler.
func NewMigrationHandler(migrationService *service.MigrationService) *MigrationHandler {
	return &MigrationHandler{migrationService: migrationService}
}

// Start starts a migration authorization session for the current user.
func (h *MigrationHandler) Start(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	var req service.MigrationStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid migration request")
		return
	}
	req.TargetUserID = subject.UserID
	result, err := h.migrationService.Start(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}
	response.Success(c, result)
}

// Current returns the authenticated user's current (or most recent) migration.
func (h *MigrationHandler) Current(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	migration, err := h.migrationService.Current(c.Request.Context(), subject.UserID)
	if err != nil {
		h.handleError(c, err)
		return
	}
	response.Success(c, migration)
}

// Status returns the current migration status for the current user.
func (h *MigrationHandler) Status(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	migration, err := h.migrationService.Status(c.Request.Context(), c.Param("migration_id"), subject.UserID)
	if err != nil {
		h.handleError(c, err)
		return
	}
	response.Success(c, migration)
}

// Preview returns the migration details before confirmation. When the request
// carries the one-time authorization state returned by the HK redirect, the
// preview also completes the authorization exchange and persists the source
// identity plus a display-only balance snapshot.
func (h *MigrationHandler) Preview(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	preview, err := h.migrationService.Preview(c.Request.Context(), c.Param("migration_id"), subject.UserID, c.Query("authorization_state"))
	if err != nil {
		h.handleError(c, err)
		return
	}
	response.Success(c, preview)
}

// Confirm confirms authorization and completes the migration for the current
// user. On success the response contains the plaintext replacement API key,
// shown exactly once.
func (h *MigrationHandler) Confirm(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	var req service.MigrationConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "invalid migration confirmation request")
		return
	}
	if req.MigrationID == "" {
		req.MigrationID = c.Param("migration_id")
	}
	req.TargetUserID = subject.UserID
	result, err := h.migrationService.Confirm(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}
	response.Success(c, result)
}

func (h *MigrationHandler) handleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrMigrationNotFound):
		response.Error(c, http.StatusNotFound, err.Error())
	case errors.Is(err, service.ErrMigrationInvalid):
		response.BadRequest(c, err.Error())
	case errors.Is(err, service.ErrMigrationConflict):
		response.Error(c, http.StatusConflict, err.Error())
	case errors.Is(err, service.ErrMigrationDisabled):
		response.Error(c, http.StatusForbidden, err.Error())
	default:
		response.ErrorFrom(c, err)
	}
}
