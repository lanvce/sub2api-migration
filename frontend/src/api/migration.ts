/**
 * User migration API endpoints
 * Handles migration of balance from the HK NewAPI site to this system.
 * All endpoints are scoped to the authenticated user on the backend.
 */

import { apiClient } from './client'

export interface UserMigration {
  id: number
  migration_id: string
  source_system: string
  source_user_id: string
  target_user_id: number
  status: MigrationStatus
  source_email?: string
  source_username?: string
  source_group?: string
  password_compatible: boolean
  authorization_redirect_url?: string
  authorization_expires_at?: string
  source_locked_at?: string
  source_lock_expires_at?: string
  live_balance_read_at?: string
  source_quota?: number
  source_used_quota?: number
  source_available_quota?: number
  conversion_factor?: number
  converted_balance?: number
  credited_balance?: number
  generated_api_key_id?: number
  failure_code?: string
  failure_message?: string
  completed_at?: string
  created_at: string
  updated_at: string
}

export type MigrationStatus =
  | 'pending'
  | 'authorizing'
  | 'authorized'
  | 'locked'
  | 'processing'
  | 'completed'
  | 'failed'
  | 'manual_review'

export interface HKAuthorizationSession {
  authorization_url: string
  state: string
  expires_at: string
}

export interface MigrationStartResponse {
  migration: UserMigration
  session: HKAuthorizationSession
}

export interface MigrationPreview {
  migration: UserMigration
  can_confirm: boolean
  warnings?: string[]
}

export interface MigrationConfirmResult {
  migration: UserMigration
  /** Plaintext replacement API key, present only right after a successful confirm (shown exactly once). */
  api_key?: string
}

/**
 * Start or resume a migration authorization session.
 * The backend may restore an existing active migration for this user and return
 * a different migration_id plus a freshly issued HK authorization session.
 * @param migrationId - Preferred migration id; reused when the user already has an active row
 * @param sourceSystem - Source system identifier, e.g. "hk-newapi"
 * @param redirectUrl - URL the HK site redirects back to after authorization
 */
export async function startMigration(
  migrationId: string,
  sourceSystem: string,
  redirectUrl: string
): Promise<MigrationStartResponse> {
  const { data } = await apiClient.post<MigrationStartResponse>('/migration', {
    migration_id: migrationId,
    source_system: sourceSystem,
    redirect_url: redirectUrl
  })
  return data
}

/**
 * Get the current status of a migration.
 */
export async function getMigrationStatus(migrationId: string): Promise<UserMigration> {
  const { data } = await apiClient.get<UserMigration>(
    `/migration/${encodeURIComponent(migrationId)}`
  )
  return data
}

/**
 * Get the migration preview (source account details, converted balance, warnings).
 * When the one-time authorization state from the HK redirect is supplied, the
 * backend completes the authorization exchange first, so the preview carries
 * the full source identity and a display-only balance snapshot.
 */
export async function getMigrationPreview(
  migrationId: string,
  authorizationState?: string
): Promise<MigrationPreview> {
  const query =
    authorizationState && authorizationState.trim() !== ''
      ? `?authorization_state=${encodeURIComponent(authorizationState.trim())}`
      : ''
  const { data } = await apiClient.get<MigrationPreview>(
    `/migration/${encodeURIComponent(migrationId)}/preview${query}`
  )
  return data
}

/**
 * Confirm the migration. On success the response may contain the plaintext
 * replacement API key, shown exactly once.
 */
export async function confirmMigration(
  migrationId: string,
  authorizationState: string
): Promise<MigrationConfirmResult> {
  const { data } = await apiClient.post<MigrationConfirmResult>(
    `/migration/${encodeURIComponent(migrationId)}/confirm`,
    {
      migration_id: migrationId,
      authorization_state: authorizationState
    }
  )
  return data
}

/**
 * Get the authenticated user's current (or most recent) migration.
 * Returns null when the user has never started a migration (HTTP 404).
 */
export async function getCurrentMigration(): Promise<UserMigration | null> {
  try {
    const { data } = await apiClient.get<UserMigration>('/migration/current')
    return data
  } catch (error) {
    const err = error as { status?: number }
    if (err.status === 404) {
      return null
    }
    throw error
  }
}

export const migrationAPI = {
  start: startMigration,
  current: getCurrentMigration,
  status: getMigrationStatus,
  preview: getMigrationPreview,
  confirm: confirmMigration
}

export default migrationAPI
