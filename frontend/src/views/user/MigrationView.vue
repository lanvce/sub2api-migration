<template>
  <AppLayout>
    <div class="mx-auto max-w-3xl space-y-6">
      <!-- 页面说明 -->
      <div class="card">
        <div class="p-6">
          <div class="flex items-start gap-4">
            <div
              class="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-2xl bg-primary-100 dark:bg-primary-900/30"
            >
              <Icon name="swap" size="lg" class="text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <h1 class="text-lg font-semibold text-gray-900 dark:text-white">账户余额迁移</h1>
              <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
                将您在香港站（旧系统）的账户余额迁移到本站。迁移需要先跳转到香港站完成授权，授权成功后返回本页确认迁移。
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- 加载中 -->
      <div v-if="loading" class="card">
        <div class="flex items-center justify-center gap-3 p-10">
          <svg class="h-6 w-6 animate-spin text-primary-500" fill="none" viewBox="0 0 24 24">
            <circle
              class="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              stroke-width="4"
            ></circle>
            <path
              class="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            ></path>
          </svg>
          <span class="text-sm text-gray-500 dark:text-dark-400">正在加载迁移状态…</span>
        </div>
      </div>

      <!-- 开始迁移 -->
      <div v-else-if="phase === 'intro'" class="card">
        <div class="space-y-5 p-6">
          <div>
            <h2 class="text-base font-semibold text-gray-900 dark:text-white">开始迁移</h2>
            <ul
              class="mt-3 list-inside list-disc space-y-1 text-sm text-gray-600 dark:text-dark-300"
            >
              <li>点击下方按钮后将跳转到香港站进行账户授权</li>
              <li>授权完成后会自动返回本页，届时可预览并确认迁移</li>
              <li>迁移完成后旧账户将被锁定，余额按官方汇率折算入账</li>
              <li>整个过程余额只会入账一次，可放心重试</li>
            </ul>
          </div>
          <button
            type="button"
            class="btn btn-primary w-full py-3"
            :disabled="submitting"
            @click="handleStart"
          >
            {{ submitting ? '正在创建迁移…' : '前往香港站授权' }}
          </button>
        </div>
      </div>

      <!-- 等待授权 -->
      <div v-else-if="phase === 'authorizing'" class="card">
        <div class="space-y-5 p-6">
          <div class="flex items-start gap-4">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/30"
            >
              <Icon name="clock" size="md" class="text-amber-600 dark:text-amber-400" />
            </div>
            <div>
              <h2 class="text-base font-semibold text-gray-900 dark:text-white">等待授权</h2>
              <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
                您有一个迁移正在等待香港站授权。如果尚未完成授权，请点击下方按钮重新打开授权页面；如果已完成授权，请点击「刷新状态」。
              </p>
            </div>
          </div>
          <div class="flex flex-col gap-3 sm:flex-row">
            <button
              type="button"
              class="btn btn-primary flex-1 py-3"
              :disabled="submitting"
              @click="handleStart"
            >
              {{ submitting ? '正在重新打开授权…' : '重新打开授权页面' }}
            </button>
            <button
              type="button"
              class="btn btn-secondary flex-1 py-3"
              :disabled="submitting"
              @click="refreshStatus"
            >
              刷新状态
            </button>
            <button
              type="button"
              class="btn btn-secondary flex-1 py-3"
              :disabled="submitting"
              @click="resetMigration"
            >
              放弃并重新开始
            </button>
          </div>
        </div>
      </div>

      <!-- 预览并确认 -->
      <div v-else-if="phase === 'preview'" class="card">
        <div class="space-y-5 p-6">
          <div>
            <h2 class="text-base font-semibold text-gray-900 dark:text-white">确认迁移</h2>
            <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
              请核对以下旧账户信息，确认无误后点击「确认迁移」。确认后旧账户将被锁定，余额将折算入账。
            </p>
          </div>

          <dl class="divide-y divide-gray-100 rounded-xl bg-gray-50 dark:divide-dark-700 dark:bg-dark-800">
            <div v-if="migration?.source_email" class="flex justify-between gap-4 px-4 py-3 text-sm">
              <dt class="shrink-0 text-gray-500 dark:text-dark-400">旧账户邮箱</dt>
              <dd class="min-w-0 break-all text-right font-medium text-gray-900 dark:text-white">
                {{ migration.source_email }}
              </dd>
            </div>
            <div v-if="migration?.source_username" class="flex justify-between gap-4 px-4 py-3 text-sm">
              <dt class="shrink-0 text-gray-500 dark:text-dark-400">旧账户用户名</dt>
              <dd class="min-w-0 break-all text-right font-medium text-gray-900 dark:text-white">
                {{ migration.source_username }}
              </dd>
            </div>
            <div
              v-if="migration?.source_available_quota != null"
              class="flex justify-between px-4 py-3 text-sm"
            >
              <dt class="text-gray-500 dark:text-dark-400">旧站可用额度</dt>
              <dd class="font-medium text-gray-900 dark:text-white">
                {{ migration.source_available_quota.toLocaleString() }}
              </dd>
            </div>
            <div
              v-if="migration?.converted_balance != null"
              class="flex justify-between px-4 py-3 text-sm"
            >
              <dt class="text-gray-500 dark:text-dark-400">折算后入账金额</dt>
              <dd class="font-semibold text-emerald-600 dark:text-emerald-400">
                ${{ migration.converted_balance.toFixed(2) }}
              </dd>
            </div>
            <div class="flex justify-between px-4 py-3 text-sm">
              <dt class="text-gray-500 dark:text-dark-400">当前状态</dt>
              <dd class="font-medium text-gray-900 dark:text-white">{{ statusLabel }}</dd>
            </div>
          </dl>

          <div
            v-if="warnings.length > 0"
            class="rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-800/50 dark:bg-amber-900/20"
          >
            <p
              v-for="(warning, index) in warnings"
              :key="index"
              class="text-sm text-amber-700 dark:text-amber-400"
            >
              {{ warning }}
            </p>
          </div>

          <div class="flex flex-col gap-3 sm:flex-row">
            <button
              type="button"
              class="btn btn-primary flex-1 py-3"
              :disabled="!canConfirm || submitting"
              @click="handleConfirm"
            >
              {{ submitting ? '正在迁移…' : '确认迁移' }}
            </button>
            <button
              type="button"
              class="btn btn-secondary flex-1 py-3"
              :disabled="submitting"
              @click="resetMigration"
            >
              放弃并重新开始
            </button>
          </div>
        </div>
      </div>

      <!-- 迁移完成 -->
      <div
        v-else-if="phase === 'done'"
        class="card border-emerald-200 bg-emerald-50 dark:border-emerald-800/50 dark:bg-emerald-900/20"
      >
        <div class="space-y-5 p-6">
          <div class="flex items-start gap-4">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-emerald-100 dark:bg-emerald-900/30"
            >
              <Icon name="checkCircle" size="md" class="text-emerald-600 dark:text-emerald-400" />
            </div>
            <div>
              <h2 class="text-base font-semibold text-emerald-800 dark:text-emerald-300">
                迁移完成
              </h2>
              <p class="mt-1 text-sm text-emerald-700 dark:text-emerald-400">
                <template v-if="migration?.credited_balance != null">
                  已成功入账
                  <span class="font-semibold">${{ migration.credited_balance.toFixed(2) }}</span
                  >。
                </template>
                余额已同步到您的账户。
              </p>
            </div>
          </div>

          <div v-if="apiKey" class="space-y-2">
            <p class="text-sm font-medium text-emerald-800 dark:text-emerald-300">
              新的 API Key（仅显示一次，请立即保存）：
            </p>
            <div
              class="flex items-center gap-2 rounded-xl border border-emerald-200 bg-white p-3 dark:border-emerald-800/50 dark:bg-dark-800"
            >
              <code class="flex-1 break-all font-mono text-sm text-gray-900 dark:text-white">{{
                apiKey
              }}</code>
              <button
                type="button"
                class="btn btn-secondary flex-shrink-0 px-3 py-1.5 text-xs"
                @click="copyApiKey"
              >
                {{ copied ? '已复制' : '复制' }}
              </button>
            </div>
          </div>

          <p v-else class="text-sm text-emerald-800 dark:text-emerald-300">
            本次迁移已完成。新 API Key 仅在确认完成时显示一次；此次迁移余额不会再次入账。请前往 API Key 管理创建新的密钥。
          </p>

          <button type="button" class="btn btn-primary w-full py-3" @click="goToKeys">
            前往 API Key 管理
          </button>
        </div>
      </div>

      <!-- 迁移失败 / 人工审核 -->
      <div
        v-else-if="phase === 'failed'"
        class="card border-red-200 bg-red-50 dark:border-red-800/50 dark:bg-red-900/20"
      >
        <div class="space-y-5 p-6">
          <div class="flex items-start gap-4">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-red-100 dark:bg-red-900/30"
            >
              <Icon name="exclamationCircle" size="md" class="text-red-600 dark:text-red-400" />
            </div>
            <div>
              <h2 class="text-base font-semibold text-red-800 dark:text-red-300">
                {{ migration?.status === 'manual_review' ? '需要人工处理' : '迁移失败' }}
              </h2>
              <p class="mt-1 text-sm text-red-700 dark:text-red-400">
                {{ failureMessage }}
              </p>
            </div>
          </div>
          <button
            v-if="migration?.status !== 'manual_review'"
            type="button"
            class="btn btn-primary w-full py-3"
            :disabled="submitting"
            @click="resetMigration"
          >
            重新开始迁移
          </button>
        </div>
      </div>

      <!-- 错误提示 -->
      <transition name="fade">
        <div
          v-if="errorMessage"
          class="card border-red-200 bg-red-50 dark:border-red-800/50 dark:bg-red-900/20"
        >
          <div class="p-4">
            <p class="text-sm text-red-700 dark:text-red-400">{{ errorMessage }}</p>
          </div>
        </div>
      </transition>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useAppStore } from '@/stores/app'
import { migrationAPI, type UserMigration } from '@/api'
import AppLayout from '@/components/layout/AppLayout.vue'
import Icon from '@/components/icons/Icon.vue'

const SOURCE_SYSTEM = 'hk-newapi'
const STORAGE_KEY = 'pending_migration'

type Phase = 'intro' | 'authorizing' | 'preview' | 'done' | 'failed'

interface PendingMigration {
  migration_id: string
  state: string
}

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const appStore = useAppStore()

const loading = ref(true)
const submitting = ref(false)
const phase = ref<Phase>('intro')
const migration = ref<UserMigration | null>(null)
const warnings = ref<string[]>([])
const canConfirm = ref(false)
const authorizationUrl = ref('')
const authorizationState = ref('')
const apiKey = ref('')
const copied = ref(false)
const errorMessage = ref('')

const STATUS_LABELS: Record<string, string> = {
  pending: '待处理',
  authorizing: '等待授权',
  authorized: '已授权',
  locked: '旧账户已锁定',
  processing: '迁移处理中',
  completed: '迁移完成',
  failed: '迁移失败',
  manual_review: '人工审核中'
}

const statusLabel = computed(() =>
  migration.value ? STATUS_LABELS[migration.value.status] || migration.value.status : ''
)

const failureMessage = computed(() => {
  if (migration.value?.status === 'manual_review') {
    return migration.value.failure_message || '迁移需要人工处理，请联系管理员。'
  }
  return migration.value?.failure_message || '迁移失败，请重试或联系管理员。'
})

function loadPending(): PendingMigration | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as PendingMigration
    if (!parsed.migration_id) return null
    return parsed
  } catch {
    return null
  }
}

function savePending(pending: PendingMigration) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(pending))
}

function clearPending() {
  localStorage.removeItem(STORAGE_KEY)
}

function extractErrorMessage(error: unknown): string {
  const err = error as {
    status?: number
    response?: { status?: number; data?: { detail?: string; message?: string } }
    message?: string
  }
  const raw = (
    err.response?.data?.detail ||
    err.response?.data?.message ||
    err.message ||
    ''
  ).toString()
  const status = err.status ?? err.response?.status
  if (
    status === 409 ||
    /already exists for source or target user/i.test(raw) ||
    /migration is (locked|processing|manual_review)/i.test(raw)
  ) {
    if (/manual_review/i.test(raw)) {
      return '该迁移需要人工处理，请联系管理员。'
    }
    if (/locked|processing/i.test(raw)) {
      return '迁移正在处理中，请稍候刷新状态，不要重复发起。'
    }
    return '您已有进行中的迁移，正在恢复原记录。请刷新页面后继续，不要重复发起。'
  }
  return raw || '操作失败，请稍后重试'
}

function applyMigration(m: UserMigration) {
  migration.value = m
  if (m.authorization_redirect_url) {
    authorizationUrl.value = m.authorization_redirect_url
  }
  switch (m.status) {
    case 'completed':
      phase.value = 'done'
      clearPending()
      break
    case 'failed':
    case 'manual_review':
      phase.value = 'failed'
      break
    case 'pending':
    case 'authorizing':
      phase.value = 'authorizing'
      break
    case 'authorized':
      phase.value = 'preview'
      break
    default:
      // locked / processing: mid-flight states, keep the user informed
      // instead of showing an empty confirm card.
      phase.value = 'authorizing'
  }
}

async function loadPreview(migrationId: string, authorizationStateArg?: string) {
  const state = authorizationStateArg ?? authorizationState.value
  const preview = await migrationAPI.preview(migrationId, state)
  migration.value = preview.migration
  warnings.value = preview.warnings ?? []
  canConfirm.value = preview.can_confirm
  if (preview.migration.status === 'completed') {
    phase.value = 'done'
    clearPending()
  } else if (
    preview.migration.status === 'failed' ||
    preview.migration.status === 'manual_review'
  ) {
    phase.value = 'failed'
  } else if (preview.migration.status === 'authorized') {
    // Only the authorized state carries the bound source identity and balance
    // snapshot worth confirming; anything else still waits for authorization.
    phase.value = 'preview'
  } else {
    phase.value = 'authorizing'
  }
}

async function restoreMigration(migrationId: string) {
  const m = await migrationAPI.status(migrationId)
  applyMigration(m)
  if (phase.value === 'preview') {
    await loadPreview(migrationId)
  }
}

async function handleStart() {
  submitting.value = true
  errorMessage.value = ''
  try {
    const pending = loadPending()
    const requestedId =
      pending?.migration_id ||
      migration.value?.migration_id ||
      (typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `mig-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`)
    const redirectUrl = `${window.location.origin}/migration`
    const result = await migrationAPI.start(requestedId, SOURCE_SYSTEM, redirectUrl)
    const serverMigrationId = result.migration?.migration_id || requestedId
    const serverState = result.session?.state || ''
    savePending({ migration_id: serverMigrationId, state: serverState })
    authorizationState.value = serverState
    if (result.session?.authorization_url) {
      window.location.href = result.session.authorization_url
      return
    }
    applyMigration(result.migration)
  } catch (error) {
    errorMessage.value = extractErrorMessage(error)
  } finally {
    submitting.value = false
  }
}

async function refreshStatus() {
  submitting.value = true
  errorMessage.value = ''
  try {
    const pending = loadPending()
    if (pending) {
      await restoreMigration(pending.migration_id)
      return
    }
    const current = await migrationAPI.current()
    if (!current) {
      phase.value = 'intro'
      return
    }
    savePending({
      migration_id: current.migration_id,
      state: authorizationState.value
    })
    applyMigration(current)
    if (phase.value === 'preview') {
      await loadPreview(current.migration_id)
    }
  } catch (error) {
    errorMessage.value = extractErrorMessage(error)
  } finally {
    submitting.value = false
  }
}

async function handleConfirm() {
  const pending = loadPending()
  const migrationId = pending?.migration_id || migration.value?.migration_id
  const state = authorizationState.value || pending?.state || ''
  if (!migrationId) {
    errorMessage.value = '迁移信息丢失，请重新开始迁移'
    phase.value = 'intro'
    return
  }
  submitting.value = true
  errorMessage.value = ''
  try {
    const result = await migrationAPI.confirm(migrationId, state)
    migration.value = result.migration
    apiKey.value = result.api_key || ''
    phase.value = 'done'
    clearPending()
    appStore.showSuccess('迁移完成，余额已入账')
    await authStore.refreshUser()
  } catch (error) {
    errorMessage.value = extractErrorMessage(error)
    // 确认失败后重新拉取状态，可能已进入 failed / manual_review
    try {
      await loadPreview(migrationId)
    } catch {
      // 保持当前界面，错误信息已展示
    }
  } finally {
    submitting.value = false
  }
}

function resetMigration() {
  clearPending()
  migration.value = null
  warnings.value = []
  canConfirm.value = false
  authorizationUrl.value = ''
  authorizationState.value = ''
  errorMessage.value = ''
  phase.value = 'intro'
}

async function copyApiKey() {
  try {
    await navigator.clipboard.writeText(apiKey.value)
    copied.value = true
    setTimeout(() => {
      copied.value = false
    }, 2000)
  } catch {
    appStore.showError('复制失败，请手动复制')
  }
}

function goToKeys() {
  router.push('/keys')
}

onMounted(async () => {
  const queryMigrationId =
    typeof route.query.migration_id === 'string' ? route.query.migration_id : ''
  const queryState = typeof route.query.state === 'string' ? route.query.state : ''
  const pending = loadPending()

  try {
    if (queryMigrationId) {
      authorizationState.value = queryState || pending?.state || ''
      savePending({ migration_id: queryMigrationId, state: authorizationState.value })
      router.replace({ path: '/migration' })
      await loadPreview(queryMigrationId)
      return
    }
    if (pending) {
      authorizationState.value = pending.state
      try {
        await restoreMigration(pending.migration_id)
        return
      } catch (error) {
        const err = error as { status?: number }
        if (err.status !== 404) {
          throw error
        }
      }
    }
    const current = await migrationAPI.current()
    if (!current) {
      return
    }
    savePending({
      migration_id: current.migration_id,
      state: authorizationState.value || pending?.state || ''
    })
    applyMigration(current)
    if (phase.value === 'preview') {
      await loadPreview(current.migration_id)
    }
  } catch (error) {
    errorMessage.value = extractErrorMessage(error)
    phase.value = pending || queryMigrationId ? 'authorizing' : 'intro'
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: all 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
