import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

import MigrationView from '../MigrationView.vue'

const { current, preview, status, confirm, showSuccess, refreshUser, push, replace } = vi.hoisted(() => ({
  current: vi.fn(),
  preview: vi.fn(),
  status: vi.fn(),
  confirm: vi.fn(),
  showSuccess: vi.fn(),
  refreshUser: vi.fn(),
  push: vi.fn(),
  replace: vi.fn(),
}))

vi.mock('@/api', () => ({
  migrationAPI: { current, preview, status, confirm },
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ query: {} }),
  useRouter: () => ({ push, replace }),
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({ refreshUser }),
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({ showSuccess }),
}))

describe('MigrationView completed state', () => {
  beforeEach(() => {
    current.mockReset()
    preview.mockReset()
    status.mockReset()
    confirm.mockReset()
    showSuccess.mockReset()
    refreshUser.mockReset()
    push.mockReset()
    replace.mockReset()
    localStorage.clear()
  })

  it('explains that a refreshed completed migration will not show the one-time API key again', async () => {
    current.mockResolvedValue({
      id: 1,
      migration_id: 'migration-1',
      source_system: 'hk-newapi',
      source_user_id: 'source-1',
      target_user_id: 2,
      status: 'completed',
      password_compatible: true,
      credited_balance: 12.5,
      created_at: '2026-10-21T00:00:00Z',
      updated_at: '2026-10-21T00:00:00Z',
    })

    const wrapper = mount(MigrationView, {
      global: {
        stubs: { AppLayout: { template: '<main><slot /></main>' }, Icon: true },
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('此次迁移余额不会再次入账')
    expect(wrapper.text()).toContain('前往 API Key 管理创建新的密钥')
    expect(wrapper.find('button').text()).toContain('前往 API Key 管理')

    wrapper.unmount()
  })
})
