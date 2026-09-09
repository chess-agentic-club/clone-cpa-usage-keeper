// @vitest-environment happy-dom

import { act, type ComponentProps } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, updateIdentityMapping } from '@/lib/api'
import type { IdentityMapping, UsageScopeOption } from '@/lib/types'
import { IdentityMappingsCard } from '../IdentityMappingsCard'

globalThis.IS_REACT_ACT_ENVIRONMENT = true

vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  updateIdentityMapping: vi.fn(),
}))

const translations: Record<string, string> = {
  'common.loading': 'Loading...',
  'usage_stats.identity_mappings_title': 'Identity mappings',
  'usage_stats.identity_mappings_subtitle': 'Link external identities to datasource users.',
  'usage_stats.identity_mappings_empty': 'No external identities are available.',
  'usage_stats.identity_mappings_external_identity': 'External identity',
  'usage_stats.identity_mappings_datasource_user': 'Datasource user',
  'usage_stats.identity_mappings_match': 'Match',
  'usage_stats.identity_mappings_unmapped': 'Unmapped',
  'usage_stats.identity_mappings_missing': 'Missing',
  'usage_stats.identity_mappings_ambiguous': 'Ambiguous',
  'usage_stats.identity_mappings_save': 'Save mapping',
  'usage_stats.identity_mappings_saving': 'Saving mapping',
  'usage_stats.identity_mappings_save_failed': 'Unable to save this mapping. Try again.',
  'usage_stats.identity_mappings_forbidden': 'You are not allowed to manage identity mappings. Sign in as an administrator.',
  'usage_stats.identity_mappings_stale': 'The datasource user catalog is stale. Refresh it before assigning identities.',
}

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => translations[key] ?? key }),
}))

const unmappedIdentity: IdentityMapping = {
  id: 'identity-opaque-1',
  label: 'Open WebUI user: Alex',
  confirmed: false,
}

const ambiguousIdentity: IdentityMapping = {
  id: 'identity-opaque-2',
  label: 'Open WebUI user: Blair',
  match_method: 'ambiguous',
  confirmed: false,
}

const sourceUser: UsageScopeOption = { id: 'source-user-opaque-7', label: 'Alice (Engineering)' }

describe('IdentityMappingsCard', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    vi.mocked(updateIdentityMapping).mockReset()
  })

  afterEach(async () => {
    await act(async () => root.unmount())
    container.remove()
    vi.restoreAllMocks()
  })

  const sourceUserOption = () => Array.from(document.querySelectorAll<HTMLButtonElement>('[role="option"]'))
    .find((option) => option.textContent?.includes(sourceUser.label))

  const renderCard = async (props: Partial<ComponentProps<typeof IdentityMappingsCard>> = {}) => {
    await act(async () => {
      root.render(
        <IdentityMappingsCard
          mappings={[unmappedIdentity, ambiguousIdentity]}
          sourceUsers={[sourceUser]}
          onRefresh={async () => undefined}
          {...props}
        />,
      )
    })
  }

  it('updates a mapping using only opaque IDs and refreshes the catalog row', async () => {
    const onRefresh = vi.fn(async () => undefined)
    vi.mocked(updateIdentityMapping).mockResolvedValue(undefined)
    await renderCard({ onRefresh })

    const selector = container.querySelector<HTMLButtonElement>('button[aria-label="Datasource user"]')
    expect(selector).not.toBeNull()
    await act(async () => selector?.click())
    const sourceOption = sourceUserOption()
    expect(sourceOption?.textContent).toContain(sourceUser.label)
    await act(async () => sourceOption?.click())

    const saveButton = container.querySelector<HTMLButtonElement>('button[aria-label="Save mapping"]')
    await act(async () => saveButton?.click())

    expect(updateIdentityMapping).toHaveBeenCalledWith(unmappedIdentity.id, { source_user_catalog_id: sourceUser.id })
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('renders ambiguous and missing identities without rendering source references or key material', () => {
    const markup = renderToStaticMarkup(
      <IdentityMappingsCard
        mappings={[unmappedIdentity, ambiguousIdentity]}
        sourceUsers={[sourceUser]}
        stale={false}
        onRefresh={async () => undefined}
      />,
    )

    expect(markup).toContain('Open WebUI user: Alex')
    expect(markup).toContain('Open WebUI user: Blair')
    expect(markup).toContain('Unmapped')
    expect(markup).toContain('Ambiguous')
    expect(markup).not.toContain('source-user-ref-private')
    expect(markup).not.toContain('api-group-secret')
    expect(markup).not.toContain('sk-virtual-secret')
    expect(markup).not.toContain('sha256:secret')
  })

  it('explains stale catalogs and forbidden mapping saves with actionable copy', async () => {
    vi.mocked(updateIdentityMapping).mockRejectedValue(new ApiError('mapping_required', 403))
    await renderCard({ stale: true })

    expect(container.textContent).toContain('The datasource user catalog is stale. Refresh it before assigning identities.')
    const selector = container.querySelector<HTMLButtonElement>('button[aria-label="Datasource user"]')
    await act(async () => selector?.click())
    await act(async () => sourceUserOption()?.click())
    await act(async () => container.querySelector<HTMLButtonElement>('button[aria-label="Save mapping"]')?.click())

    expect(container.textContent).toContain('You are not allowed to manage identity mappings. Sign in as an administrator.')
  })
})
