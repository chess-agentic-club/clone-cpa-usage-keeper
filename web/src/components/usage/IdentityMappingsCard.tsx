import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { ApiError, updateIdentityMapping } from '@/lib/api'
import type { IdentityMapping, UsageScopeOption } from '@/lib/types'
import styles from './IdentityMappingsCard.module.scss'

export interface IdentityMappingsCardProps {
  mappings: IdentityMapping[]
  sourceUsers: UsageScopeOption[]
  loading?: boolean
  stale?: boolean
  onRefresh: () => Promise<void>
}

const getMappingState = (mapping: IdentityMapping, t: (key: string) => string) => {
  if (mapping.match_method === 'ambiguous') return t('usage_stats.identity_mappings_ambiguous')
  if (!mapping.source_user_catalog_id) return t('usage_stats.identity_mappings_unmapped')
  if (!mapping.confirmed) return t('usage_stats.identity_mappings_missing')
  return mapping.match_method || t('usage_stats.identity_mappings_missing')
}

export function IdentityMappingsCard({ mappings, sourceUsers, loading = false, stale = false, onRefresh }: IdentityMappingsCardProps) {
  const { t } = useTranslation()
  const initialSelections = useMemo(
    () => Object.fromEntries(mappings.map((mapping) => [mapping.id, mapping.source_user_catalog_id])),
    [mappings],
  )
  const [selections, setSelections] = useState<Record<string, string>>(initialSelections)
  const [savingID, setSavingID] = useState<string | null>(null)
  const [saveError, setSaveError] = useState('')

  useEffect(() => setSelections(initialSelections), [initialSelections])

  const saveMapping = async (mapping: IdentityMapping) => {
    const sourceUserCatalogID = selections[mapping.id] ?? ''
    if (!sourceUserCatalogID) return
    setSavingID(mapping.id)
    setSaveError('')
    try {
      await updateIdentityMapping(mapping.id, { source_user_catalog_id: sourceUserCatalogID })
      await onRefresh()
    } catch (error) {
      setSaveError(
        error instanceof ApiError && error.status === 403
          ? t('usage_stats.identity_mappings_forbidden')
          : t('usage_stats.identity_mappings_save_failed'),
      )
    } finally {
      setSavingID(null)
    }
  }

  return (
    <Card
      title={t('usage_stats.identity_mappings_title')}
      subtitle={t('usage_stats.identity_mappings_subtitle')}
      className={styles.card}
    >
      <div className={styles.body} aria-busy={loading || undefined}>
        {stale && <p className={styles.stale} role="status">{t('usage_stats.identity_mappings_stale')}</p>}
        {saveError && <p className={styles.error} role="alert">{saveError}</p>}
        {loading && mappings.length === 0 ? (
          <div className={styles.hint}>{t('common.loading')}</div>
        ) : mappings.length === 0 ? (
          <div className={styles.hint}>{t('usage_stats.identity_mappings_empty')}</div>
        ) : (
          <div className={styles.list}>
            {mappings.map((mapping) => {
              const sourceUserCatalogID = selections[mapping.id] ?? ''
              const saving = savingID === mapping.id
              return (
                <div key={mapping.id} className={styles.item}>
                  <div className={styles.summary}>
                    <span className={styles.fieldLabel}>{t('usage_stats.identity_mappings_external_identity')}</span>
                    <span className={styles.identityLabel} title={mapping.label}>{mapping.label}</span>
                    <span className={styles.matchState}>{getMappingState(mapping, t)}</span>
                  </div>
                  <label className={styles.selectorField}>
                    <span className={styles.fieldLabel}>{t('usage_stats.identity_mappings_datasource_user')}</span>
                    <Select
                      value={sourceUserCatalogID}
                      ariaLabel={t('usage_stats.identity_mappings_datasource_user')}
                      options={[
                        { value: '', label: t('usage_stats.identity_mappings_unmapped') },
                        ...sourceUsers.map((user) => ({ value: user.id, label: user.label })),
                      ]}
                      onChange={(value) => setSelections((current) => ({ ...current, [mapping.id]: value }))}
                      disabled={saving}
                    />
                  </label>
                  <Button
                    type="button"
                    variant="primary"
                    size="sm"
                    appearance="action"
                    aria-label={saving ? t('usage_stats.identity_mappings_saving') : t('usage_stats.identity_mappings_save')}
                    disabled={saving || !sourceUserCatalogID}
                    onClick={() => void saveMapping(mapping)}
                  >
                    {saving ? t('usage_stats.identity_mappings_saving') : t('usage_stats.identity_mappings_save')}
                  </Button>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </Card>
  )
}
