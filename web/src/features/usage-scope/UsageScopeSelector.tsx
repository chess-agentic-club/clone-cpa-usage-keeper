import { useTranslation } from 'react-i18next'
import { Select } from '@/components/ui/Select'
import type { AuthRole, UsageScopeKeysResponse, UsageScopeSelection, UsageScopeUsersResponse } from '@/lib/types'
import styles from './UsageScopeSelector.module.scss'

export function UsageScopeSelector({
  role,
  selection,
  users,
  keys,
  loading = false,
  error = '',
  onSelectionChange,
}: {
  role: AuthRole
  selection: UsageScopeSelection
  users?: UsageScopeUsersResponse | null
  keys?: UsageScopeKeysResponse | null
  loading?: boolean
  error?: string
  onSelectionChange: (selection: UsageScopeSelection) => void
}) {
  const { t } = useTranslation()
  const keyDisabled = role === 'admin' && !selection.userCatalogId
  const stale = Boolean(users?.stale || keys?.stale)
  return (
    <div className={styles.scope} aria-busy={loading || undefined}>
      {role === 'admin' && (
        <label className={styles.field}>
          <span>User</span>
          <Select
            value={selection.userCatalogId}
            ariaLabel="User"
            options={[{ value: '', label: 'All users' }, ...(users?.users ?? []).map((user) => ({ value: user.id, label: user.label }))]}
            onChange={(userCatalogId) => onSelectionChange({ userCatalogId, keyCatalogId: '' })}
          />
        </label>
      )}
      <label className={styles.field}>
        <span>API key</span>
        <Select
          value={selection.keyCatalogId}
          ariaLabel="API key"
          disabled={keyDisabled || loading}
          options={[{ value: '', label: 'All API keys' }, ...(keys?.keys ?? []).map((key) => ({ value: key.id, label: key.label }))]}
          onChange={(keyCatalogId) => onSelectionChange({ ...selection, keyCatalogId })}
        />
      </label>
      {stale && <span className={styles.stale} role="status">{t('usage_scope.stale')}</span>}
      {error && <span className={styles.error} role="alert">{t('usage_scope.load_failed')}</span>}
    </div>
  )
}
