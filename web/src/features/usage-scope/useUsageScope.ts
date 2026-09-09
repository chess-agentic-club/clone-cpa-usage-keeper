import { useCallback, useEffect, useMemo, useState } from 'react'
import { ApiError, fetchUsageScopeKeys, fetchUsageScopeUsers } from '@/lib/api'
import type { AuthRole, UsageScopeKeysResponse, UsageScopeSelection, UsageScopeUsersResponse } from '@/lib/types'

const STORAGE_KEY = 'cpa-usage-keeper-usage-scope-v1'
const emptySelection: UsageScopeSelection = { userCatalogId: '', keyCatalogId: '' }

const loadSelection = (): UsageScopeSelection => {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') as Partial<UsageScopeSelection>
    return {
      userCatalogId: typeof value.userCatalogId === 'string' ? value.userCatalogId : '',
      keyCatalogId: typeof value.keyCatalogId === 'string' ? value.keyCatalogId : '',
    }
  } catch {
    return emptySelection
  }
}

const persistSelection = (selection: UsageScopeSelection) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(selection))
  } catch {
    // Storage is optional in embedded browsers.
  }
}

export const scopeSearchParams = (selection: UsageScopeSelection) => {
  const params = new URLSearchParams()
  if (selection.userCatalogId) params.set('user_catalog_id', selection.userCatalogId)
  if (selection.keyCatalogId) params.set('key_catalog_id', selection.keyCatalogId)
  return params
}

export interface UsageScopeState {
  selection: UsageScopeSelection
  users: UsageScopeUsersResponse | null
  keys: UsageScopeKeysResponse | null
  loading: boolean
  error: string
  setSelection: (selection: UsageScopeSelection) => void
}

export const useUsageScope = ({ role, enabled, onAuthRequired }: {
  role: AuthRole | null
  enabled: boolean
  onAuthRequired?: () => void
}): UsageScopeState => {
  const [selection, setSelectionState] = useState<UsageScopeSelection>(loadSelection)
  const [users, setUsers] = useState<UsageScopeUsersResponse | null>(null)
  const [keys, setKeys] = useState<UsageScopeKeysResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const scopedSelection = useMemo(() => ({
    userCatalogId: role === 'user' ? '' : selection.userCatalogId,
    keyCatalogId: selection.keyCatalogId,
  }), [role, selection.keyCatalogId, selection.userCatalogId])

  const setSelection = useCallback((next: UsageScopeSelection) => {
    const sanitized = {
      userCatalogId: role === 'admin' ? next.userCatalogId : '',
      keyCatalogId: next.keyCatalogId,
    }
    persistSelection(sanitized)
    setSelectionState(sanitized)
  }, [role])

  const loadKeys = useCallback(async (controller: AbortController) => {
    setLoading(true)
    setError('')
    setKeys(null)
    if (role === 'admin' && !scopedSelection.userCatalogId) {
      setLoading(false)
      return
    }
    try {
      const response = await fetchUsageScopeKeys(scopedSelection.userCatalogId, controller.signal)
      if (controller.signal.aborted) return
      setKeys(response)
      if (scopedSelection.keyCatalogId && !response.keys.some((key) => key.id === scopedSelection.keyCatalogId)) {
        setSelection({ ...scopedSelection, keyCatalogId: '' })
      }
    } catch (nextError) {
      if (controller.signal.aborted) return
      if (nextError instanceof ApiError && nextError.status === 401) onAuthRequired?.()
      setError(nextError instanceof Error ? nextError.message : 'USAGE_SCOPE_LOAD_FAILED')
    } finally {
      if (!controller.signal.aborted) setLoading(false)
    }
  }, [onAuthRequired, role, scopedSelection, setSelection])

  const loadUsers = useCallback(async (controller: AbortController) => {
    try {
      const response = await fetchUsageScopeUsers(controller.signal)
      if (!controller.signal.aborted) setUsers(response)
    } catch (nextError) {
      if (controller.signal.aborted) return
      if (nextError instanceof ApiError && nextError.status === 401) onAuthRequired?.()
      setError(nextError instanceof Error ? nextError.message : 'USAGE_SCOPE_LOAD_FAILED')
    }
  }, [onAuthRequired])

  useEffect(() => {
    if (!enabled || (role !== 'admin' && role !== 'user')) return
    const controller = new AbortController()
    void loadKeys(controller)
    return () => controller.abort()
  }, [enabled, loadKeys, role])

  useEffect(() => {
    if (!enabled || role !== 'admin') return
    const controller = new AbortController()
    void loadUsers(controller)
    return () => controller.abort()
  }, [enabled, loadUsers, role])

  return { selection: scopedSelection, users, keys, loading, error, setSelection }
}
