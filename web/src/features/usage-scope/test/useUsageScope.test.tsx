// @vitest-environment happy-dom

import React, { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { UsageScopeKeysResponse } from '@/lib/types';

const apiMocks = vi.hoisted(() => ({
  fetchUsageScopeKeys: vi.fn(),
  fetchUsageScopeUsers: vi.fn(),
}));

vi.mock('@/lib/api', async (importOriginal) => ({
  ...await importOriginal<typeof import('@/lib/api')>(),
  fetchUsageScopeKeys: apiMocks.fetchUsageScopeKeys,
  fetchUsageScopeUsers: apiMocks.fetchUsageScopeUsers,
}));

import { scopeSearchParams, useUsageScope } from '../useUsageScope';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

type Deferred<T> = { promise: Promise<T>; resolve: (value: T) => void };
const deferred = <T,>(): Deferred<T> => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((nextResolve) => { resolve = nextResolve; });
  return { promise, resolve };
};

describe('usage scope query parameters', () => {
  it('serializes only selected opaque catalog IDs', () => {
    const params = scopeSearchParams({
      userCatalogId: 'usr_opaque_A',
      keyCatalogId: 'key_opaque_B',
    });

    expect(params.toString()).toBe('user_catalog_id=usr_opaque_A&key_catalog_id=key_opaque_B');
  });

  it('represents All users and keys with empty selections', () => {
    expect(scopeSearchParams({ userCatalogId: '', keyCatalogId: '' }).toString()).toBe('');
  });
});

describe('useUsageScope', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    localStorage.clear();
    apiMocks.fetchUsageScopeKeys.mockReset();
    apiMocks.fetchUsageScopeUsers.mockReset();
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it('aborts a stale key request when an admin selects another user', async () => {
    const first = deferred<UsageScopeKeysResponse>();
    const second = deferred<UsageScopeKeysResponse>();
    apiMocks.fetchUsageScopeUsers.mockResolvedValue({ source_system: 'litellm', synced_at: '2026-09-09T00:00:00Z', stale: false, users: [] });
    apiMocks.fetchUsageScopeKeys.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const Harness = () => {
      const scope = useUsageScope({ role: 'admin', enabled: true });
      return <>
        <button type="button" onClick={() => scope.setSelection({ userCatalogId: 'usr_a', keyCatalogId: '' })}>first</button>
        <button type="button" onClick={() => scope.setSelection({ userCatalogId: 'usr_b', keyCatalogId: '' })}>second</button>
      </>;
    };

    await act(async () => { root.render(<Harness />); await Promise.resolve(); });
    await act(async () => {
      // The first selection starts the first key request.
      Array.from(container.querySelectorAll('button')).find((button) => button.textContent === 'first')?.click();
      await Promise.resolve();
    });
    const firstSignal = apiMocks.fetchUsageScopeKeys.mock.calls[0]?.[1] as AbortSignal;
    await act(async () => {
      // A subsequent selection aborts the in-flight request rather than accepting its response.
      Array.from(container.querySelectorAll('button')).find((button) => button.textContent === 'second')?.click();
      await Promise.resolve();
    });

    expect(firstSignal.aborted).toBe(true);
    await act(async () => {
      first.resolve({ source_system: 'litellm', synced_at: '2026-09-09T00:00:00Z', stale: false, keys: [] });
      second.resolve({ source_system: 'litellm', synced_at: '2026-09-09T00:00:00Z', stale: false, keys: [] });
      await Promise.resolve();
    });
  });

  it('clears a restored key selection and its persisted opaque value for admin All users', async () => {
    localStorage.setItem('cpa-usage-keeper-usage-scope-v1', JSON.stringify({
      userCatalogId: '',
      keyCatalogId: 'key_opaque_stale',
    }));
    const seen: string[] = [];
    apiMocks.fetchUsageScopeUsers.mockResolvedValue({ source_system: 'litellm', synced_at: '2026-09-09T00:00:00Z', stale: false, users: [] });
    const Harness = () => {
      const scope = useUsageScope({ role: 'admin', enabled: true });
      seen.push(scopeSearchParams(scope.selection).toString());
      return null;
    };

    await act(async () => { root.render(<Harness />); await Promise.resolve(); });

    expect(seen.at(-1)).toBe('');
    expect(JSON.parse(localStorage.getItem('cpa-usage-keeper-usage-scope-v1') ?? '{}')).toEqual({
      userCatalogId: '',
      keyCatalogId: '',
    });
  });
});
