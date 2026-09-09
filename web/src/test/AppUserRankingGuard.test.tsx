// @vitest-environment happy-dom

import React, { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const appMocks = vi.hoisted(() => ({
  getSession: vi.fn(),
  fetchUsageScopeKeys: vi.fn(),
  rankingPageMount: vi.fn(),
}));

vi.mock('@/lib/api', async (importOriginal) => ({
  ...await importOriginal<typeof import('@/lib/api')>(),
  getSession: appMocks.getSession,
  fetchUsageScopeKeys: appMocks.fetchUsageScopeKeys,
}));

vi.mock('@/pages/KeyRankingPage', () => ({
  KeyRankingPage: () => {
    appMocks.rankingPageMount();
    return <div>ranking page</div>;
  },
}));
vi.mock('@/pages/KeyOverviewPage', () => ({ KeyOverviewPage: () => <div>overview page</div> }));
vi.mock('@/pages/KeyAnalysisPage', () => ({ KeyAnalysisPage: () => <div>analysis page</div> }));
vi.mock('@/components/AppFooter', () => ({ AppFooter: () => null }));
vi.mock('@/embed/cpamcEmbed', () => ({
  cpamcEmbedSearch: () => '',
  isCPAMCEmbed: () => false,
  notifyCPAMCEmbedReady: () => undefined,
}));
vi.mock('react-i18next', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-i18next')>(),
  useTranslation: () => ({ t: (key: string) => key }),
}));

import App from '@/App';

describe('App embedded user ranking guard', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    window.history.replaceState(null, '', '/key-ranking');
    appMocks.rankingPageMount.mockReset();
    appMocks.fetchUsageScopeKeys.mockResolvedValue({
      source_system: 'litellm',
      synced_at: '2026-09-09T00:00:00Z',
      stale: false,
      keys: [],
    });
    appMocks.getSession.mockResolvedValue({
      authenticated: true,
      role: 'user',
      auth_mode: 'embedded_jwt',
      capabilities: {},
    });
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it('never mounts the ranking page for a user restored on /key-ranking', async () => {
    await act(async () => {
      root.render(<App />);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(appMocks.rankingPageMount).not.toHaveBeenCalled();
    expect(container.textContent).toContain('overview page');
  });
});
