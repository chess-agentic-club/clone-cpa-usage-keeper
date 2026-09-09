// @vitest-environment happy-dom

import React, { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UsageScopeSelector } from '../UsageScopeSelector';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

describe('UsageScopeSelector', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it('keeps All API keys as an empty selection for a user', () => {
    act(() => {
      root.render(
        <UsageScopeSelector
          role="user"
          selection={{ userCatalogId: '', keyCatalogId: '' }}
          keys={{ source_system: 'litellm', synced_at: '2026-09-09T00:00:00Z', stale: false, keys: [] }}
          onSelectionChange={() => undefined}
        />,
      );
    });

    expect(container.querySelector('button[aria-label="API key"]')).not.toBeNull();
    expect(container.textContent).toContain('All API keys');
  });
});
