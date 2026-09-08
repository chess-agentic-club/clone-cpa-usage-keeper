/* @vitest-environment happy-dom */

import { readFileSync } from 'node:fs';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nextProvider } from 'react-i18next';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '@/i18n';
import { getLoginErrorForMode } from './LoginPage';
import { LoginPage } from './LoginPage';

const source = readFileSync('src/pages/LoginPage.tsx', 'utf8');
const stylesSource = readFileSync('src/pages/LoginPage.module.scss', 'utf8');
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const mountedRoots: Array<{ root: ReturnType<typeof createRoot>; container: HTMLDivElement }> = [];

const renderLoginPage = async (viewerKeyLoginEnabled: boolean) => {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  mountedRoots.push({ root, container });
  const onPasswordSubmit = vi.fn(async () => undefined);
  const onAPIKeySubmit = vi.fn(async () => undefined);

  await act(async () => {
    root.render(createElement(
      I18nextProvider,
      { i18n },
      createElement(LoginPage, {
        viewerKeyLoginEnabled,
        onPasswordSubmit,
        onAPIKeySubmit,
      }),
    ));
  });

  return { container, onAPIKeySubmit };
};

afterEach(async () => {
  while (mountedRoots.length > 0) {
    const mounted = mountedRoots.pop();
    if (!mounted) continue;
    await act(async () => mounted.root.unmount());
    mounted.container.remove();
  }
});

describe('LoginPage mode-specific errors', () => {
  it('shows only the active login mode error', () => {
    expect(getLoginErrorForMode('admin', { adminError: 'bad password', apiKeyError: 'bad api key' })).toBe('bad password');
    expect(getLoginErrorForMode('api_key', { adminError: 'bad password', apiKeyError: 'bad api key' })).toBe('bad api key');
  });

  it('does not leak API Key failures onto the admin tab or admin failures onto the API Key tab', () => {
    expect(getLoginErrorForMode('admin', { adminError: '', apiKeyError: 'bad api key' })).toBe('');
    expect(getLoginErrorForMode('api_key', { adminError: 'bad password', apiKeyError: '' })).toBe('');
  });

  it('keeps the login hero concise and exposes theme switching', () => {
    expect(source).toContain('styles.themeSwitcher');
    expect(source).toContain('useThemeStore');
    expect(source).not.toContain('capabilityGrid');
    expect(source).not.toContain('capability_persistence');
  });

  it('fills the app main area instead of adding a second viewport height', () => {
    expect(stylesSource).toMatch(/\.pageShell\s*\{[\s\S]*?flex:\s*1\s+1\s+auto;/);
    expect(stylesSource).toMatch(/\.pageShell\s*\{[\s\S]*?min-height:\s*0;/);
    expect(stylesSource).not.toMatch(/\.pageShell\s*\{[\s\S]*?min-height:\s*100v?h;/);
  });

  it('offers virtual-key login when the server advertises viewer_key_login without CPA integration', async () => {
    const { container, onAPIKeySubmit } = await renderLoginPage(true);
    const apiKeyTab = Array.from(container.querySelectorAll<HTMLButtonElement>('[role="tab"]'))
      .find((button) => button.textContent === i18n.t('auth.api_key_tab'));

    expect(apiKeyTab).toBeDefined();
    await act(async () => apiKeyTab?.click());

    const input = container.querySelector<HTMLInputElement>('input[autocomplete="off"]');
    expect(input).not.toBeNull();
    await act(async () => {
      if (!input) return;
      const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      valueSetter?.call(input, 'sk-virtual');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => {
      container.querySelector<HTMLFormElement>('form')?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });

    expect(onAPIKeySubmit).toHaveBeenCalledOnce();
    expect(onAPIKeySubmit).toHaveBeenCalledWith('sk-virtual');
  });

  it('omits virtual-key login when viewer_key_login is false', async () => {
    const { container } = await renderLoginPage(false);

    expect(container.textContent).not.toContain(i18n.t('auth.api_key_tab'));
    expect(container.querySelector('input[autocomplete="off"]')).toBeNull();
  });
});
