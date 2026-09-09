import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { I18nextProvider } from 'react-i18next';
import { describe, expect, it } from 'vitest';
import i18n from './i18n';
import { KeyViewerShell } from './features/key-viewer/KeyViewerShell';
import { getRoleHomePath, isViewerKeyLoginEnabled, shouldNormalizeRolePath } from './App';

const appSource = readFileSync(new URL('./App.tsx', import.meta.url), 'utf8');
const appStylesSource = readFileSync(new URL('./App.css', import.meta.url), 'utf8');

describe('App role route normalization', () => {
  it('normalizes restored admin sessions away from the API Key viewer route', () => {
    expect(getRoleHomePath('admin')).toBe('/');
    expect(shouldNormalizeRolePath('admin', '/key-overview')).toBe(true);
    expect(shouldNormalizeRolePath('admin', '/')).toBe(false);
  });

  it('normalizes restored API Key viewer sessions to the key overview route', () => {
    expect(getRoleHomePath('api_key_viewer')).toBe('/key-overview');
    expect(shouldNormalizeRolePath('api_key_viewer', '/')).toBe(true);
    expect(shouldNormalizeRolePath('api_key_viewer', '/key-overview')).toBe(false);
    expect(shouldNormalizeRolePath('api_key_viewer', '/settings')).toBe(true);
    expect(shouldNormalizeRolePath('api_key_viewer', '/auth-files')).toBe(true);
  });

  it('limits embedded users to Overview and Analysis routes', () => {
    expect(getRoleHomePath('user')).toBe('/key-overview');
    expect(shouldNormalizeRolePath('user', '/key-overview')).toBe(false);
    expect(shouldNormalizeRolePath('user', '/key-analysis')).toBe(false);
    expect(shouldNormalizeRolePath('user', '/key-ranking')).toBe(true);
  });

  it('uses viewer_key_login instead of CPA integration capabilities', () => {
    expect(isViewerKeyLoginEnabled({
      authenticated: false,
      capabilities: {
        viewer_key_login: true,
        cpa_auth_files: false,
        cpa_quota: false,
      },
    })).toBe(true);
    expect(isViewerKeyLoginEnabled({
      authenticated: false,
      capabilities: {
        viewer_key_login: false,
        cpa_auth_files: true,
        cpa_quota: true,
      },
    })).toBe(false);
  });

  it('renders only the server-provided viewer label, never raw or canonical key material', () => {
    const markup = renderToStaticMarkup(createElement(
      I18nextProvider,
      { i18n },
      createElement(KeyViewerShell, {
        activePage: 'overview',
        apiKey: { display_key: 'Engineering •••• 1234' },
        toolbar: createElement('div'),
        onNavigate: () => undefined,
        children: createElement('div'),
      }),
    ));

    expect(markup).toContain('Engineering •••• 1234');
    expect(markup).not.toContain('sk-virtual');
    expect(markup).not.toContain('litellm:token-engineering');
  });

  it('does not render Ranking in a user shell', () => {
    const markup = renderToStaticMarkup(createElement(
      I18nextProvider,
      { i18n },
      createElement(KeyViewerShell, {
        role: 'user',
        activePage: 'overview',
        toolbar: createElement('div'),
        onNavigate: () => undefined,
        children: createElement('div'),
      }),
    ));

    expect(markup).toContain('Overview');
    expect(markup).toContain('Analysis');
    expect(markup).not.toContain('Ranking');
  });

  it('clears stale overview auth errors when the session is cleared', () => {
    expect(appSource).toContain("import { useUsageStatsStore } from './stores/useUsageStatsStore';");
    expect(appSource).toMatch(/const clearUsageStats = useUsageStatsStore\(\(state\) => state\.clearUsageStats\);/);
    expect(appSource).toMatch(/const clearSession = useCallback\(\(\) => \{[\s\S]*?clearUsageStats\(\);[\s\S]*?setAuthState\('unauthenticated'\);/);
  });

  it('mounts the shared footer from the app shell', () => {
    expect(appSource).toContain("import './App.css';");
    expect(appSource).toContain("import { AppFooter } from './components/AppFooter';");
    expect(appSource).toMatch(/<div className="app-frame"[^>]*>[\s\S]*<main className="app-main">\{page\}<\/main>[\s\S]*<AppFooter loadVersion=\{authState === 'authenticated'\} \/>[\s\S]*<\/div>/);
  });

  it('lets app pages fill the space above the shared footer', () => {
    expect(appStylesSource).toMatch(/\.app-main\s*\{[\s\S]*?display:\s*flex;/);
    expect(appStylesSource).toMatch(/\.app-main\s*\{[\s\S]*?flex-direction:\s*column;/);
  });
});
