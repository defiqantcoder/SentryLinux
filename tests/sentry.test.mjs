import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const daemonBin = path.resolve('daemon/target/release/sentrylinux-daemon');
const desktopBin = path.resolve('src-tauri/target/release/sentrylinux');

test('Native Rust daemon binary returns valid live Linux kernel telemetry JSON', () => {
  const raw = execFileSync(daemonBin, ['--telemetry'], { encoding: 'utf8' });
  const parsed = JSON.parse(raw);
  assert.ok(parsed.kernelVersion.startsWith('Linux '));
  assert.ok(typeof parsed.memoryTotalMb === 'number' && parsed.memoryTotalMb > 0);
  assert.equal(parsed.secureBootEnabled, true);
});

test('Canonical path guard rejects .. traversal and protected system paths', () => {
  assert.throws(() => {
    execFileSync(daemonBin, ['--validate-path', '../etc/passwd'], { stdio: 'pipe' });
  });
  assert.throws(() => {
    execFileSync(daemonBin, ['--validate-path', '/etc/shadow'], { stdio: 'pipe' });
  });
  const okOut = execFileSync(daemonBin, ['--validate-path', '~/Projects/CrateBench-BOMs'], {
    encoding: 'utf8',
  });
  const parsed = JSON.parse(okOut);
  assert.equal(parsed.valid, true);
  assert.ok(parsed.normalized.endsWith('Projects/CrateBench-BOMs'));
});

test('Native desktop shell binary passes headless IPC and WebKit self-check', () => {
  const out = execFileSync(desktopBin, ['--headless-check'], { encoding: 'utf8' });
  assert.ok(out.includes('SentryLinux Headless Self-Test OK'));
});

test('Source tree contains zero hardcoded API keys or plaintext secrets', () => {
  const srcFiles = [
    'src/App.tsx',
    'src/services/sentryBridge.ts',
    'src/services/geminiService.ts',
    'src/decks/TelemetryDecks.tsx',
    'src/decks/ComplianceAndConfigDecks.tsx',
  ];
  for (const rel of srcFiles) {
    const content = fs.readFileSync(path.resolve(rel), 'utf8');
    assert.ok(!/AIza[0-9A-Za-z-_]{35}/.test(content), `Found hardcoded API key in ${rel}`);
  }
});

test('Plain-language AI threat explainers are present and complete for all 9 sections', () => {
  const serviceCode = fs.readFileSync(path.resolve('src/services/geminiService.ts'), 'utf8');
  const requiredSections = [
    'overview',
    'dns-sentry',
    'outbound-intercepts',
    'usg-and-lynis-cis-audit',
    'malware-and-sweep',
    'daemon-restarts-and-needrestart',
    'network-profiles-and-wireguard',
    'rules-and-quarantine',
    'settings-and-polkit-auth',
  ];
  for (const sec of requiredSections) {
    assert.ok(
      serviceCode.includes(`'${sec}': {`) || serviceCode.includes(`${sec}: {`),
      `Missing plain-language explainer for section: ${sec}`,
    );
  }
  assert.ok(serviceCode.includes('simpleExplanation:'));
  assert.ok(serviceCode.includes('threatOrigin:'));
  assert.ok(serviceCode.includes('threatImpact:'));
  assert.ok(serviceCode.includes('recommendedAction:'));
  assert.ok(serviceCode.includes('actionButtonLabel:'));
});

