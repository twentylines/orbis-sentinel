import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, existsSync, writeFileSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { signerCommit } from '../.github/actions/attest-package/index.mjs';

const launcher = fileURLToPath(new URL('../.github/actions/attest-package/index.mjs', import.meta.url));

function fixture(t) {
  assert.ok(process.env.TMPDIR, 'Use a project-scoped TMPDIR');
  const root = mkdtempSync(join(process.env.TMPDIR, 'sentinel-signing-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const workspace = join(root, 'workspace');
  const temporary = join(workspace, 'tmp');
  const outside = join(root, 'platform-temp');
  const signer = join(workspace, 'sentinel-package-work', 'tools', 'attest');
  mkdirSync(temporary, { recursive: true });
  mkdirSync(outside);
  mkdirSync(join(signer, '.git'), { recursive: true });
  mkdirSync(join(signer, 'dist'));
  writeFileSync(join(signer, 'package.json'), JSON.stringify({ type: 'commonjs' }));
  writeFileSync(join(signer, '.git', 'HEAD'), `${signerCommit}\n`);
  writeFileSync(join(signer, 'dist', 'index.js'), `require('fs').writeFileSync(require('path').join(process.env.RUNNER_TEMP, 'proof.json'), JSON.stringify({ temporary: process.env.RUNNER_TEMP, configured: process.env.TMPDIR }));`);
  const run = (overrides = {}) => spawnSync(process.execPath, [launcher], {
    encoding: 'utf8', timeout: 5000,
    env: { GITHUB_WORKSPACE: workspace, TMPDIR: temporary, RUNNER_TEMP: outside, ...overrides },
  });
  return { workspace, temporary, outside, signer, run };
}

test('delegated signing writes inside the project despite a platform temporary directory', (t) => {
  const f = fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  const proof = JSON.parse(readFileSync(join(f.temporary, 'proof.json')));
  assert.equal(proof.temporary, proof.configured);
  assert.equal(existsSync(join(f.outside, 'proof.json')), false);
});

test('an external or missing temporary directory cannot start the signer', (t) => {
  const f = fixture(t);
  for (const directory of [f.outside, join(f.workspace, 'missing')]) {
    const result = f.run({ TMPDIR: directory });
    assert.equal(result.status, 1);
    assert.equal(existsSync(join(f.temporary, 'proof.json')), false);
    assert.equal(existsSync(join(f.outside, 'proof.json')), false);
  }
});

test('a temporary-directory symlink cannot escape the workspace', (t) => {
  const f = fixture(t);
  const linked = join(f.workspace, 'linked');
  symlinkSync(f.outside, linked);
  assert.equal(f.run({ TMPDIR: linked }).status, 1);
  assert.equal(existsSync(join(f.outside, 'proof.json')), false);
});

test('a different signing revision cannot run', (t) => {
  const f = fixture(t);
  writeFileSync(join(f.signer, '.git', 'HEAD'), `${'0'.repeat(40)}\n`);
  assert.equal(f.run().status, 1);
  assert.equal(existsSync(join(f.temporary, 'proof.json')), false);
});

test('a signing entrypoint symlink cannot load other workspace code', (t) => {
  const f = fixture(t);
  const entry = join(f.signer, 'dist', 'index.js');
  const replacement = join(f.workspace, 'unexpected.js');
  writeFileSync(replacement, readFileSync(entry));
  rmSync(entry);
  symlinkSync(replacement, entry);
  assert.equal(f.run().status, 1);
  assert.equal(existsSync(join(f.temporary, 'proof.json')), false);
});
