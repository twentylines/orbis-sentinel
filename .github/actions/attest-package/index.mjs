import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const signerCommit = '1e69f48acb82d1966a394da916b4c1698aa569d6';

function inside(parent, child) {
  const value = relative(parent, child);
  return value !== '' && value !== '..' && !value.startsWith(`..${sep}`) && !isAbsolute(value);
}

export async function attest() {
  if (!process.env.GITHUB_WORKSPACE || !process.env.TMPDIR || !isAbsolute(process.env.TMPDIR)) {
    throw new Error('Package workspace paths are required');
  }
  const workspace = realpathSync(process.env.GITHUB_WORKSPACE);
  const temporary = realpathSync(process.env.TMPDIR);
  if (!inside(workspace, temporary) || !statSync(temporary).isDirectory()) {
    throw new Error('Signing temporary directory must be inside the workspace');
  }
  const signer = realpathSync(join(workspace, 'sentinel-package-work', 'tools', 'attest'));
  const entry = realpathSync(join(signer, 'dist', 'index.js'));
  if (!inside(workspace, signer) || !inside(signer, entry)) {
    throw new Error('Signing code must be inside the workspace');
  }
  if (readFileSync(join(signer, '.git', 'HEAD'), 'utf8').trim() !== signerCommit) {
    throw new Error('Signing code does not match the pinned revision');
  }
  process.env.RUNNER_TEMP = temporary;
  if (!inside(workspace, realpathSync(process.env.RUNNER_TEMP))) {
    throw new Error('Signing temporary directory could not be confined');
  }
  await import(pathToFileURL(entry).href);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  attest().catch(() => {
    console.error('Package signing failed before completion.');
    process.exitCode = 1;
  });
}
