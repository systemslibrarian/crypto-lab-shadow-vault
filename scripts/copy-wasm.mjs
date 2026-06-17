// Copy the wasm-pack output into public/ so Vite can serve it.
// Cross-platform (works in PowerShell, cmd, bash, and Linux CI) and
// dependency-free — replaces a shell-specific `cp`/`copy` invocation.
import { copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
for (const file of ['shadow_vault_crypto_bg.wasm', 'shadow_vault_crypto.js']) {
  copyFileSync(join(root, 'pkg', file), join(root, 'public', file));
}
