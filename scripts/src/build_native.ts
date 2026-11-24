// Builds the l3x-native addon (native/) and installs it where scripts/src/native.ts loads it.
// (It imports nothing that loads the addon.)
import { execFileSync } from 'node:child_process';
import { copyFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = join(resolve(dirname(fileURLToPath(import.meta.url)), '../..'), 'native');
execFileSync('cargo', ['build', '--release'], { cwd: dir, stdio: 'inherit' });
const lib = process.platform === 'darwin' ? 'libl3x_native.dylib' : 'libl3x_native.so';
copyFileSync(join(dir, 'target', 'release', lib), join(dir, 'l3x_native.node'));
console.log(`installed ${join(dir, 'l3x_native.node')}`);
