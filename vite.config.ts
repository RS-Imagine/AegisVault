import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { defineConfig, Plugin } from 'vite';

/**
 * Injects deterministic build asset precache manifest and version hash into dist/sw.js
 * using relative paths ('./assets/...') so PWA offline startup works at both '/' and '/AegisVault/'.
 */
function aegisVaultPwaPlugin(): Plugin {
  let outDir = 'dist';
  return {
    name: 'aegis-vault-pwa-manifest-inject',
    configResolved(config) {
      outDir = config.build.outDir;
    },
    closeBundle() {
      const resolvedOutDir = path.resolve(process.cwd(), outDir);
      const swPath = path.join(resolvedOutDir, 'sw.js');
      if (!fs.existsSync(swPath)) return;

      const collectedRelativeAssets: string[] = [];
      const walk = (dir: string) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walk(fullPath);
          } else if (entry.isFile()) {
            const rel = path
              .relative(resolvedOutDir, fullPath)
              .split(path.sep)
              .join('/');
            if (rel === 'sw.js') continue;
            if (
              /\.(?:js|css|html|woff2?|svg|png|ico|webmanifest)$/i.test(rel)
            ) {
              collectedRelativeAssets.push(`./${rel}`);
            }
          }
        }
      };

      walk(resolvedOutDir);

      const hash = crypto
        .createHash('sha256')
        .update(collectedRelativeAssets.sort().join('|'))
        .digest('hex')
        .slice(0, 12);

      let swContent = fs.readFileSync(swPath, 'utf-8');
      swContent = swContent.replace('__AEGIS_SW_VERSION__', `v2-${hash}`);
      swContent = swContent.replace(
        '/* __AEGIS_PRECACHE_MANIFEST__ */',
        collectedRelativeAssets.map((a) => JSON.stringify(a)).join(',\n  ')
      );
      fs.writeFileSync(swPath, swContent, 'utf-8');
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss(), aegisVaultPwaPlugin()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  server: {
    hmr: process.env.DISABLE_HMR !== 'true',
  },
});
