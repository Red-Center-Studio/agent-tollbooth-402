import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@redcenterstudio/agent-tollbooth-edge': path.resolve(
        __dirname,
        'packages/edge-middleware/src/index.ts',
      ),
    },
  },
  test: {
    environment: 'node',
    include: ['packages/**/test/**/*.test.ts'],
  },
});
