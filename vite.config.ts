import { defineConfig } from 'vite';

export default defineConfig({
  base: '/shadow-vault/',
  build: {
    outDir: 'out',
    target: 'esnext',
  },
});
