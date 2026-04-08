import { defineConfig } from 'vite';

const base = '/crypto-lab-shadow-vault/';

export default defineConfig({
  base,
  build: {
    outDir: 'dist',
    target: 'esnext',
  },
});
