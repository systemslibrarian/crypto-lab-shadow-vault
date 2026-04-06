import { defineConfig } from 'vite';

const repoName = process.env.GITHUB_PAGES_REPO_NAME?.trim();
const base = repoName ? `/${repoName}/` : '/';

export default defineConfig({
  base,
  build: {
    outDir: 'out',
    target: 'esnext',
  },
});
