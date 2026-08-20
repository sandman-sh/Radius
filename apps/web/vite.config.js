import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const rootDir = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, rootDir, '');
  const apiPort = env.RADIUS_API_PORT || env.PORT || '4102';
  const webPort = Number(env.RADIUS_WEB_PORT || 5174);

  return {
    root: fileURLToPath(new URL('.', import.meta.url)),
    envDir: rootDir,
    plugins: [react()],
    server: {
      port: webPort,
      proxy: {
        '/api': {
          target: `http://localhost:${apiPort}`,
          changeOrigin: true
        }
      }
    }
  };
});
