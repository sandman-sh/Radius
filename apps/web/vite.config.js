import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '../..', '');
  return {
    envDir: '../..',
    plugins: [react()],
    server: {
      port: Number(env.RADIUS_WEB_PORT || 5174),
      proxy: {
        '/api': `http://localhost:${env.RADIUS_API_PORT || 4100}`
      }
    }
  };
});
