import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies /api (REST + WS) to the Python backend so you can
// iterate on the UI with only `npm run dev` + the backend running.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
  },
});
