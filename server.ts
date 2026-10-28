import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { scanWebsiteInSandbox, sanitizeErrorMessage } from './src/utils/sandboxScanner';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;
  const isProduction = process.env.NODE_ENV === 'production';

  app.use(express.json());

  // API endpoint for live sandbox scan
  app.post('/api/sandbox-scan', async (req: Request, res: Response) => {
    try {
      const { url } = req.body;
      if (!url || typeof url !== 'string' || !url.trim()) {
        res.status(400).json({ error: 'Please provide a valid website URL to scan.' });
        return;
      }

      const scanResult = await scanWebsiteInSandbox(url);
      res.json(scanResult);
    } catch (err: unknown) {
      const rawMessage = err instanceof Error ? err.message : 'An error occurred during sandbox scanning.';
      const sanitized = sanitizeErrorMessage(rawMessage);
      res.status(400).json({ error: sanitized });
    }
  });

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', engine: 'ScamLens Live Sandbox Engine' });
  });

  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ScamLens server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
