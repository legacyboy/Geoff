
import express from 'express';
import { OllamaService } from './services/ollama';
import { spawn } from 'child_process';
import { join } from 'path';
import { mkdir } from 'fs/promises';
import multer from 'multer';
import cors from 'cors';
import fs from 'fs';

const app = express();
const port = 3000;
const ollama = new OllamaService();

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuration state
let config = {
  ollamaBaseUrl: 'http://localhost:11434',
  model: 'qwen2.5-coder:14b',
  evidenceLocation: join(process.cwd(), 'evidence'),
};

// File upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, config.evidenceLocation);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

// Ensure evidence directory exists
async function init() {
  try {
    await mkdir(config.evidenceLocation, { recursive: true });
    console.log(`Evidence directory ready: ${config.evidenceLocation}`);
  } catch (e) {
    console.error('Failed to create evidence directory', e);
  }
}
init();

// Endpoints
app.get('/api/config', (req, res) => res.json(config));

app.post('/api/config', (req, res) => {
  config = { ...config, ...req.body };
  if (req.body.ollamaBaseUrl) {
    ollama.baseUrl = req.body.ollamaBaseUrl; // Note: OllamaService.baseUrl is private, will fix in service
  }
  res.json({ success: true });
});

app.post('/api/chat', async (req, res) => {
  const { message, history } = req.body;
  
  res.setHeader('Content-Type', 'text/plain');
  
  try {
    const messages = [...history, { role: 'user', content: message }];
    const stream = ollama.chat({
      model: config.model,
      messages: messages,
    });

    for await (const chunk of stream) {
      res.write(chunk);
    }
    res.end();
  } catch (e: any) {
    res.status(500).send(`Error: ${e.message}`);
  }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  res.json({ 
    success: true, 
    filename: req.file.filename, 
    path: req.file.path 
  });
});

app.get('/api/models', async (req, res) => {
  try {
    const models = await ollama.listModels();
    res.json(models);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(port, () => {
  console.log(`🚀 Geoff Web UI running at http://localhost:${port}`);
});
