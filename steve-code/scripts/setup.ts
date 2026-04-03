#!/usr/bin/env bun
import { spawn } from 'child_process';
import { promisify } from 'util';
import { join } from 'path';
import { homedir } from 'os';
import { mkdir } from 'fs/promises';

const execAsync = promisify(exec);

const MODELS = [
  { name: 'qwen2.5-coder:14b', description: 'Primary coding model', size: '9.0 GB' },
  { name: 'llama3.1:8b', description: 'Fast responses', size: '4.9 GB' },
  { name: 'mistral:latest', description: 'Balanced', size: '4.4 GB' },
  { name: 'nomic-embed-text:latest', description: 'Embeddings (optional)', size: '274 MB' },
];

async function checkOllama(): Promise<boolean> {
  try {
    await execAsync('which ollama');
    return true;
  } catch {
    return false;
  }
}

async function pullModel(model: string): Promise<void> {
  return new Promise((resolve, reject) => {
    console.log(`📥 Pulling ${model}...`);
    const proc = spawn('ollama', ['pull', model], {
      stdio: 'inherit',
    });
    
    proc.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Failed to pull ${model}`));
    });
  });
}

async function setup() {
  console.log('🦊 Steve Code Setup\n');
  
  // Check Ollama
  console.log('Checking Ollama...');
  if (!await checkOllama()) {
    console.error('❌ Ollama not found. Please install it first:');
    console.error('   curl -fsSL https://ollama.com/install.sh | sh');
    process.exit(1);
  }
  console.log('✓ Ollama found\n');
  
  // Create config directory
  const configDir = join(homedir(), '.steve-code');
  await mkdir(configDir, { recursive: true });
  console.log('✓ Created ~/.steve-code directory\n');
  
  // Pull models
  console.log('Recommended Models:');
  MODELS.forEach(m => {
    console.log(`  • ${m.name} (${m.size}) - ${m.description}`);
  });
  console.log('\nPulling models (this may take a while)...\n');
  
  for (const model of MODELS) {
    try {
      await pullModel(model.name);
      console.log(`✓ ${model.name} ready\n`);
    } catch (error) {
      console.error(`⚠️ Failed to pull ${model.name}: ${error}`);
    }
  }
  
  console.log('\n🦊 Setup complete!');
  console.log('   Run: bun run start');
}

setup().catch(console.error);