import Database from 'better-sqlite3';
import { mkdir } from 'fs/promises';
import { homedir } from 'os';
import { join } from 'path';
import type { Message } from '../types/index.js';

export interface Conversation {
  id: string;
  messages: Message[];
  model: string;
  timestamp: number;
}

export class Memory {
  private db: Database.Database;
  private dbPath: string;

  constructor(dbPath?: string) {
    this.dbPath = dbPath || join(homedir(), '.steve-code', 'memory.db');
    this.db = new Database(this.dbPath);
    this.init();
  }

  private init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        model TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        messages TEXT NOT NULL
      );
      
      CREATE INDEX IF NOT EXISTS idx_timestamp ON conversations(timestamp);
    `);
  }

  async ensureDir() {
    const dir = join(homedir(), '.steve-code');
    await mkdir(dir, { recursive: true });
  }

  saveConversation(conversation: Conversation) {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO conversations (id, model, timestamp, messages)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(
      conversation.id,
      conversation.model,
      conversation.timestamp,
      JSON.stringify(conversation.messages)
    );
  }

  getConversation(id: string): Conversation | null {
    const stmt = this.db.prepare('SELECT * FROM conversations WHERE id = ?');
    const row = stmt.get(id) as any;
    if (!row) return null;
    
    return {
      id: row.id,
      model: row.model,
      timestamp: row.timestamp,
      messages: JSON.parse(row.messages),
    };
  }

  getRecentConversations(limit: number = 10): Conversation[] {
    const stmt = this.db.prepare(`
      SELECT * FROM conversations 
      ORDER BY timestamp DESC 
      LIMIT ?
    `);
    const rows = stmt.all(limit) as any[];
    
    return rows.map(row => ({
      id: row.id,
      model: row.model,
      timestamp: row.timestamp,
      messages: JSON.parse(row.messages),
    }));
  }

  close() {
    this.db.close();
  }
}