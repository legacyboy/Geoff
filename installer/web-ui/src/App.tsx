import React, { useState, useEffect, useRef } from 'react';
import { 
  Send, 
  Paperclip, 
  Mic, 
  Settings, 
  X,
  AlertCircle
} from 'lucide-react';

// --- Types ---
interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
}

interface Attachment {
  id: string;
  file: File;
  preview: string;
}

interface Config {
  cloudOllamaUrl: string;
  evidenceLocation: string;
  model: string;
}

const API_BASE = '/api';

// --- Components ---

const ChatBubble = ({ message }: { message: Message }) => {
  const isUser = message.role === 'user';
  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-4`}>
      <div className={`max-w-[80%] rounded-2xl px-4 py-2 ${
        isUser ? 'bg-indigo-600 text-white rounded-tr-none' : 'bg-gray-200 text-gray-800 rounded-tl-none'
      }`}>
        <div className="text-sm whitespace-pre-wrap">{message.content}</div>
        <div className={`text-[10px] mt-1 opacity-70 ${isUser ? 'text-right' : 'text-left'}`}>
          {new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </div>
      </div>
    </div>
  );
};

export default function GeoffUI() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [config, setConfig] = useState<Config>({
    cloudOllamaUrl: '',
    evidenceLocation: '',
    model: 'deepseek-v3',
  });
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  async function loadSettings() {
    try {
      const response = await fetch(`${API_BASE}/settings`);
      if (response.ok) {
        const data = await response.json();
        setConfig({
          cloudOllamaUrl: data.ollamaUrl || '',
          evidenceLocation: data.evidencePath || '',
          model: data.ollamaModel || 'deepseek-v3',
        });
      }
    } catch (e) {
      console.error('Failed to load settings', e);
    }
  }

  const handleSend = async () => {
    if (!input.trim() && attachments.length === 0) return;

    const userMsg: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input,
      timestamp: Date.now(),
    };

    setMessages(prev => [...prev, userMsg]);
    const currentInput = input;
    const currentAttachments = [...attachments];
    setInput('');
    setAttachments([]);

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          message: currentInput,
          attachments: currentAttachments.map(a => a.file.name) 
        })
      });
      const data = await response.json();
      
      const geoffMsg: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: data.reply || 'I encountered an error processing that.',
        timestamp: Date.now(),
      };
      setMessages(prev => [...prev, geoffMsg]);
    } catch (e) {
      const errorMsg: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: 'Connection Error: I cannot reach the backend logic right now.',
        timestamp: Date.now(),
      };
      setMessages(prev => [...prev, errorMsg]);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      const newAttachments = files.map(file => ({
        id: Math.random().toString(36).substr(2, 9),
        file,
        preview: URL.createObjectURL(file),
      }));
      setAttachments(prev => [...prev, ...newAttachments]);

      // Upload files immediately to backend
      for (const file of files) {
        const formData = new FormData();
        formData.append('file', file);
        try {
          await fetch(`${API_BASE}/upload`, { method: 'POST', body: formData });
        } catch (e) {
          console.error(`Upload failed for ${file.name}`, e);
        }
      }
    }
  };

  const removeAttachment = (id: string) => {
    setAttachments(prev => prev.filter(a => a.id !== id));
  };

  const saveSettings = async () => {
    try {
      const response = await fetch(`${API_BASE}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ollamaUrl: config.cloudOllamaUrl,
          ollamaModel: config.model,
          evidencePath: config.evidenceLocation,
        })
      });
      if (response.ok) {
        alert('Settings saved successfully!');
        setIsConfigOpen(false);
      }
    } catch (e) {
      alert('Error saving settings.');
    }
  };

  return (
    <div className="flex h-screen bg-gray-50 text-gray-900 font-sans overflow-hidden">
      <div className="flex-1 flex flex-col relative">
        <header className="h-16 border-b bg-white flex items-center justify-between px-6 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-indigo-600 rounded-full flex items-center justify-center text-white font-bold">G</div>
            <h1 className="font-semibold text-lg">Geoff</h1>
          </div>
          <button 
            onClick={() => setIsConfigOpen(!isConfigOpen)}
            className="p-2 hover:bg-gray-100 rounded-full transition-colors"
          >
            <Settings size={20} className="text-gray-600" />
          </button>
        </header>

        <div 
          ref={scrollRef}
          className="flex-1 overflow-y-auto p-6 space-y-4"
        >
          {messages.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-center text-gray-400">
              <div className="w-16 h-16 bg-gray-200 rounded-full mb-4 flex items-center justify-center">
                <AlertCircle size={32} />
              </div>
              <p>Start a conversation with Geoff.<br/>Upload evidence or ask questions.</p>
            </div>
          )}
          {messages.map(msg => <ChatBubble key={msg.id} message={msg} />)}
        </div>

        <div className="p-4 bg-white border-t shrink-0">
          <div className="max-w-4xl mx-auto">
            {attachments.length > 0 && (
              <div className="flex gap-2 mb-3 overflow-x-auto py-2">
                {attachments.map(att => (
                  <div key={att.id} className="relative group w-16 h-16 bg-gray-100 rounded-lg overflow-hidden border">
                    <img src={att.preview} className="w-full h-full object-cover" alt="preview" />
                    <button 
                      onClick={() => removeAttachment(att.id)}
                      className="absolute top-0 right-0 bg-red-500 text-white p-0.5 rounded-bl-lg opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <X size={12} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="flex items-end gap-2 bg-gray-100 rounded-2xl p-2 border focus-within:border-indigo-400 transition-all">
              <div className="flex gap-1 pb-1">
                <button 
                  onClick={() => document.getElementById('file-upload')?.click()}
                  className="p-2 hover:bg-gray-200 rounded-xl text-gray-600 transition-colors"
                  title="Upload Evidence"
                >
                  <Paperclip size={20} />
                </button>
                <button className="p-2 hover:bg-gray-200 rounded-xl text-gray-600 transition-colors">
                  <Mic size={20} />
                </button>
              </div>
              
              <textarea 
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
                placeholder="Message Geoff..."
                className="flex-1 bg-transparent border-none focus:ring-0 py-2 px-2 resize-none max-h-32"
                rows={1}
              />
              
              <button 
                onClick={handleSend}
                disabled={!input.trim() && attachments.length === 0}
                className="p-2 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 disabled:bg-gray-300 transition-all"
              >
                <Send size={20} />
              </button>
            </div>
            <input 
              id="file-upload" 
              type="file" 
              multiple 
              className="hidden" 
              onChange={handleFileChange} 
            />
          </div>
        </div>

        {isConfigOpen && (
          <div className="absolute inset-0 bg-black/20 backdrop-blur-sm z-10 flex justify-end">
            <div className="w-full max-w-md bg-white h-full shadow-2xl p-6 overflow-y-auto animate-in slide-in-from-right">
              <div className="flex items-center justify-between mb-8">
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <Settings size={24} /> Configuration
                </h2>
                <button onClick={() => setIsConfigOpen(false)} className="p-2 hover:bg-gray-100 rounded-full">
                  <X size={20} />
                </button>
              </div>

              <div className="space-y-6">
                <section>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Cloud Ollama URL</label>
                  <input 
                    type="text" 
                    value={config.cloudOllamaUrl} 
                    onChange={e => setConfig({...config, cloudOllamaUrl: e.target.value})}
                    className="w-full p-2 border rounded-lg bg-gray-50 focus:ring-2 focus:ring-indigo-500 outline-none" 
                  />
                  <p className="text-xs text-gray-500 mt-1">The endpoint for the hosted LLM service.</p>
                </section>

                <section>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Evidence Location</label>
                  <input 
                    type="text" 
                    value={config.evidenceLocation} 
                    onChange={e => setConfig({...config, evidenceLocation: e.target.value})}
                    className="w-full p-2 border rounded-lg bg-gray-50 focus:ring-2 focus:ring-indigo-500 outline-none" 
                  />
                  <p className="text-xs text-gray-500 mt-1">Path where Geoff looks for reference files.</p>
                </section>

                <section>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Active Model</label>
                  <select 
                    value={config.model} 
                    onChange={e => setConfig({...config, model: e.target.value})}
                    className="w-full p-2 border rounded-lg bg-gray-50 focus:ring-2 focus:ring-indigo-500 outline-none"
                  >
                    <option value="deepseek-v3">DeepSeek V3 (Cloud)</option>
                    <option value="gemma4">Gemma 4 (Cloud)</option>
                    <option value="llama3.1">Llama 3.1 (Local)</option>
                    <option value="phi3">Phi-3 (Local)</option>
                  </select>
                </section>

                <button 
                  onClick={saveSettings}
                  className="w-full py-3 bg-indigo-600 text-white rounded-xl font-semibold hover:bg-indigo-700 transition-colors"
                >
                  Save Settings
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
