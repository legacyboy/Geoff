from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import json
import os
import shutil
import asyncio
import httpx
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()

# Enable CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SETTINGS_FILE = "settings.json"
UPLOAD_DIR = "uploads"

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

class ChatRequest(BaseModel):
    message: str
    attachments: List[str]

class SettingsRequest(BaseModel):
    ollamaUrl: str
    ollamaModel: str
    evidencePath: str

@app.get("/api/settings")
async def get_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"ollamaUrl": "http://127.0.0.1:11434", "ollamaModel": "deepseek-v3", "evidencePath": os.path.expanduser("~/.geoff/evidence")}

@app.post("/api/settings")
async def save_settings(settings: SettingsRequest):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings.dict(), f)
    return {"status": "success"}

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"filename": file.filename, "status": "uploaded"}

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "agent": "Geoff"}

@app.post("/api/chat")
async def chat(request: ChatRequest):
    # Load settings for the model and URL
    settings = {"ollamaUrl": "http://127.0.0.1:11434", "ollamaModel": "deepseek-v3"}
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            settings = json.load(f)
    
    url = settings.get("ollamaUrl", "http://127.0.0.1:11434")
    model = settings.get("ollamaModel", "deepseek-v3")
    
    # We attempt to call Ollama directly for the UI interaction
    # In a full integration, this would go through the OpenClaw Gateway / ACP
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are Geoff, a helpful AI assistant. You have access to uploaded evidence files if mentioned."},
                    {"role": "user", "content": f"{request.message}\n\nAttached files: {', '.join(request.attachments) if request.attachments else 'None'}"}
                ],
                "stream": False
            }
            response = await client.post(f"{url}/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            return {"reply": data.get("message", {}).get("content", "I processed that, but couldn't generate a text response.")}
    except Exception as e:
        return {"reply": f"Error connecting to LLM: {str(e)}"}

# Serve React static files (assuming they are built into /dist)
# Use a try-except or check for directory to avoid startup crash if not built yet
if os.path.exists("dist"):
    app.mount("/", StaticFiles(directory="dist", html=True), name="static")
else:
    @app.get("/{path:path}")
    async def serve_placeholder(path: str):
        return {"error": "Frontend build not found. Please build the React app to the 'dist' folder."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
