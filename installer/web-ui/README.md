# Installation and Setup for Geoff Web UI

## Frontend
The frontend is a React application using Tailwind CSS and Lucide-React.

### Run Development Server
1. `cd /home/claw/.openclaw/workspace/geoff-installer/web-ui`
2. `npm install`
3. `npm run dev`

## Backend
The backend is a FastAPI server that handles chat requests, file uploads, and settings.

### Run Backend
1. `cd /home/claw/.openclaw/workspace/geoff-installer/web-ui/backend`
2. `pip install fastapi uvicorn pydantic python-multipart`
3. `python main.py`

## Integration
- The frontend communicates with the backend via `/api` endpoints.
- In production, build the frontend (`npm run build`) and let the FastAPI server serve the `dist` folder.
