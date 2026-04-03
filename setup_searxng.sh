#!/bin/bash
# Setup SearxNG locally without Docker

cd /home/claw/.openclaw/workspace

# Create virtual environment
python3 -m venv searxng-venv
source searxng-venv/bin/activate

# Install SearxNG dependencies
pip install --upgrade pip
pip install -r searxng-install/requirements.txt

# Create minimal settings
cat > searxng-install/searx/settings.yml << 'EOF'
use_default_settings: true

server:
  bind_address: "127.0.0.1"
  port: 8888
  secret_key: "ultrasecretkey123456789"
  
search:
  safe_search: 0
  autocomplete: ""
  default_lang: ""
  formats:
    - html
    - json

engines:
  - name: duckduckgo
    engine: duckduckgo
    shortcut: ddg
    disabled: false
    
  - name: bing
    engine: bing
    shortcut: bi
    disabled: false
    
  - name: brave
    engine: brave
    shortcut: br
    disabled: false
    
  - name: google
    engine: google
    shortcut: go
    disabled: false
    
  - name: yahoo
    engine: yahoo
    shortcut: yh
    disabled: false
    
  - name: startpage
    engine: startpage
    shortcut: sp
    disabled: false

ui:
  static_path: ""
  templates_path: ""
  default_theme: simple
  default_locale: en

# Limit results for faster response
outgoing:
  request_timeout: 10.0
  max_request_timeout: 15.0
  pool_connections: 100
  pool_maxsize: 100
  enable_http2: true
EOF

echo "SearxNG setup complete!"
echo "To start: source searxng-venv/bin/activate && cd searxng-install && python -m searx.webapp"
