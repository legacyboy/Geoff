#!/usr/bin/env bash
# Install script for systemd service and run it
SERVICE_FILE="/home/claw/.openclaw/workspace/systemd/trading-bot-web.service"
DEST_DIR="$HOME/.config/systemd/user/"
mkdir -p $DEST_DIR
cp "$SERVICE_FILE" $DEST_DIR/
systemctl --user daemon-reload
systemctl --user enable trading-bot-web.service
systemctl --user start trading-bot-web.service
systemctl --user status trading-bot-web.service