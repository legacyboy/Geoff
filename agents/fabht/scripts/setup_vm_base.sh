#!/bin/bash
# FabHT - VM System Update and Chrome Installation
set -e

echo "[+] Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

echo "[+] Installing dependencies..."
sudo apt-get install -y wget gnupg curl

echo "[+] Installing Google Chrome..."
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt-get update
sudo apt-get install -y google-chrome-stable

echo "[+] Verifying installation..."
google-chrome --version

echo "[+] System and Chrome installation complete."
