#!/bin/bash
# Redirect — the canonical installer is now at the repo root: install.sh
# This file is kept for backwards compatibility only.
echo "NOTE: installer/install.sh is deprecated. Use install.sh from the repo root."
echo "      curl -fsSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash"
echo ""
exec "$(dirname "$0")/../install.sh" "$@"