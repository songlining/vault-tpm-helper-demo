#!/bin/bash

set -e

SSH_TARGET="lsong@vault-tpm-demo"

echo "=== Resetting Vault on Remote Server ==="

ssh $SSH_TARGET << 'EOF'
echo "Stopping Vault service..."
sudo systemctl stop vault || true

echo "Removing Vault data directory..."
sudo rm -rf /opt/vault/data/*

echo "Removing initialization file..."
rm -f /tmp/vault-init.json

echo "Starting Vault service..."
sudo systemctl start vault

echo "Vault reset complete. Run setup.sh to reinitialize."
EOF

echo "✓ Vault reset complete on $SSH_TARGET"