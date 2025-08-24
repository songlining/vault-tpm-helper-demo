#!/bin/bash

set -e

DEFAULT_USERNAME="lsong"
DEFAULT_HOSTNAME="vault-tpm-demo"

USE_DEFAULTS=false

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --defaults    Use default values ($DEFAULT_USERNAME@$DEFAULT_HOSTNAME)"
    echo "  -h, --help        Show this help message"
    echo ""
    exit 0
fi

if [[ "$1" == "--defaults" || "$1" == "-d" ]]; then
    USE_DEFAULTS=true
fi

echo "=== Vault TPM Helper Demo Setup Test ==="
echo "This is a test version that verifies connectivity and basic setup"
echo

if [[ "$USE_DEFAULTS" == "true" ]]; then
    USERNAME="$DEFAULT_USERNAME"
    HOSTNAME="$DEFAULT_HOSTNAME"
    echo "Using defaults: $USERNAME@$HOSTNAME"
else
    read -p "Enter SSH username (default: $DEFAULT_USERNAME): " USERNAME
    USERNAME=${USERNAME:-$DEFAULT_USERNAME}

    read -p "Enter SSH hostname (default: $DEFAULT_HOSTNAME): " HOSTNAME
    HOSTNAME=${HOSTNAME:-$DEFAULT_HOSTNAME}
fi

SSH_TARGET="${USERNAME}@${HOSTNAME}"

echo "Testing connection to: $SSH_TARGET"
echo

if ! ssh -o ConnectTimeout=5 -o BatchMode=yes $SSH_TARGET exit 2>/dev/null; then
    echo "ERROR: Cannot connect to $SSH_TARGET via SSH"
    echo "Please ensure:"
    echo "  - SSH keys are configured"
    echo "  - Server is accessible"
    echo "  - Username and hostname are correct"
    exit 1
fi

echo "✓ SSH connection verified"

echo "Testing basic commands on remote server..."
ssh $SSH_TARGET "echo '✓ Remote command execution works'"
ssh $SSH_TARGET "uname -a"
ssh $SSH_TARGET "which tpm2_getcap || echo 'TPM2 tools not yet installed'"
ssh $SSH_TARGET "which vault || echo 'Vault not yet installed'"

echo
echo "=== Connection Test Complete ==="
echo "Server: $SSH_TARGET is ready for full setup"
echo "Run './setup.sh --defaults' to perform the complete installation"