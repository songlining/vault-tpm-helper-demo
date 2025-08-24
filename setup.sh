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

echo "=== Vault TPM Helper Demo Setup ==="
echo "This script will configure a remote Ubuntu 24 server for TPM-based Vault authentication"
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

echo "Setting up TPM Vault demo on: $SSH_TARGET"
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

REMOTE_SETUP_DIR="/tmp/vault-tpm-setup"

echo "Creating remote setup directory..."
ssh $SSH_TARGET "mkdir -p $REMOTE_SETUP_DIR"

echo "Copying setup files to remote server..."
cat > /tmp/remote_setup.sh << 'EOF'
#!/bin/bash

set -e

echo "=== Remote Server Setup Started ==="

echo "Updating package lists..."
sudo apt-get update -y

echo "Installing required packages..."
sudo apt-get install -y \
    wget \
    curl \
    unzip \
    openssl \
    jq \
    tpm2-tools \
    tpm2-openssl \
    libtss2-dev

echo "✓ All packages installed using simplified Ubuntu package approach"

echo "Adding user to tss group for TPM device access..."
USERNAME=$(whoami)

# Create tss group if it doesn't exist
if ! grep -q "^tss:" /etc/group; then
    echo "Creating tss group..."
    sudo groupadd tss
fi

sudo usermod -a -G tss $USERNAME
echo "✓ User $USERNAME added to tss group (will take effect on next login)"

echo "Configuring OpenSSL for TPM2 provider..."
OPENSSL_CONF="/etc/ssl/openssl.cnf"
sudo cp "$OPENSSL_CONF" "${OPENSSL_CONF}.backup"

if ! grep -q "openssl_conf = openssl_init" "$OPENSSL_CONF"; then
    echo "Adding OpenSSL configuration for TPM2..."
    
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        MODULE_PATH="/usr/lib/aarch64-linux-gnu/ossl-modules/tpm2.so"
    else
        MODULE_PATH="/usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so"
    fi
    
    sudo tee -a "$OPENSSL_CONF" > /dev/null << OPENSSL_EOF

# TPM2 Provider Configuration
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
tpm2 = tpm2_sect

[default_sect]
activate = 1

[tpm2_sect]
activate = 1
module = $MODULE_PATH
OPENSSL_EOF
fi

echo "Installing Hashicorp Vault..."
if ! command -v vault &> /dev/null; then
    wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
    sudo apt-get update -y
    sudo apt-get install -y vault
fi

echo "Creating Vault configuration..."
sudo mkdir -p /etc/vault.d
sudo tee /etc/vault.d/vault.hcl > /dev/null << VAULT_EOF
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = false
  tls_cert_file = "/etc/vault.d/vault-cert.pem"
  tls_key_file = "/etc/vault.d/vault-key.pem"
}

api_addr = "https://0.0.0.0:8200"
cluster_addr = "https://0.0.0.0:8201"
ui = true
VAULT_EOF

echo "Creating self-signed certificate for Vault with proper SANs..."
sudo mkdir -p /opt/vault/data
sudo chown vault:vault /opt/vault/data

if [ ! -f "/etc/vault.d/vault-cert.pem" ]; then
    # Get the server's IP address for SAN
    SERVER_IP=$(hostname -I | awk '{print $1}')
    sudo openssl req -x509 -newkey rsa:4096 \
        -keyout /etc/vault.d/vault-key.pem \
        -out /etc/vault.d/vault-cert.pem \
        -days 365 -nodes \
        -subj "/C=US/ST=CA/L=SF/O=Demo/CN=vault-tpm-demo" \
        -addext "subjectAltName=DNS:vault-tpm-demo,DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}"
    sudo chown vault:vault /etc/vault.d/vault-*.pem
    sudo chmod 600 /etc/vault.d/vault-key.pem
fi

echo "Creating Vault systemd service..."
sudo tee /etc/systemd/system/vault.service > /dev/null << SYSTEMD_EOF
[Unit]
Description=Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

echo "Starting Vault service..."
sudo systemctl daemon-reload
sudo systemctl enable vault
sudo systemctl start vault

sleep 5

echo "Initializing Vault..."
export VAULT_ADDR="https://localhost:8200"
export VAULT_SKIP_VERIFY=1

# Wait for Vault to be ready
echo "Waiting for Vault to start..."
for i in {1..30}; do
    if vault status >/dev/null 2>&1; then
        break
    fi
    echo "Waiting for Vault to start... ($i/30)"
    sleep 2
done

# Check if Vault is already initialized and unsealed
VAULT_STATUS=$(vault status -format=json 2>/dev/null || echo '{}')
IS_INITIALIZED=$(echo "$VAULT_STATUS" | jq -r '.initialized // false')
IS_SEALED=$(echo "$VAULT_STATUS" | jq -r '.sealed // true')

echo "Vault status: initialized=$IS_INITIALIZED, sealed=$IS_SEALED"

if [[ "$IS_INITIALIZED" == "true" && "$IS_SEALED" == "false" ]]; then
    echo "✓ Vault is already initialized and unsealed"
    
    # Try to get the root token from existing file
    if [ -f "/tmp/vault-init.json" ]; then
        ROOT_TOKEN=$(cat /tmp/vault-init.json | jq -r '.root_token')
        echo "Using existing root token"
    else
        echo "WARNING: Vault is unsealed but no init file found."
        echo "You may need to provide the root token manually or reset Vault"
        ROOT_TOKEN=""
    fi
    
elif [[ "$IS_INITIALIZED" == "true" && "$IS_SEALED" == "true" ]]; then
    echo "Vault is initialized but sealed. Attempting to unseal..."
    
    if [ ! -f "/tmp/vault-init.json" ]; then
        echo "ERROR: Vault is sealed but no init file found. Cannot unseal automatically."
        echo "Please provide the unseal keys manually or reset Vault data"
        exit 1
    fi
    
    # Get unseal keys and attempt unsealing
    UNSEAL_KEYS=$(cat /tmp/vault-init.json | jq -r '.unseal_keys_b64[]')
    THRESHOLD=$(echo "$VAULT_STATUS" | jq -r '.t // 3')
    ROOT_TOKEN=$(cat /tmp/vault-init.json | jq -r '.root_token')
    
    echo "Unsealing Vault (threshold: $THRESHOLD)..."
    COUNT=0
    for key in $UNSEAL_KEYS; do
        if [ $COUNT -ge $THRESHOLD ]; then
            break
        fi
        echo "Using unseal key $((COUNT + 1))..."
        vault operator unseal "$key"
        COUNT=$((COUNT + 1))
    done
    
else
    echo "Vault is not initialized. Initializing..."
    if [ -f "/tmp/vault-init.json" ]; then
        echo "Removing old init file..."
        rm -f /tmp/vault-init.json
    fi
    
    # Initialize with 5 shares, threshold of 3
    vault operator init -key-shares=5 -key-threshold=3 -format=json > /tmp/vault-init.json
    echo "Vault initialized. Keys saved to /tmp/vault-init.json"
    
    # Extract unseal keys and root token
    ROOT_TOKEN=$(cat /tmp/vault-init.json | jq -r '.root_token')
    
    echo "Unsealing newly initialized Vault..."
    UNSEAL_KEY1=$(cat /tmp/vault-init.json | jq -r '.unseal_keys_b64[0]')
    UNSEAL_KEY2=$(cat /tmp/vault-init.json | jq -r '.unseal_keys_b64[1]')
    UNSEAL_KEY3=$(cat /tmp/vault-init.json | jq -r '.unseal_keys_b64[2]')
    
    vault operator unseal "$UNSEAL_KEY1"
    vault operator unseal "$UNSEAL_KEY2"  
    vault operator unseal "$UNSEAL_KEY3"
fi

# Final verification - use text parsing as JSON seems unreliable
echo "Checking final Vault status..."
if vault status | grep -q "Sealed.*false"; then
    echo "✓ Vault is successfully unsealed and ready"
    vault status
elif vault status | grep -q "Sealed.*true"; then
    echo "ERROR: Vault is still sealed"
    vault status
    exit 1
else
    echo "WARNING: Could not determine Vault seal status"
    vault status
    # Continue anyway as Vault might be responding
fi

echo "Configuring Vault authentication..."
export VAULT_TOKEN="$ROOT_TOKEN"

echo "Enabling PKI secrets engine..."
if ! vault secrets list | grep -q "^pki/"; then
    vault secrets enable pki
    echo "PKI secrets engine enabled"
else
    echo "PKI secrets engine already enabled"
fi

echo "Enabling KV v2 secrets engine..."
if ! vault secrets list | grep -q "^secret/"; then
    vault secrets enable -path=secret kv-v2
    echo "KV v2 secrets engine enabled at secret/"
else
    echo "KV v2 secrets engine already enabled at secret/"
fi

echo "Creating sample KV data for testing..."
vault kv put secret/demo/app \
    username="demo-user" \
    password="demo-password" \
    api_key="abc123xyz789" \
    database_url="postgresql://user:pass@localhost:5432/myapp"

vault kv put secret/demo/config \
    environment="development" \
    debug="true" \
    max_connections="100"

vault kv put secret/myapp/credentials \
    service_account="myapp-service" \
    token="myapp-secret-token-123" \
    refresh_token="refresh-abc-xyz-789"

echo "✓ Sample data created:"
echo "  - secret/demo/app (application credentials)"
echo "  - secret/demo/config (configuration settings)"
echo "  - secret/myapp/credentials (app-specific secrets)"

echo "Verifying KV access with TPM certificate authentication..."
echo "Test commands you can run after TPM authentication:"
echo "  vault kv list secret/"
echo "  vault kv get secret/demo/app"
echo "  vault kv get secret/demo/config"
echo "  vault kv get secret/myapp/credentials"
vault secrets tune -max-lease-ttl=8760h pki

echo "Configuring PKI root CA..."
vault write pki/root/generate/internal \
    common_name="Demo Root CA" \
    ttl=8760h

vault write pki/config/urls \
    issuing_certificates="https://localhost:8200/v1/pki/ca" \
    crl_distribution_points="https://localhost:8200/v1/pki/crl"

echo "Creating PKI role for client certificates..."
vault write pki/roles/client-cert \
    allowed_domains="demo.local" \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl="72h" \
    generate_lease=true \
    key_type="any" \
    key_bits=256

echo "Enabling TLS certificate authentication..."
if ! vault auth list | grep -q "^cert/"; then
    vault auth enable cert
    echo "TLS cert auth method enabled"
else
    echo "TLS cert auth method already enabled"
fi

echo "Creating KV secrets policy for TPM certificate authentication..."
vault policy write kv-policy - << 'POLICY_EOF'
# Allow listing the secret/ mount point and its subdirectories
path "secret/" {
  capabilities = ["list"]
}

path "secret/*" {
  capabilities = ["list"]
}

# Allow full access to KV v2 metadata (required for listing and operations)
path "secret/metadata/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow full access to KV v2 data
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Allow access to sys/mounts for KV engine discovery
path "sys/mounts" {
  capabilities = ["read"]
}

# Allow access to sys/internal/ui/mounts for UI functionality  
path "sys/internal/ui/mounts/*" {
  capabilities = ["read"]
}
POLICY_EOF

echo "Configuring TLS cert auth method..."
vault write auth/cert/certs/demo \
    display_name="TPM Demo Cert" \
    policies="default,kv-policy" \
    certificate=@<(vault read -field=certificate pki/cert/ca)

echo "Setting up example application certificate authentication..."
echo "You can configure additional applications using this pattern:"
echo ""
echo "# Example: Configure myapp certificate authentication"
echo "# vault policy write myapp-policy - << 'APP_POLICY_EOF'"
echo "# path \"secret/data/myapp/*\" {"
echo "#   capabilities = [\"create\", \"read\", \"update\", \"delete\"]"
echo "# }"
echo "# APP_POLICY_EOF"
echo ""
echo "# vault write auth/cert/certs/myapp \\"
echo "#     display_name=\"myapp-cert\" \\"
echo "#     policies=\"myapp-policy\" \\"
echo "#     certificate=@path/to/myapp-cert.pem"

echo "Downloading vault-tpm-helper..."
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    BINARY_ARCH="arm64"
else
    BINARY_ARCH="x86_64"
fi

LATEST_RELEASE=$(curl -s https://api.github.com/repos/ausmartway/vault-tpm-helper/releases/latest | jq -r .tag_name)
cd /tmp
wget -O vault-tpm-helper.tar.gz "https://github.com/ausmartway/vault-tpm-helper/releases/download/${LATEST_RELEASE}/vault-tpm-helper_Linux_${BINARY_ARCH}.tar.gz"

echo "Extracting vault-tpm-helper..."
tar -xzf vault-tpm-helper.tar.gz
sudo mv vault-tpm-helper /usr/local/bin/
sudo chmod +x /usr/local/bin/vault-tpm-helper

echo "Cleaning up download files..."
rm -f vault-tpm-helper.tar.gz

echo "Verifying TPM functionality..."
if ! tpm2_getcap properties-fixed 2>/dev/null; then
    echo "WARNING: TPM device not found or not functional"
    echo "Please ensure TPM is enabled in VM settings"
fi

echo "Testing OpenSSL TPM2 provider..."
if openssl list -providers | grep -q tpm2; then
    echo "✓ TPM2 provider loaded successfully"
    
    echo "Configuring TPM2 environment..."
    echo 'export TPM2TOOLS_TCTI="device:/dev/tpmrm0"' | sudo tee -a /etc/environment
    
    echo "Configuring Vault and TPM2 environment..."
    cat >> ~/.bashrc << 'BASHRC_EOF'

# Vault and TPM2 Environment Configuration
export VAULT_ADDR="https://localhost:8200"
export VAULT_SKIP_VERIFY=1
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# Dynamically retrieve Vault root token if available
if [ -f /tmp/vault-init.json ] && command -v jq >/dev/null 2>&1; then
    export VAULT_TOKEN=$(cat /tmp/vault-init.json | jq -r '.root_token' 2>/dev/null)
fi
BASHRC_EOF
    
    echo "Testing TPM2 key generation..."
    export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
    # Test with proper group permissions (user needs to be in tss group)
    if grep -q "^tss:" /etc/group && sudo -u $USERNAME -g tss bash -c "export TPM2TOOLS_TCTI='device:/dev/tpmrm0' && openssl genpkey -provider tpm2 -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out /tmp/test-tpm-key.pem 2>/dev/null"; then
        if sudo -u $USERNAME -g tss head -1 /tmp/test-tpm-key.pem | grep -q "TSS2"; then
            echo "✓ TPM2 provider generating TSS2 keys correctly"
        else
            echo "WARNING: TPM2 provider loaded but not generating TSS2 keys"
        fi
        sudo rm -f /tmp/test-tpm-key.pem
    else
        echo "WARNING: TPM2 key generation failed (user will need to log out/in for tss group to take effect)"
    fi
else
    echo "WARNING: TPM2 provider not loaded properly"
fi

echo
echo "=== Setup Complete ==="
echo "Vault is running on https://localhost:8200"
echo "Root token: $ROOT_TOKEN"
echo "Unseal keys saved in: /tmp/vault-init.json"
echo
echo "Next steps:"
echo "1. Verify TPM functionality"
echo "2. Generate TPM-based certificates" 
echo "3. Test authentication with vault-tpm-helper"
EOF

scp /tmp/remote_setup.sh $SSH_TARGET:$REMOTE_SETUP_DIR/
ssh $SSH_TARGET "chmod +x $REMOTE_SETUP_DIR/remote_setup.sh"

echo "Executing remote setup..."
ssh $SSH_TARGET "$REMOTE_SETUP_DIR/remote_setup.sh"

echo
echo "=== Setup Complete ==="
echo "Server: $SSH_TARGET"
echo "✓ TPM2 tools and OpenSSL provider installed via Ubuntu packages (simplified approach)"
echo "✓ User added to tss group for TPM device access"
echo "✓ OpenSSL configured for TPM2 provider"
echo "✓ Vault server installed with proper TLS certificate (including SANs)"
echo "✓ PKI engine and TLS cert auth enabled (supports any key type including ECC)"
echo "✓ vault-tpm-helper installed"
echo
echo "IMPORTANT: Log out and back in for tss group membership to take effect"
echo "Connect to server: ssh $SSH_TARGET"
echo "Vault URL: https://$HOSTNAME:8200"