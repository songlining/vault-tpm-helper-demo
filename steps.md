# TPM-based Vault Authentication Demo Steps

This document provides step-by-step instructions for demonstrating TPM-based TLS certificate authentication with HashiCorp Vault.

## Prerequisites

- Server setup completed using `./setup.sh --defaults` (or `./setup.sh` for interactive mode)
- SSH access to the configured server  
- TPM device enabled and functional

### Running the Setup

```bash
# Interactive mode (prompts for username/hostname)
./setup.sh

# Non-interactive mode using defaults (lsong@vault-tpm-demo)
./setup.sh --defaults

# Test connectivity only
./test-setup.sh --defaults

# Reset Vault if needed (clears all data and reinitializes)
./reset-vault.sh

# View help and options
./setup.sh --help
```

### Setup Script Features
- ✅ Automatic TPM2 library installation with Ubuntu 24 compatibility
- ✅ OpenSSL TPM2 provider compilation and configuration
- ✅ Vault server installation with proper TLS certificate setup **including SANs**
- ✅ PKI engine and TLS cert authentication configuration (supports ECC keys)
- ✅ vault-tmp-helper v0.1.1 installation from GitHub releases
- ✅ TPM2TOOLS_TCTI environment configuration for TSS2 key generation
- ✅ Intelligent handling of existing Vault installations
- ✅ Comprehensive error handling and validation

### Critical Requirements for vault-tpm-helper Success
1. **TSS2 Keys**: Private keys must be in TSS2 format (generated with `-provider tpm2`)
2. **TLS Certificate SANs**: Vault server certificate must include Subject Alternative Names
3. **PKI Role**: Must accept ECC keys (`key_type = any`)  
4. **Environment**: `TPM2TOOLS_TCTI="device:/dev/tpmrm0"` must be set
5. **Provider Specification**: Use both `-provider tpm2 -provider default` for TSS2 key operations

## Step 1: Connect to the Server

```bash
ssh lsong@vault-tpm-demo
```

## Step 2: Verify TPM Readiness

### Check TPM Device Status
```bash
# Check if TPM device is available
ls -la /dev/tpm*

# Verify TPM functionality
sudo tpm2_getcap properties-fixed

# Check TPM manufacturer and version
sudo tpm2_getcap properties-variable
```

### Verify TPM2 Tools Installation
```bash
# Check installed TPM2 tools version
tpm2_getcap --version

# Test basic TPM operations
sudo tpm2_getrandom 16 --hex
```

## Step 3: Verify Vault Server Readiness

### Check Vault Status
```bash
export VAULT_ADDR="https://localhost:8200"
export VAULT_SKIP_VERIFY=1

# Check Vault status
vault status

# Verify Vault is unsealed and accessible
curl -k https://localhost:8200/v1/sys/health
```

### Verify TLS Certificate Configuration
```bash
# Check if Vault server certificate has proper SANs (required for vault-tpm-helper)
echo "Checking Vault server certificate SANs:"
openssl s_client -connect localhost:8200 -servername localhost < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A5 'Subject Alternative Name'

# Expected output should show:
# X509v3 Subject Alternative Name: 
#     DNS:vault-tpm-demo, DNS:localhost, IP Address:127.0.0.1, IP Address:172.16.236.132

# If SANs are missing, vault-tmp-helper will fail with TLS errors
# See troubleshooting section for how to fix this
```

### Check Authentication Methods
```bash
# Get root token from initialization
ROOT_TOKEN=$(cat /tmp/vault-init.json | jq -r '.root_token')
export VAULT_TOKEN="$ROOT_TOKEN"

# List enabled auth methods
vault auth list

# Verify cert auth method is enabled
vault auth list | grep cert
```

### Check PKI Engine
```bash
# List enabled secrets engines
vault secrets list

# Verify PKI engine is enabled
vault secrets list | grep pki

# Check PKI CA certificate
vault read pki/cert/ca
```

## Step 4: Verify OpenSSL TPM2 Provider

### Test TPM2 Provider Loading
```bash
# List available OpenSSL providers
openssl list -providers

# Verify TPM2 provider is loaded
openssl list -providers | grep -i tpm2
```

### Test TPM2 Provider Functionality
```bash
# Set TPM2 environment variable (required for TSS2 key generation)
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# Generate a test key using TPM2 provider
openssl genpkey \
    -provider tpm2 \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -out test-tpm-key.pem

# Verify the key contains TSS2 data (TPM-specific format)
echo "Expected output should show 'TSS2' format:"
head -1 test-tpm-key.pem

# Expected result: -----BEGIN TSS2 PRIVATE KEY-----
# NOT: -----BEGIN PRIVATE KEY-----

file test-tpm-key.pem

# Clean up test key
rm test-tpm-key.pem
```

**⚠️ Critical Check:** If you see `-----BEGIN PRIVATE KEY-----` instead of `-----BEGIN TSS2 PRIVATE KEY-----`, the TPM2 provider is not working correctly, and the key is NOT TPM-backed! You must fix this before proceeding.

## Step 5: Generate TPM-based Client Certificate

### Generate TPM-backed Private Key
```bash
# Create directory for client certificates
mkdir -p ~/vault-client-certs
cd ~/vault-client-certs

# Set TPM2 environment variable (critical for TSS2 key generation)
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# Generate ECC private key in TPM
openssl genpkey \
    -provider tpm2 \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -out client.key.pem

# Verify the key is TPM-backed by checking for TSS2 content
echo "Checking if key is TPM-backed:"
if grep -q "TSS2" client.key.pem; then
    echo "✓ Key contains TSS2 data - TPM-backed key confirmed"
else
    echo "✗ Key does not contain TSS2 data - NOT TPM-backed"
    exit 1
fi
```

### Create Certificate Signing Request (CSR)
```bash
# Ensure TPM2 environment is set
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# Create CSR using TPM-backed private key (requires tpm2 provider for TSS2 key)
openssl req -new \
    -provider tpm2 \
    -provider default \
    -key client.key.pem \
    -out client.csr \
    -subj "/C=US/ST=CA/L=Demo/O=TPM-Demo/CN=tpm-client"

# Verify CSR was created successfully
openssl req -in client.csr -text -noout
```

### Sign Certificate with Vault PKI
Make sure VAULT_TOKEN is set.
```bash
# Sign the CSR using Vault PKI
vault write pki/sign/client-cert \
    csr=@client.csr \
    format=pem_bundle \
    ttl=24h

# Extract the signed certificate
vault write -field=certificate pki/sign/client-cert \
    csr=@client.csr \
    format=pem \
    ttl=24h > client.cert.pem

# Verify the certificate
openssl x509 -in client.cert.pem -text -noout
```

## Step 6: Test TPM-based Vault Authentication

### Authenticate Using vault-tpm-helper

```bash
# Extract Vault server certificate for TLS verification
openssl s_client -connect localhost:8200 -servername localhost < /dev/null 2>/dev/null | openssl x509 > vault-server-ca.pem

# Test authentication with vault-tpm-helper
vault-tpm-helper \
    -vaultaddr="https://localhost:8200" \
    -client-cert="client.cert.pem" \
    -client-key="client.key.pem" \
    -authpath="cert" \
    -name="demo" \
    -ca="vault-server-ca.pem" \
    -debug

# If successful, you should see a client token returned
# Example successful output:
# hvs.CAESICbtrb1PFM1g1npjxClzfWouWXHsTM76LuS-StYesPtNGh4KHGh2cy5VMW9UY085OThabFFrRkFHdzFDWFVaQUk
```

### Alternative: Direct Certificate Authentication
```bash
# Authenticate directly using curl with client certificate
curl -k \
    --cert client.cert.pem \
    --key client.key.pem \
    -X POST \
    https://localhost:8200/v1/auth/cert/login \
    -d '{"name": "demo"}'
```

### Verify Token Functionality
```bash
# Save the token from vault-tpm-helper output (example token shown)
CLIENT_TOKEN="hvs.CAESICbtrb1PFM1g1npjxClzfWouWXHsTM76LuS-StYesPtNGh4KHGh2cy5VMW9UY085OThabFFrRkFHdzFDWFVaQUk"
export VAULT_TOKEN="$CLIENT_TOKEN"

# Test token functionality
vault token lookup

# The token should show:
# - display_name: "cert-TPM Demo Cert" (indicating certificate-based auth)
# - policies: ["default"]
# - meta: containing certificate details including serial_number and common_name
# - ttl: ~768h (32 days)

# Test access to secrets
vault kv list secret/ 2>/dev/null || echo "No secrets found (expected for new setup)"
```

## Step 7: Comprehensive Testing

### Test Key Persistence
```bash
# Reboot test (optional - requires sudo)
echo "Testing TPM key persistence after reboot..."
sudo reboot

# After reboot, reconnect and test
ssh lsong@vault-tpm-demo
cd ~/vault-client-certs

# Test if TPM key still works
openssl dgst -sha256 -sign client.key.pem -provider tpm2 -provider default /etc/hostname > test-signature.bin
echo "✓ TPM key still functional after reboot"
rm test-signature.bin
```

### Verify TSS2 Key Format
```bash
# Double-check that client.key.pem contains TSS2 format
echo "Verifying TPM key format:"
if openssl pkey -in client.key.pem -provider tpm2 -provider default -text -noout | grep -q "TSS2"; then
    echo "✓ Confirmed: Key is in TSS2 format (TPM-backed)"
else
    echo "✗ Error: Key is not in TSS2 format"
    exit 1
fi
```

### Performance Test
```bash
# Test authentication speed
echo "Testing authentication performance:"
time vault-tpm-helper \
    -vault-addr="https://localhost:8200" \
    -tls-skip-verify \
    -cert-file="client.cert.pem" \
    -key-file="client.key.pem" \
    -auth-path="cert"
```

## Step 8: Troubleshooting Commands

### If TPM Authentication Fails

```bash
# Check TPM status
sudo tpm2_getcap properties-fixed

# Verify OpenSSL can load TPM2 provider
openssl list -providers -verbose

# Test key file integrity (MUST use tpm2 provider for TSS2 keys)
openssl pkey -in client.key.pem -provider tpm2 -provider default -check

# Verify key is actually TPM-backed
head -1 client.key.pem  # Should show "-----BEGIN TSS2 PRIVATE KEY-----"

# Check Vault logs
sudo journalctl -u vault -f

# Verify certificate chain
openssl verify -CAfile <(vault read -field=certificate pki/cert/ca) client.cert.pem
```

### If TPM2 Provider Not Working (Keys Show PEM Instead of TSS2)

**Problem:** OpenSSL generates `-----BEGIN PRIVATE KEY-----` instead of `-----BEGIN TSS2 PRIVATE KEY-----`

**Root Cause:** Missing TPM2TOOLS_TCTI environment variable

```bash
# 1. Verify TPM2 module exists
ls -la /usr/lib/*/ossl-modules/tpm2.so

# 2. Check if tpm2 provider is active
openssl list -providers
# Should show both 'default' and 'tpm2' providers as active

# 3. Set the required environment variable
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"

# 4. Test TPM2 provider with environment variable
openssl genpkey -provider tpm2 -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out test.pem
head -1 test.pem  # Should show "-----BEGIN TSS2 PRIVATE KEY-----"
rm test.pem

# 5. Make environment variable persistent
echo 'export TPM2TOOLS_TCTI="device:/dev/tpmrm0"' >> ~/.bashrc
source ~/.bashrc

# 6. If still failing, check TPM device access
ls -la /dev/tpm*
sudo tpm2_getcap properties-fixed

# 7. If still failing, the setup script may need to be re-run
./reset-vault.sh
./setup.sh --defaults
```

**Key Point:** The TPM2 provider will be "active" but won't generate TSS2 keys without the proper TCTI configuration!

### If Vault Connection Fails

```bash
# Check Vault service status
sudo systemctl status vault

# Verify Vault configuration
vault operator init -status
vault status

# Check network connectivity
nc -zv localhost 8200
```

### If Setup Script Fails

```bash
# Run connectivity test first
./test-setup.sh --defaults

# Check for common issues:
# 1. SSH keys not configured - ensure passwordless SSH works
# 2. Server not accessible - verify network connectivity
# 3. Insufficient permissions - ensure user has sudo access

# If Vault is in a bad state, reset completely
./reset-vault.sh
```

### If vault-tpm-helper Fails with TLS Errors

**Problem:** vault-tmp-helper fails with TLS certificate verification errors like:
- `certificate is not valid for any names`
- `certificate relies on legacy Common Name field, use SANs instead`
- `certificate signed by unknown authority`

**Root Cause:** Vault server certificate lacks proper Subject Alternative Names (SANs)

```bash
# Fix: Regenerate Vault server certificate with proper SANs
sudo systemctl stop vault

# Create new certificate with SANs for localhost, hostname, and IP
SERVER_IP=$(hostname -I | awk '{print $1}')
sudo openssl req -x509 -newkey rsa:4096 \
    -keyout /etc/vault.d/vault-key.pem \
    -out /etc/vault.d/vault-cert.pem \
    -days 365 -nodes \
    -subj "/C=US/ST=CA/L=SF/O=Demo/CN=vault-tpm-demo" \
    -addext "subjectAltName=DNS:vault-tpm-demo,DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}"

sudo chown vault:vault /etc/vault.d/vault-*.pem
sudo chmod 600 /etc/vault.d/vault-key.pem

# Restart and unseal Vault
sudo systemctl start vault
sleep 5

# Unseal Vault
export VAULT_ADDR="https://localhost:8200"
export VAULT_SKIP_VERIFY=1
export VAULT_TOKEN=$(cat /tmp/vault-init.json | jq -r '.root_token')

UNSEAL_KEY1=$(cat /tmp/vault-init.json | jq -r '.unseal_keys_b64[0]')
UNSEAL_KEY2=$(cat /tmp/vault-init.json | jq -r '.unseal_keys_b64[1]')
UNSEAL_KEY3=$(cat /tmp/vault-init.json | jq -r '.unseal_keys_b64[2]')

vault operator unseal "$UNSEAL_KEY1"
vault operator unseal "$UNSEAL_KEY2"
vault operator unseal "$UNSEAL_KEY3"

# Verify certificate has proper SANs
echo "Verifying certificate SANs:"
openssl s_client -connect localhost:8200 -servername localhost < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A5 'Subject Alternative Name'
```

**Expected output should show:**
```
X509v3 Subject Alternative Name: 
    DNS:vault-tpm-demo, DNS:localhost, IP Address:127.0.0.1, IP Address:172.16.236.132
```

**Why SANs are critical:**
- Modern TLS libraries (including Go, used by vault-tpm-helper) require Subject Alternative Names
- Legacy certificates using only Common Name (CN) are rejected by default
- Without proper SANs, vault-tmp-helper cannot establish TLS connections to Vault
- The setup script now automatically creates certificates with proper SANs

### Reset Demo Environment

```bash
# Quick reset using utility script (recommended)
./reset-vault.sh

# Manual reset if needed
ssh lsong@vault-tpm-demo << 'EOF'
sudo systemctl stop vault
sudo rm -rf /opt/vault/data/*
rm -f /tmp/vault-init.json
sudo systemctl start vault
EOF

# Remove client certificates and start over
rm -rf ~/vault-client-certs
```

### Common Setup Issues Fixed

- ✅ **Package compatibility**: TSS2 libraries updated for Ubuntu 24
- ✅ **Vault unsealing**: Proper handling of existing sealed/unsealed states
- ✅ **Download errors**: vault-tpm-helper now downloads from correct tar.gz URLs
- ✅ **Interactive prompts**: Use `--defaults` flag for unattended installation
- ✅ **Duplicate engines**: Smart detection of already-enabled PKI/cert auth
- ✅ **TLS certificate SANs**: Vault server certificates now include Subject Alternative Names
- ✅ **PKI role compatibility**: Updated to accept ECC keys (`key_type = any`)
- ✅ **TPM2 environment**: Proper `TPM2TOOLS_TCTI` configuration for TSS2 key generation

## Expected Results

1. **TPM Readiness**: TPM device should be detected and functional
2. **Vault Readiness**: Vault server running on HTTPS port 8200, unsealed
3. **OpenSSL TPM2**: Provider loaded and functional
4. **Key Generation**: TPM-backed ECC key with TSS2 format
5. **Authentication**: Successful token retrieval using vault-tpm-helper
6. **Persistence**: TPM keys remain functional across reboots

## Success Indicators

- ✅ TPM device responds to `tpm2_getcap` commands
- ✅ OpenSSL lists TPM2 provider in available providers
- ✅ Generated key file contains "TSS2" identifier
- ✅ vault-tpm-helper returns valid authentication token
- ✅ Token allows access to Vault operations
- ✅ Authentication works consistently across multiple attempts