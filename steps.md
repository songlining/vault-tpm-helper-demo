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
- ✅ Vault server installation with proper TLS certificate setup
- ✅ PKI engine and TLS cert authentication configuration
- ✅ vault-tpm-helper v0.1.1 installation from GitHub releases
- ✅ Intelligent handling of existing Vault installations
- ✅ Comprehensive error handling and validation

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

# Create CSR using TPM-backed private key
openssl req -new \
    -provider tpm2 \
    -key client.key.pem \
    -out client.csr \
    -subj "/C=US/ST=CA/L=Demo/O=TPM-Demo/CN=tpm-client"

# Verify CSR was created successfully
openssl req -in client.csr -text -noout
```

### Sign Certificate with Vault PKI
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
# Test authentication with vault-tpm-helper
vault-tpm-helper \
    -vault-addr="https://localhost:8200" \
    -tls-skip-verify \
    -cert-file="client.cert.pem" \
    -key-file="client.key.pem" \
    -auth-path="cert"

# If successful, you should see a client token returned
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
# Save the token from previous authentication
CLIENT_TOKEN="<token_from_vault-tpm-helper_output>"
export VAULT_TOKEN="$CLIENT_TOKEN"

# Test token by reading Vault status
vault auth -method=token token="$CLIENT_TOKEN"
vault kv list secret/ 2>/dev/null || echo "No secrets found (expected for new setup)"

# Verify token information
vault token lookup
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
openssl dgst -sha256 -sign client.key.pem -provider tpm2 /etc/hostname > test-signature.bin
echo "✓ TPM key still functional after reboot"
rm test-signature.bin
```

### Verify TSS2 Key Format
```bash
# Double-check that client.key.pem contains TSS2 format
echo "Verifying TPM key format:"
if openssl pkey -in client.key.pem -provider tpm2 -text -noout | grep -q "TSS2"; then
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
openssl pkey -in client.key.pem -provider tpm2 -check

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