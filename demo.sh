#!/bin/bash

# TPM-based Vault Authentication Demo
# This script demonstrates Steps 1-7 from steps.md using demo-magic
# Run this script directly on the vault-tpm-demo server after copying it there
# Usage: ./demo.sh

# Import demo-magic functions
. demo-magic.sh

# Configure demo settings for interactive mode
TYPE_SPEED=100
NO_WAIT=false  # Enable pausing for user input
DEMO_PROMPT="${GREEN}➜ ${CYAN}\W ${COLOR_RESET}"

# Function to wait for user input with message
wait_for_user() {
    echo -e "\n${BOLD}${GREEN}Press ENTER to continue...${COLOR_RESET}"
    read -r
}

# Function to display step header
step_header() {
    clear
    echo -e "${BOLD}${BLUE}================================${COLOR_RESET}"
    echo -e "${BOLD}${BLUE}TPM-based Vault Authentication Demo${COLOR_RESET}"
    echo -e "${BOLD}${BLUE}$1${COLOR_RESET}"
    echo -e "${BOLD}${BLUE}================================${COLOR_RESET}\n"
}

# Get current user and hostname for display
CURRENT_USER=$(whoami)
CURRENT_HOST=$(hostname)

# Initial screen
clear
echo -e "${BOLD}${GREEN}TPM-based Vault Authentication Demo${COLOR_RESET}"
echo -e "${BOLD}${GREEN}Steps 1-7 from the setup guide${COLOR_RESET}"
echo -e "${BOLD}${GREEN}Running on: $CURRENT_USER@$CURRENT_HOST${COLOR_RESET}"
echo -e "${BOLD}${GREEN}================================${COLOR_RESET}\n"
echo "This demo will walk through each step of TPM-based Vault authentication."
echo "Each step will pause for you to review the output."
wait_for_user

# Step 1: Verify Current Server
step_header "Step 1: Verify Current Server"
echo "Since we're running locally, we'll verify the current server instead of connecting."
pe "whoami"
pe "hostname"

# Step 2: Verify TPM Readiness
step_header "Step 2: Verify TPM Readiness"
echo "Checking TPM Device Status..."
pe "ls -la /dev/tpm*"
echo -e "\nVerifying TPM functionality..."
pe "sudo tpm2_getcap properties-fixed"
echo -e "\nChecking TPM manufacturer and version..."
pe "sudo tpm2_getcap properties-variable"
echo -e "\nVerifying TPM2 Tools Installation..."
pe "tpm2_getcap --version"
echo -e "\nTesting basic TPM operations..."
pe "sudo tpm2_getrandom 16 --hex"
wait_for_user

# Step 3: Verify Vault Server Readiness
step_header "Step 3: Verify Vault Server Readiness"
echo "Setting up Vault environment variables..."
pe "export VAULT_ADDR=\"https://localhost:8200\""
pe "export VAULT_SKIP_VERIFY=1"
echo -e "\nChecking Vault status..."
pe "vault status"
echo -e "\nVerifying TLS Certificate Configuration..."
echo "Checking Vault server certificate SANs:"
pe "openssl s_client -connect localhost:8200 -servername localhost < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A5 'Subject Alternative Name'"
echo -e "\nSetting up authentication..."
pe "ROOT_TOKEN=\$(cat /tmp/vault-init.json | jq -r '.root_token')"
pe "export VAULT_TOKEN=\"\$ROOT_TOKEN\""
echo -e "\nListing enabled auth methods..."
pe "vault auth list"
echo -e "\nChecking PKI Engine..."
pe "vault secrets list"
echo -e "\nChecking PKI CA certificate..."
pe "vault read pki/cert/ca"
wait_for_user

# Step 4: Verify OpenSSL TPM2 Provider
step_header "Step 4: Verify OpenSSL TPM2 Provider"
echo "Testing TPM2 Provider Loading..."
pe "export TPM2TOOLS_TCTI=\"device:/dev/tpmrm0\""
# pe "export OPENSSL_CONF=/tmp/tpm2-openssl.cnf"
pe "openssl list -providers"
echo -e "\nGenerating a test key using TPM2 provider..."
pe "openssl genpkey -provider tpm2 -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out test-tpm-key.pem"
echo -e "\nVerifying the key contains TSS2 data (TPM-specific format):"
echo "Expected output should show 'TSS2' format:"
pe "cat test-tpm-key.pem"
echo -e "\nCleaning up test key..."
pe "rm test-tpm-key.pem"
echo -e "\n${BOLD}${RED}CRITICAL CHECK:${COLOR_RESET} If you saw '-----BEGIN PRIVATE KEY-----' instead of '-----BEGIN TSS2 PRIVATE KEY-----', "
echo "the TPM2 provider is not working correctly, and the key is NOT TPM-backed!"
wait_for_user

# Step 5: Generate TPM-based Client Certificate
step_header "Step 5: Generate TPM-based Client Certificate"
echo "Creating directory for client certificates..."
pe "mkdir -p ~/vault-client-certs"
pe "cd ~/vault-client-certs"
echo -e "\nSetting TPM2 environment variable (critical for TSS2 key generation)..."
pe "export TPM2TOOLS_TCTI=\"device:/dev/tpmrm0\""
echo -e "\nGenerating ECC private key in TPM..."
pe "openssl genpkey -provider tpm2 -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out client.key.pem"
echo -e "\nVerifying the key is TPM-backed by checking for TSS2 content..."
pe "if grep -q \"TSS2\" client.key.pem; then echo \"Key contains TSS2 data - TPM-backed key confirmed\"; else echo \"Key does not contain TSS2 data - NOT TPM-backed\"; exit 1; fi"
echo -e "\nCreating Certificate Signing Request (CSR)..."
pe "openssl req -new -provider tpm2 -provider default -key client.key.pem -out client.csr -subj \"/C=US/ST=CA/L=Demo/O=TPM-Demo/CN=tpm-client\""
echo -e "\nVerifying CSR was created successfully..."
pe "openssl req -in client.csr -text -noout"
echo -e "\nSigning certificate with Vault PKI..."
pe "vault write pki/sign/client-cert csr=@client.csr format=pem_bundle ttl=24h"
echo -e "\nExtracting the signed certificate..."
pe "vault write -field=certificate pki/sign/client-cert csr=@client.csr format=pem ttl=24h > client.cert.pem"
echo -e "\nVerifying the certificate..."
pe "openssl x509 -in client.cert.pem -text -noout"
wait_for_user

# Step 6: Test TPM-based Vault Authentication
step_header "Step 6: Test TPM-based Vault Authentication"
echo "Making sure we're in the client certs directory..."
pe "cd ~/vault-client-certs"
echo -e "\nExtracting Vault server certificate for TLS verification..."
pe "openssl s_client -connect localhost:8200 -servername localhost < /dev/null 2>/dev/null | openssl x509 > vault-server-ca.pem"
echo -e "\nTesting authentication with vault-tpm-helper..."
pe "CLIENT_TOKEN=\$(vault-tpm-helper -vaultaddr=\"https://localhost:8200\" -client-cert=\"client.cert.pem\" -client-key=\"client.key.pem\" -authpath=\"cert\" -name=\"demo\" -ca=\"vault-server-ca.pem\" -debug | tee /dev/stderr | tail -1)"
pe "echo \"Captured client token: \$CLIENT_TOKEN\""
echo -e "\n${BOLD}${GREEN}If successful, you should see a client token captured above.${COLOR_RESET}"
echo "Example token format: hvs.CAESICbtrb1PFM1g1npjxClzfWouWXHsTM76LuS-StYesPtNGh4K..."
wait_for_user

# Step 7: Testing KV Secrets Access
step_header "Step 7: Testing KV Secrets Access"
echo "Using the client token captured from step 6..."
echo -e "\nSetting up Vault environment with TPM-authenticated token..."
pe "export VAULT_ADDR=\"https://localhost:8200\""
pe "export VAULT_SKIP_VERIFY=1"
pe "export VAULT_TOKEN=\"\$CLIENT_TOKEN\""
pe "echo \"Using client token from step 6: \$CLIENT_TOKEN\""
echo -e "\nListing all secrets..."
pe "vault kv list secret/"
echo -e "\nListing secrets in demo/ path..."
pe "vault kv list secret/demo/"
echo -e "\nReading sample application secrets..."
pe "vault kv get secret/demo/app"
wait_for_user

# Demo completion
clear
echo -e "${BOLD}${GREEN}================================${COLOR_RESET}"
echo -e "${BOLD}${GREEN}Demo Completed Successfully!${COLOR_RESET}"
echo -e "${BOLD}${GREEN}================================${COLOR_RESET}\n"
echo -e "${BOLD}${GREEN}✓${COLOR_RESET} TPM device verified and functional"
echo -e "${BOLD}${GREEN}✓${COLOR_RESET} Vault server running and accessible"
echo -e "${BOLD}${GREEN}✓${COLOR_RESET} OpenSSL TPM2 provider loaded and working"
echo -e "${BOLD}${GREEN}✓${COLOR_RESET} TPM-backed client certificate generated"
echo -e "${BOLD}${GREEN}✓${COLOR_RESET} vault-tpm-helper authentication tested"
echo -e "${BOLD}${GREEN}✓${COLOR_RESET} KV secrets access verified"
echo -e "\n${BOLD}${BLUE}TPM-based authentication is now configured and working!${COLOR_RESET}"
echo -e "\nYou can now use vault-tpm-helper with the generated client certificate"
echo "to authenticate to Vault using TPM-backed keys."
echo -e "\nClient certificates are located in: ${BOLD}~/vault-client-certs/${COLOR_RESET}"