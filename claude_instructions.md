# Demo scenario for Hashicorp Vault TPM based TLS cert authentication
This is to build a demo that works around https://github.com/ausmartway/vault-tpm-helper/blob/main/README.md, which will be referred in this document as "THE repo".

# Prerequisite
A server will be setup before hand (out of the scope of this repo) with the following:
- Ubuntu 24
- files encrypted and TPM device enabled on VM level
- the current (supplied) linux user will be part of the sudoers
- ssh is enabled and can logon with ssh keys (not username/password)
- The default test ssh info: `ssh lsong@vault-tpm-demo`

# Setup script
The setup script (setup.sh) will be executed on the local machine and run remote commands via ssh, not the target server.

## Initial setup
It takes care of the following:
- take input of the username and hostname for ssh into the server
- `scp` local files to the target server and execute from the target server.
- learn from "THE repo" on how to prepare the server by installing all necessary libs, including `pv`
- also, configure openssl by modifying /etc/ssl/openssl.cnf file and make sure it's compliant with the following lines.  Only make necessary changes when needed. 
```
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
module = /usr/lib/aarch64-linux-gnu/ossl-modules/tpm2.so
```

## Vault server
`setup.sh` will also install hashicorp vault community edition and configure it.
- make sure Vault is configured to enable https on port 8200
- unseal the Vault server.
- make sure TLS cert auth method is enabled. You can learn from https://github.com/songlining/tls-cert-auth-demo on how to set it up.
- also make sure the PKI secret engine is enabled.  It will be used as trusted CA for signing the CSR

## vault-tpm-helper
`setup.sh` will download vault-tpm-helper from "THE repo" via its releases page. Make sure the right arch type for the binary to download. Also, make sure it's spelled as tpm not tmp!

# Demo
This will be a manual demo.  Please generate a new steps.md file for guidence, with command lines to follow.

## The flow in the steps.md file
Steps:
- show tpm readiness on the server
- show vault readiness on the server
- show how to authenticate to vault using TPM based TLS cert.  Break down to more steps if needed. 
- make sure the keys are generated using tpm2 provider like this:
```
# Generate ECC private key in TPM
openssl genpkey \
    -provider tpm2 \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -out client.key.pem
```

## Test
Test TPM authentication to Vault following "THE repo" and make sure it works.  DO NOT use any simulation to bypass any functions.

If there's any error in the test, go back and fix the original script, scp to the target server and test again, until the problems are gone.

Use this command to test if a TSS2 key is contained in client.key.pem.  If it's not, it means the setup is wrong somewhere along the line.
openssl genpkey \
    -provider tpm2 \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -out client.key.pem

# Rules
- make sure the spelling is always tpm not tmp (except the linux directory /tmp/) in various tpm related commands and files.  The server is vault-tpm-demo not vault-tmp-demo!