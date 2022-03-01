#!/bin/bash -x
#
#
# This example creates a 3 tier CA
#
# root-a -> int-1 -> int-2 -> demo-app.local (identity)
#
# root-a
#   int-1
#     int-2
#       demo-app.local
#
# This POC script shows that Vault can participate at every level of this 
# CA hierarchy
#
# Naming convention - 
#   config path is "pki-" followed by the CA common name, so
#   CN=root-a will be found at path "pki-root-a" 
# 

set -e

vault secrets enable -path=pki-root-a pki

# 10yr TTL for root 
vault secrets tune -max-lease-ttl=87600h pki-root-a

# Generate root 
vault write -format=json pki-root-a/root/generate/internal \
  common_name=root-a ttl=87600h \
  | jq -r .data.certificate > root-a.crt


# Configure CRLs
#
# Note: 
# CRL checking is not implemented consistently across browsers
# https://medium.com/@alexeysamoshkin/how-ssl-certificate-revocation-is-broken-in-practice-af3b63b9cb3
#
# HashiCorp recommends short TTLs instead where possible
# https://www.vaultproject.io/docs/secrets/pki#keep-certificate-lifetimes-short-for-crl-s-sake
#
#vault write pki-root-a/config/urls \
#  issuing_certificates="$VAULT_ADDR/v1/pki-root-a/ca" \
#  crl_distribution_points="$VAULT_ADDR/v1/pki-root-a/crl"


###############################################################################
# Setup first level intermediate
vault secrets enable -path=pki-int-1 pki
vault secrets tune -max-lease-ttl=43800h pki-int-1

# Generate intermediate and save CSR
vault write -format=json pki-int-1/intermediate/generate/internal \
  common_name=int-1 \
  | jq -r '.data.csr' > int-1.csr

# Sign the intermediate certificate with the root CA private key
vault write -format=json pki-root-a/root/sign-intermediate csr=@int-1.csr \
     format=pem_bundle ttl="43800h" \
     | jq -r '.data.certificate' > int-1.cert.pem

# Import signed intermediate
vault write pki-int-1/intermediate/set-signed certificate=@int-1.cert.pem



###############################################################################
# Setup second level intermediate
vault secrets enable -path=pki-int-2 pki
vault secrets tune -max-lease-ttl=43800h pki-int-2

# Generate intermediate and save CSR
vault write -format=json pki-int-2/intermediate/generate/internal \
  common_name=int-2 \
  | jq -r '.data.csr' > int-2.csr

# Sign the 2nd level intermediate certificate with the 1st level CA private key
vault write -format=json pki-int-1/root/sign-intermediate csr=@int-2.csr \
     format=pem_bundle ttl="43800h" \
     | jq -r '.data.certificate' > int-2.cert.pem

# Import signed intermediate
vault write pki-int-2/intermediate/set-signed certificate=@int-2.cert.pem


###############################################################################
# Create role for issuing leaf certs
vault write pki-int-2/roles/demo-app.local \
    allowed_domains=demo-app.local \
    allow_bare_domains=true \
    allow_subdomains=true max_ttl=72h \
    key_bits=4096

# Issue leaf cert
vault write pki-int-2/issue/demo-app.local \
  common_name=demo-app.local \
  format=pem_bundle > demo-app.pem


# Create policy allowing a service to generate 2nd level intermediates
vault policy write int-1-signer - <<EOF
path "int-1/root/sign-intermediate" {
  capabilities = ["create", "update"]
}
EOF

vault token create -policy=int-1-signer


