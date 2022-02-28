#!/bin/bash -x
#
#
# This example creates a 3 tier CA
#
# demo-root-a -> demo-int-a1 -> demo-int-a1a -> leaf/identity cert
#
# The naming convention allows multiple roots and intermediates so that new
# roots and intermediates can be issued with overlapping validity windows
#
# demo-root-a
#   demo-int-a1
#     demo-int-a1a
#     demo-int-a1b
#   demo-int-a2
#     demo-int-a2a
# demo-root-b
#   demo-int-b1
#   demo-int-b2  ...and so on
#
# 
# POC scenario - 
#   demo-root-a is an openssl offline CA
#   demo-int-a1 is Vault
#   demo-int-a1a is Istio
#   demo-app is an app identity cert
#
# This POC script shows that Vault can participate at every level of this 
# CA hierarchy


rootcn=demo-root-a-offline
rootpath=pki-${rootcn}

vault secrets disable $rootpath
vault secrets enable -path=$rootpath pki

# 10yr TTL for root 
vault secrets tune -max-lease-ttl=87600h $rootpath

# Generate root 
vault write -format=json ${rootpath}/root/generate/internal \
  common_name=$rootcn ttl=87600h \
  | jq -r .data.certificate > ${rootcn}.crt

# Configure CRLs
#
# Note: 
# CRL checking is not implemented consistently across browsers
# https://medium.com/@alexeysamoshkin/how-ssl-certificate-revocation-is-broken-in-practice-af3b63b9cb3
#
# HashiCorp recommends short TTLs instead where possible
# https://www.vaultproject.io/docs/secrets/pki#keep-certificate-lifetimes-short-for-crl-s-sake
#
vault write ${rootpath}/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/${rootpath}/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/${rootpath}/crl"



###############################################################################
# Setup first level intermediate
intcn=demo-int-a1-vault
intpath=pki-${intcn}
vault secrets disable $intpath
vault secrets enable -path=$intpath pki
vault secrets tune -max-lease-ttl=43800h $intpath

# Generate intermediate and save CSR
vault write -format=json ${intpath}/intermediate/generate/internal \
  common_name=$intcn \
  | jq -r '.data.csr' > ${intcn}.csr

# Sign the intermediate certificate with the root CA private key
vault write -format=json ${rootpath}/root/sign-intermediate csr=@${intcn}.csr \
     format=pem_bundle ttl="43800h" \
     | jq -r '.data.certificate' > ${intcn}.cert.pem


# Import signed intermediate
vault write ${intpath}/intermediate/set-signed certificate=@${intcn}.cert.pem



###############################################################################
# Setup first intermediate at the second level 
intcn2=demo-int-a1a-istio
intpath2=pki-${intcn2}
vault secrets disable $intpath2
vault secrets enable -path=$intpath2 pki
vault secrets tune -max-lease-ttl=43800h $intpath2

# Generate intermediate and save CSR
vault write -format=json ${intpath2}/intermediate/generate/internal \
  common_name=$intcn2 \
  | jq -r '.data.csr' > ${intcn2}.csr

# Sign the 2nd level intermediate certificate with the root CA private key
vault write -format=json ${intpath}/root/sign-intermediate csr=@${intcn2}.csr \
     format=pem_bundle ttl="43800h" \
     | jq -r '.data.certificate' > ${intcn2}.cert.pem

# Import signed intermediate
vault write ${intpath2}/intermediate/set-signed certificate=@${intcn2}.cert.pem


###############################################################################
# Setup second intermediate at the second level 
intcn3=demo-int-a1b-istio
intpath3=pki-${intcn3}
vault secrets disable $intpath3
vault secrets enable -path=$intpath3 pki
vault secrets tune -max-lease-ttl=43800h $intpath3

# Generate intermediate and save CSR
vault write -format=json ${intpath3}/intermediate/generate/internal \
  common_name=$intcn3 \
  | jq -r '.data.csr' > ${intcn3}.csr

# Sign the 2nd level intermediate certificate with the root CA private key
vault write -format=json ${intpath}/root/sign-intermediate csr=@${intcn3}.csr \
     format=pem_bundle ttl="43800h" \
     | jq -r '.data.certificate' > ${intcn3}.cert.pem

# Import signed intermediate
vault write ${intpath3}/intermediate/set-signed certificate=@${intcn3}.cert.pem

exit

###############################################################################
# Create leaf / identity certs
vault write ${intpath2}/roles/demo-app.local \
    allowed_domains=demo-app.local \
    allow_bare_domains=true \
    allow_subdomains=true max_ttl=72h \
    key_bits=4096

vault write ${intpath2}/issue/demo-app.local \
  common_name=demo-app.local \
  format=pem_bundle > demo-app.pem


# Create policy allowing Istio to generate 2nd level intermediates
vault policy create 


# Create role for generating identity cert from 
vault write pki/roles/ \
    allowed_domains=hashicorp-test.com \
    allow_bare_domains=true \
    allow_subdomains=true max_ttl=72h \
    key_bits=4096


vault write pki/issue/hashicorp-test-dot-com \
    common_name=app1.hashicorp-test.com 


