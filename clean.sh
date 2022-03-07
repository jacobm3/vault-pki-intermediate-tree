vault secrets list | grep pki | awk '{print $1}' | xargs -n1 vault secrets disable

rm *.csr *.pem *.crt
