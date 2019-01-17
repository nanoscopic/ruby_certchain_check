# ruby_certchain_check
Ruby code to check certificate chain validity

To generate a root CA, an intermediate CA, and a site certificate from the intermediate, do the following:
1. `openssl genrsa -out rootca.key`
2. `openssl genrsa -out intermed/root.key`
3. `openssl genrsa -out test.com.key`
4. ./redo
