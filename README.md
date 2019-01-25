# OpenSSL Bash and Ruby code
Bash code to use OpenSSL to easily create CAs, intermediates CAs, and certificates from the chain.
Also includes bash code to create self signed certificates.
Supporting setting subject alternative names in both cases.

Ruby code to check certificate chain validity and altnames ( both dns names and ipv4/ipv6 addresses )

To generate a root CA, an intermediate CA, and a site certificate from the intermediate:
`./redo`

To run the test ruby code checking the generated site.crt:
`./check.rb`
