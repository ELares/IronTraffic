# Test fixtures

## `p521-leaf.der`

A self-signed P-521 (secp521r1) leaf certificate, used by
`store::cred::tests::load_p521_rejected` to prove `Credentials::load` refuses a key type this
crate does not serve. rcgen 0.14.8 has no P-521 algorithm, so this one fixture is committed
instead of generated at test time. It carries no private key: the test only asserts
`Err(CertError::UnsupportedKeyType)`, and that error is returned before the code ever reaches
the key-matching step, so no key is needed to exercise it.

Generated with:

```sh
openssl ecparam -genkey -name secp521r1 -noout -out p521-key.pem
openssl req -new -x509 -key p521-key.pem -days 3650 -subj "/CN=p521.example.com" \
  -addext "subjectAltName=DNS:p521.example.com" \
  -outform DER -out p521-leaf.der
rm p521-key.pem
```

`p521-key.pem` was deleted immediately after signing and was never committed.
