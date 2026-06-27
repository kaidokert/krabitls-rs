# mTLS canned fixture (seed 0)

Hermetic replay material for `krabitls/tests/canned_handshake_mtls.rs` — a
full client-mutual-auth (mTLS) handshake whose server flight carries a
`CertificateRequest`, so the client emits `Certificate` + `CertificateVerify`
+ `Finished`. CI replays these bytes with no network.

Packets (TLS records, hex):
- `001_c2s_ClientHello.hex`
- `002_s2c_ServerHello.hex`
- `003_s2c_ServerFlight_encrypted.hex`  — EE + CertificateRequest + Certificate + CertificateVerify + Finished
- `004_c2s_ClientSecondFlight_encrypted.hex` — Certificate + CertificateVerify + Finished
- `client_leaf.der` — the client's Ed25519 leaf (public); the matching
  throwaway seed is `CLIENT_SEED` in the test.

## How it was generated (one-time, local; not needed for CI)

Server: `openssl s_server` constrained to krabitls's profile, requiring a
client cert:

```
openssl req -x509 -newkey ed25519 -keyout server.key -out server.crt -days 36500 -nodes \
  -subj "/CN=mtls-fixture.local" -addext "subjectAltName=DNS:mtls-fixture.local"
openssl req -x509 -newkey ed25519 -keyout clientca.key -out clientca.crt -days 36500 -nodes \
  -subj "/CN=krabitls fixture client CA"
openssl req -new -newkey ed25519 -keyout client.key -out client.csr -nodes -subj "/CN=krabitls-fixture-client"
openssl x509 -req -in client.csr -CA clientca.crt -CAkey clientca.key -CAcreateserial -days 36500 -out client.crt
openssl x509 -in client.crt -outform DER -out client_leaf.der
# CLIENT_SEED = last 32 bytes of:  openssl pkey -in client.key -outform DER
openssl s_server -accept 14433 -tls1_3 -cert server.crt -key server.key \
  -Verify 1 -CAfile clientca.crt -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519 -www -quiet
```

Client: a `SeededRng(0)` krabitls client with
`.with_client_auth(Ed25519ClientAuth::from_seed(CLIENT_SEED, client_leaf.der))`
over a byte-recording transport, split into the records above. The whole
exchange is deterministic (seeded RNG + deterministic Ed25519 signatures), so
the replay is byte-exact.
