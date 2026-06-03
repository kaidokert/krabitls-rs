### KrabiTLS

 A hobby TLS 1.3 client for microcontrollers. Don't use it for
  anything you care about.

  - Locked to one cipher / curve / sig combo — won't negotiate with
    most servers
  - Trust model is "pin a pubkey or trust SAN" — no CA bundle, no
    chain walking
  - Hand-rolled, unaudited, not constant-time, no scalar blinding

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.
