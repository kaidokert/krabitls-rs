# Nordic CryptoCell libraries

These three unmodified Arm Cortex-M33 hard-float, no-interrupt archives are
from Nordic's `sdk-nrfxlib` tag `v3.4.1` (commit
`bb715183a57ac501907b63df2079c3fbcd067641`), library version 0.9.23. They are
redistributed under `LICENSE-NORDIC` and may only be used with Nordic ICs.

The adapter links only the CryptoCell platform, core, and PSA driver archives.
Its PSA attributes ABI is pinned to TF-PSA-Crypto commit
`fa92349590a54959ee2efc21b668e5afdb144726`, selected by the same nRF Connect
SDK 3.4.1 manifest.

SHA-256:

- `libnrf_cc312_core_0.9.23.a`: `07ffd9265db0f1263c74b4fb1a5875fb79fe60d216f055344bab228906f16e1b`
- `libnrf_cc312_psa_crypto_0.9.23.a`: `24d14bc5bfd0b590d365ebfc90b3b010a2131751cff20f4e2805e2d4678a07ec`
- `libnrf_cc312_platform_0.9.23.a`: `2ef1179bd5e2d1af7bc7d9349f53111843db6786d477806105ca24eca5bbebe0`
