//! Throwaway RSA-2048 client keypair shared by the RSA mTLS capture
//! harness and its replay test — a test vector, not a real credential.
//! The public half is certified by
//! `testdata/packets_mtls_rsa/client_leaf.der`.

/// Big-endian RSA-2048 modulus.
pub const CLIENT_N_HEX: &str = "a2906830b167480a497efc6bbbe503a038fe4778e6e04f09f2e2e3667140beb6\
     397a86523c0e9129820665dd7d69e60ceac0d9988addfcb9a3316de6f4084af8\
     4f70250a833f057bfa960ec8ede6889c4ca3b79c0decfc394b02e8581ba46dfe\
     132e734223e34900368d9bb2a5087a2c595a444c4b232fc95cc2a766a9e10f7b\
     c4842c28275a0f131ea0ea3d5ffefa208f52a723be2e85beed036195bf96ea5a\
     fa5e28716d708ef59b281d1b80c782e1b18b4992602085f478d550588520d994\
     37ebd17189824cf61f5c0389051167a0679c17e87c61bb1f9a8765bb3a4d0251\
     f1cf04f81ed426c1bd3c9618ac5f8574fe89ce6b89b4945dd58c1a39ac911ba5";

/// Big-endian private exponent.
pub const CLIENT_D_HEX: &str = "14f43731db941c019372a657beaae8da3cae6e0903fd72c2ae0797d72b0ef4e6\
     2927856bd128f1861fa7f27667c5802d370f2f9d0d7d4aa7a504e88d25f471b1\
     6b0fe1fe666777ae00e159bb858abb1e2674cde474191173d31ae757000d244e\
     652b8e18bee67b90e6f73ed3fa98caa2afcbc654ed347662e6ad828565ad4860\
     ef65d75740448190eb2d75aaec68fde78e20eeca81d98505b084d3859c49fc3b\
     2130beb6b8b2076321d28ba4b35bc3213336a109579990a2eb1fbede6632a5d9\
     1a2ef0459fa077e28691a503f9ca369966de82923328b58a1ea295f47b85cca8\
     f2b36cd39a0a93234d2da7313c9191a307c80bd271f0ff74be8a4665149eb791";

pub const CLIENT_E: u32 = 65537;
