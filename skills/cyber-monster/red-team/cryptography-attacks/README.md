# Cryptography Attacks

> Tree: `red-team/cryptography-attacks` | **33 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`rsa-attacks`](rsa-attacks/SKILL.md) | **flagship** | Attacks RSA implementations: small exponent and low exponent conditions, common modulus, Wiener and Hastad, faulty padding, oracle attacks, and w |
| [`aead-aes-gcm-and-chacha20-misuse`](aead-aes-gcm-and-chacha20-misuse/SKILL.md) | **core** | Audits Authenticated Encryption with Associated Data (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, XChaCha20) implementations: 96-bit nonce reuse / b |
| [`block-cipher-modes-and-padding-oracles`](block-cipher-modes-and-padding-oracles/SKILL.md) | **core** | Exploits block cipher mode misuse: ECB pattern leakage, CBC bit flipping, padding oracle decryption, and IV and salt handling errors |
| [`crypto-implementation-review`](crypto-implementation-review/SKILL.md) | **core** | Reviews cryptographic code for real-world mistakes: home-made constructions, key management errors, unsafe defaults and misuse of library APIs |
| [`ecc-and-diffie-hellman-attacks`](ecc-and-diffie-hellman-attacks/SKILL.md) | **core** | Attacks elliptic curve and Diffie-Hellman usage: invalid curve points, small subgroup confinement, parameter validation gaps and weak curves |
| [`hash-attacks-and-length-extension`](hash-attacks-and-length-extension/SKILL.md) | **core** | Attacks hash constructions: length extension on Merkle-Damgard, collision paths, weak or truncated digests, and comparison flaws |
| [`password-hashing-and-kdf-attacks`](password-hashing-and-kdf-attacks/SKILL.md) | **core** | Attacks password storage and key derivation: fast-hash cracking, salting gaps, weak KDF parameters, and offline attack economics |
| [`post-quantum-cryptography-migration-and-hybrids`](post-quantum-cryptography-migration-and-hybrids/SKILL.md) | **core** | Assesses Post-Quantum Cryptography (PQC) and hybrid KEM/signature deployments (ML-KEM / Kyber, ML-DSA / Dilithium, X25519MLKEM768): harvest-now-d |
| [`prng-and-nonce-attacks`](prng-and-nonce-attacks/SKILL.md) | **core** | Exploits weak randomness: predictable PRNG seeds, time-based tokens, nonce and IV reuse, and biased generators |
| [`signature-and-mac-attacks`](signature-and-mac-attacks/SKILL.md) | **core** | Attacks signature and MAC verification: algorithm confusion, missing verification, malleability, and encoding of signed data |
| [`symmetric-cipher-attacks`](symmetric-cipher-attacks/SKILL.md) | **core** | Attacks symmetric encryption: key reuse, weak key derivation, nonce and IV mistakes, mode-specific weaknesses and known-plaintext exploitation |
| [`tls-and-pki-attacks`](tls-and-pki-attacks/SKILL.md) | **core** | Attacks TLS and PKI in practice: weak protocol versions and ciphers, certificate validation gaps, pinning weaknesses, and trust store abuse |
| [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](block-cipher-modes-and-padding-oracles-cbc-bit-flipping/SKILL.md) | **leaf** | CBC bit flipping and IV manipulation |
| [`block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation`](block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation/SKILL.md) | **leaf** | ECB pattern exploitation |
| [`block-cipher-padding-oracle-exploitation`](block-cipher-padding-oracle-exploitation/SKILL.md) | **leaf** | Padding oracle exploitation |
| [`classical-and-covert-encoding`](classical-and-covert-encoding/SKILL.md) | **leaf** | Decodes and breaks classical ciphers and encoding layers: Caesar, Vigenere, substitution, transposition, Morse, base variants, hex, and chained e |
| [`constant-time-and-crypto-side-channel-code-audit`](constant-time-and-crypto-side-channel-code-audit/SKILL.md) | **leaf** | Audits cryptographic and authentication routines for software timing/cache side channels: early-exit byte comparison (`==` instead of `hmac.compa |
| [`envelope-encryption-and-kms-tenant-isolation`](envelope-encryption-and-kms-tenant-isolation/SKILL.md) | **leaf** | Audits envelope encryption (DEK/KEK) and cloud KMS usage (AWS KMS, GCP KMS, Vault Transit): missing `EncryptionContext` / AAD tenant binding allo |
| [`hash-attacks-and-length-extension-collision-and-bypass`](hash-attacks-and-length-extension-collision-and-bypass/SKILL.md) | **leaf** | Hash collision and comparison bypass |
| [`hash-attacks-and-length-extension-length-extension`](hash-attacks-and-length-extension-length-extension/SKILL.md) | **leaf** | Hash length extension attacks |
| [`lattice-and-advanced-crypto-attacks`](lattice-and-advanced-crypto-attacks/SKILL.md) | **leaf** | Applies lattice reduction and advanced cryptanalysis to CTF and real constructions: LLL, Coppersmith, hidden number and knapsack problems |
| [`prng-and-nonce-attacks-predictable-token-generation`](prng-and-nonce-attacks-predictable-token-generation/SKILL.md) | **leaf** | Predictable token generation |
| [`prng-and-nonce-attacks-signature-nonce-reuse`](prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md) | **leaf** | Signature nonce reuse |
| [`rsa-attacks-factorization`](rsa-attacks-factorization/SKILL.md) | **leaf** | RSA factorisation attacks |
| [`rsa-attacks-padding-oracle`](rsa-attacks-padding-oracle/SKILL.md) | **leaf** | RSA padding oracle attacks |
| [`rsa-attacks-signature-forgery`](rsa-attacks-signature-forgery/SKILL.md) | **leaf** | RSA signature forgery |
| [`rsa-attacks-small-and-low-exponent`](rsa-attacks-small-and-low-exponent/SKILL.md) | **leaf** | RSA small and low exponent attacks |
| [`steganography-and-covert-channels`](steganography-and-covert-channels/SKILL.md) | **leaf** | Detects and extracts hidden data: LSB steganography, appended data, metadata hiding, and covert channels in protocols and files |
| [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md) | **leaf** | Keystream and nonce reuse |
| [`symmetric-cipher-attacks-weak-key-derivation`](symmetric-cipher-attacks-weak-key-derivation/SKILL.md) | **leaf** | Weak symmetric key derivation |
| [`tls-and-pki-attacks-certificate-validation-gaps`](tls-and-pki-attacks-certificate-validation-gaps/SKILL.md) | **leaf** | Certificate validation gaps |
| [`tls-and-pki-attacks-configuration-weaknesses`](tls-and-pki-attacks-configuration-weaknesses/SKILL.md) | **leaf** | TLS configuration weaknesses |
| [`zk-and-mpc-protocol-review`](zk-and-mpc-protocol-review/SKILL.md) | **leaf** | Reviews zero-knowledge and multi-party computation designs for soundness and trust assumptions, including trusted setup, commitment binding and r |
