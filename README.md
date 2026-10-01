# GM / SM Cryptography Atlas

**Live:** https://shundazhang.github.io/gm-sm-atlas/

Independent bilingual learning atlas, English by default, with a top-right EN / 中文 switch preserving the chapter. Shared language preference with the personal homepage.

## Coverage

- Principal named GM families: SM1/2/3/4/7/9 and ZUC, with clear public-disclosure limits and no invented algorithms for numbering gaps
- SM2: ZA, exact signature equations, nonce reuse, encryption/KDF/C1C2C3 versus C1C3C2/DER, static-plus-ephemeral exchange and confirmation
- Exact curveSM2 / NIST P-256 domain tables; ECDSA/ECDH versus SM2; P-384/521 and representation/security-level distinctions
- SM3: padding, expansion, P0/P1, all round updates and XOR feed-forward; detailed SHA-256, SHA-512, SHA3-256 and SHAKE comparisons
- SM4: S-box, L/L-prime, round keys, reverse decryption; AES-128/192/256 state, GF arithmetic, round structure and key expansion comparison
- Modes, MACs, SM9 pairings/KGC, ZUC profiles, TLCP/TLS 1.3, implementation and side-channel considerations
- 42 pages, 17 original bilingual diagrams, 3 local labs and a downloadable standard-library reference project

The browser computes exact teaching digests, block traces and public curve examples. No network request or upload is made by the labs; exercise inputs are not stored. Language selection alone is saved locally. No private-key entry, signing wallet or user-account operation is provided.

## Build and verification

```sh
python3 -B build.py
python3 -B audit.py
node check-labs.cjs
cd examples
python3 -B test_reference.py
python3 -B demo.py
```

`build.py` generates both languages and a deterministic `examples.zip`. GitHub Pages serves the committed documents from `main` at `/`. The Python project requires 3.9+ and no packages; optional independent checks use the installed OpenSSL CLI. See [examples/README.md](examples/README.md) for scope, test evidence and synthetic-key warnings.

Reviewed **1 October 2026**. Sources distinguish normative standards, current/forthcoming dates, expired explanatory Internet-Drafts, protocol profiles and implementation documents. NIST comparison does not imply GM algorithms are FIPS-approved. Public reference code is not constant-time, production-ready or a certified module. Original content, diagrams and teaching code; no closed algorithm internals or mirrored third-party standard PDFs.
