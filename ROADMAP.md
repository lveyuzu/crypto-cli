# Roadmap

Progress on Cryptix. Still a WIP.

## Milestone 1 — Basics [done]

- [x] Project setup and CLI
- [x] Plugin system and registry
- [x] Custom plugins
- [x] File input/output and piping
- [x] Encoding and decoding chains
- [x] JSON output, quiet mode, error handling
- [x] Built-in encoding, compression and cipher operations
- [x] Basic detection and byte analysis
- [x] Tests using `unittest`

### Supported operations

**Base encodings:** hex, base2, base8, base10, base32, base32hex, base36, base58, base62, base64, base64url, base85, ascii85, z85

**Text:** URL, HTML, quoted-printable, Unicode escape, ROT13, ROT-N, ROT47, Atbash, Morse, A1Z26

**Other:** reverse, XOR, gzip, zlib, deflate, bzip2, lzma

**Analysis:** byte stats, printable ratio, magic bytes

## Milestone 2 — Auto decoder [done]

- [x] `cryptix auto`
- [x] Automatic encoding detection
- [x] Multi-layer decoding
- [x] Best-first, BFS and beam search
- [x] Output scoring and ranking
- [x] Flag detection
- [x] Custom flag regex and prefixes
- [x] Known plaintext hints
- [x] Cycle detection and deduplication
- [x] Depth, time, memory and output limits
- [x] Replayable decoding chains
- [x] Explainable results
- [x] JSON and quiet output
- [x] Handle interrupted searches
- [x] Tests and benchmarks

### How it works

Tries different decoding chains, scores the outputs and returns the most likely results.

Uses things like text readability, entropy, file signatures and flag patterns to rank candidates.

Only runs safe, low-cost operations automatically.

### Testing

- 77 tests for the auto decoder
- Around 1,900 two-layer decoding chains tested
- 99–100% recovery on generated multi-layer samples
- Usually around 1–3 ms per search in the synthetic benchmark

Benchmarks are from generated test data, not actual CTF challenges.

See `benchmarks/auto_corpus.py` for the benchmark code.

### Still needs work

- [ ] Test on more real CTF challenges
- [ ] Improve scoring and detection
- [ ] Reduce false-positive flag matches
- [ ] Improve handling of short or non-English text
- [ ] Add safer regex handling
- [ ] Streaming for large files
- [ ] Improve performance on harder searches

Some decoding paths are intentionally skipped to keep searches manageable. Keyed operations like XOR will need dedicated solvers.

## Milestone 3 — Cracking [not started]

- [ ] `cryptix crack`
- [ ] Caesar, Affine, Vigenere
- [ ] Atbash, Rail Fence, Columnar, substitution
- [ ] Frequency analysis
- [ ] Chi-squared and n-grams
- [ ] Index of coincidence / Kasiski
- [ ] Hamming distance
- [ ] Single-byte XOR cracking
- [ ] Repeating-key XOR cracking
- [ ] XOR key analysis

## Milestone 4 — RSA [not started]

- [ ] `cryptix rsa`
- [ ] RSA key analysis
- [ ] Modular arithmetic tools
- [ ] Factorization
- [ ] Wiener attack
- [ ] Small exponent attacks
- [ ] Common modulus
- [ ] CRT and other RSA utilities

## Milestone 5 — More tools [not started]

- [ ] More bases (Base45, Base91, Base92, Base100, etc.)
- [ ] ASCII and Unicode codecs
- [ ] More classical ciphers
- [ ] Bitwise and byte operations
- [ ] String and byte manipulation
- [ ] Hash identification and verification
- [ ] `cryptix inspect`
- [ ] Hexdump and byte analysis
- [ ] Lazy plugin loading

## Milestone 6 — Cleanup [not started]

- [ ] Documentation
- [ ] CONTRIBUTING.md
- [ ] Plugin benchmarks
- [ ] Test on different Linux distros
- [ ] Verify pipx / uv installation
- [ ] Improve CLI output
- [ ] Shell completion

## Other stuff to fix

- [ ] Verify Typer CLI
- [ ] Verify Rich output
- [ ] Run pytest, Ruff and mypy
- [ ] Add Hypothesis tests
- [ ] Test third-party plugin installation
- [ ] Speed up the test suite

The `unittest` suite passes, but some dependencies weren't available in the original testing environment. Typer, Rich and the other development tools still need proper verification.

---

Currently at Milestone 2/6. Auto decoding works, cracking and RSA are next.