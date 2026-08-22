# Strict postscan manifest

These reports supersede the verdicts emitted by the original remote scanner.
They were produced by applying the then-current strict scanner to retained,
independently hashed assembly. No assembly was rebuilt during this postscan.
The later scanner revision makes the external-symbol allowlist portable to
Linux `awk` and adds a second exact reviewed Linux O3 assembly hash; these
historical report bytes and their producing scanner hash remain frozen below.

- Scanner SHA-256 used for these retained postscans:
  `5b59c9c4dc45d6d2512a9cc88b4e29aef5dd3b445985a979519d2869b9a9f202`
- Scanner self-test SHA-256 used for these retained postscans:
  `d3fc18f9f56b4f70733e9fc069e081d93c9f8d7632b24c15b45f4e95f2f1ce4e`
- Rust compiler commit supplied to the scanner:
  `1159e78c4747b02ef996e55082b704c09b970588`

| Report | Input assembly SHA-256 | Report SHA-256 | Provenance |
|---|---|---|---|
| `linux-x86_64-O0.txt` | `72ad16d2e3ee8b609182d6ac8f65271f2c10ed4c038ee403a285b88839db98fd` | `f7c597174fecc7b14cde592380e3f15308e4c60d5ac46703abc767ad59ca5ed4` | Verified raw bundle `f98775df...88aed7` |
| `linux-x86_64-O3.txt` | `c0202cfb26d0c5657cfcdb9b3576a1ddfb4fbee7ecc6f5be2b4f0c9d3173114d` | `cb4056904563cd1f4a143b1e17d17c970982b1df277eae878686e5fcdaa997b9` | Verified raw bundle `f98775df...88aed7` |
| `macos-x86_64-O0.txt` | `8d732576528c881826e1151046941cf75e9bc4b9820e11404c46c5b834af918f` | `f77688a63536aa026cf0ee6d736b429b5e483d382cdf40746225b8141c69dd4c` | Packaged source `1c4435bb...9686b11` |
| `macos-x86_64-O3.txt` | `004cf21af175d63c60a993b4249da7c754235ff4d46e9357d3a8510ade922a4b` | `36cb20e7e53c800c2f22cddd914212147c536af36e4b32690b59f27a9a06dcb8` | Packaged source `1c4435bb...9686b11` |
| `macos-aarch64-O0.txt` | `1afbfbc4dcd0d45433fc3942cd3f004e7b33163c0e665002e1b26b84f6e37bd2` | `08a07ad7b2126280a06798cc2c61486161d00bb847f34f999fe3edccaf3af6ed` | Packaged source `1c4435bb...9686b11` |
| `macos-aarch64-O3.txt` | `3146205c05a5fba34c0a71472f2a5b129ab2058bf2170421fa2cf579874fddb2` | `431df3629547985a1c548bdf15f5133bfd2424ff705dcad95ef5043eadbac7ce` | Packaged source `1c4435bb...9686b11` |

The Linux raw bundle was copied back and every internal `SHA256SUMS` entry was
verified before postscan. Its full SHA-256 is
`f98775dffcba40cc61481df1fa7849f6ebe876247f112f79db09b2caf888aed7`.
The abbreviated provenance strings in the table refer to these full hashes:
source archive
`1c4435bbc26d832c5728c27c0767af9c76a9851b9b9038d5fb0ebd7369686b11`
and raw bundle
`f98775dffcba40cc61481df1fa7849f6ebe876247f112f79db09b2caf888aed7`.

The command form was:

```text
awk -v arch=ARCH -v target_triple=TARGET -v optimization=LEVEL \
  -v compiler_commit=1159e78c4747b02ef996e55082b704c09b970588 \
  -v assembly_sha256=ASSEMBLY_SHA256 -f scripts/ct-scan.awk ASSEMBLY
```
