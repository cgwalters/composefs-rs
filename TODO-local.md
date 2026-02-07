# OCI Signing Artifact — Local TODO

Tracking work for PR #224: separate signing OCI artifact with Referrer pattern.

Branch: `sealing-impl` (based on `oci-native-layer` / PR #216)

## Done

- [x] `ComposeFsAlgorithm` type (`crates/composefs/src/fsverity/algorithm.rs`)
  - Parse/display `sha512-12` format, constants, private fields w/ accessors
- [x] Per-layer composefs digest computation (`image.rs:compute_per_layer_digests`)
  - Builds single-layer EROFS per layer, computes fsverity digest
  - Security doc: must use trusted `config_verity`
- [x] Signature artifact builder + parser (`crates/composefs-oci/src/signature.rs`)
  - `SignatureArtifactBuilder`: typed algorithm, entry ordering enforcement
  - `parse_signature_artifact`: validates artifact type, media types, digest
    format/length, ordering, requires subject
  - `ParsedSignatureArtifact` return type with subject
- [x] Security hardening of parser (trust boundary validation)
  - Digest hex validation + length vs algorithm cross-check
  - Artifact type + layer media type validation
  - Entry ordering validation (manifest < config < layer < merged)
- [x] Referrer index (`oci_image.rs`)
  - `add_referrer()` / `list_referrers()` via `oci-referrers/{subject}/` symlinks
- [x] Store/discover signature artifacts (`signature.rs`)
  - `store_signature_artifact()`: writes blobs + manifest + referrer link
  - `find_signature_artifacts()`: discovers by subject, filters by artifact type
- [x] Spec updates (`doc/plans/oci-sealing-spec.md`, `oci-sealing-impl.md`)
  - Full Signature Artifacts section with example manifest JSON
- [x] Tests: 71 tests passing in composefs-oci, all clean on clippy
- [x] Security review of referrer storage/discovery code
  - No critical issues found; path traversal blocked by encode_tag()
  - Referrer symlinks are GC roots (walked recursively by repository GC)
  - Design decision: artifacts persist independently until explicit removal
- [x] GC handling for referrer artifacts
  - `cleanup_dangling_referrers()`: removes referrer entries for GC'd subjects
  - `remove_referrer()` / `remove_referrers_for_subject()`: explicit cleanup APIs
  - Two-pass GC: untag → gc → cleanup_dangling → gc removes artifacts
- [x] End-to-end integration test (`test_end_to_end_seal_sign_verify`)
  - seal → compute_per_layer_digests → build artifact → store → discover → verify
- [x] `fsverity_formatted_digest` construction (`crates/composefs/src/fsverity/formatted_digest.rs`)
  - Kernel-compatible byte layout: magic + LE algorithm + LE size + digest
- [x] `fs_ioc_enable_verity_with_sig` ioctl wrapper
  - Accepts optional PKCS#7 DER blob for kernel-level signature enforcement
  - Existing `fs_ioc_enable_verity` delegates to it with `None`
- [x] PKCS#7 signing library (`crates/composefs-oci/src/signing.rs`, feature-gated)
  - `FsVeritySigningKey`: load PEM cert+key, sign digests → DER PKCS#7
  - `FsVeritySignatureVerifier`: verify PKCS#7 against trusted cert
  - Input validation: digest length vs algorithm, cert-key mismatch check
  - 8 unit tests including wrong-digest, wrong-cert, tampered-sig rejection
- [x] External `openssl` CLI workflow documented + tested
  - Spec section with exact byte layout and shell commands
  - `tests/test-openssl-sign.sh`: 9 tests including wrong-cert rejection
- [x] `cfsctl oci sign` and `cfsctl oci verify` CLI commands
  - sign: seal check → per-layer digests → PKCS#7 sign → store artifact
  - verify: discover artifacts → recompute digests → compare
  - Errors on missing artifacts, errors when --cert used (blob verification TBD)
- [x] Security review of signing implementation
  - Cryptographic correctness verified (flags, formatted_digest layout)
  - Fixed -noverify in docs and tests
  - Trust model documented (application-level vs kernel-level signatures)
- [x] Tests: 79 passing in composefs-oci (with signing), 9 shell tests
- [x] FUSE verified object opens (`VerifiedObject` enum, `VerifyMode`)
  - `open_object_verified()`: kernel fsverity fast path → userspace fallback
  - `VerifiedObject::Fd` (kernel-verified) vs `VerifiedObject::Data` (no TOCTOU)
  - FUSE daemon uses `VerifyMode::Always` by default
  - Fixed `mount_fuse()` to use calling user UID/GID
- [x] Unprivileged verification architecture documented in spec + impl doc
  - FUSE becomes enforcement point when kernel path unavailable
  - Trust store options: file-based, user keyring, per-repository

## Remaining

### Follow-up work

- [ ] Wire up PKCS#7 blob verification in `cfsctl oci verify --cert`
  - Need to fetch blobs from artifact layers via `open_blob()`
  - Then verify with `FsVeritySignatureVerifier`
- [ ] FUSE mount-time signature artifact verification
  - Verify signature artifacts against trusted certs before serving
  - `--trust-cert` flag on FUSE mount command
- [ ] Registry push/pull for signature artifacts
  - Push artifact manifest + blobs alongside image
  - Query `/referrers/{digest}` API during pull
- [ ] `cfsctl seal --sign` convenience command
  - Seal + create signature artifact in one step
- [ ] Kernel-level signature enforcement integration testing
  - Requires VM with ext4/btrfs + `.fs-verity` keyring configured
  - Test `enable_verity_raw_with_sig` with real filesystem
- [ ] Linux user keyring integration for trust certificates
  - Read certs from `@u` keyring via `keyutils`
- [ ] Cosign/sigstore integration
  - Sign/verify the signature artifact manifest itself

## Architecture Notes

The signature artifact sits alongside the source image in the repo:

```
streams/
  oci-manifest-sha256:aaa...   (source image manifest)
  oci-manifest-sha256:bbb...   (signature artifact manifest)
  refs/
    oci/
      myimage:latest -> ../../oci-manifest-sha256:aaa...
    oci-referrers/
      sha256:aaa.../
        sha256:bbb... -> ../../../oci-manifest-sha256:bbb...
```

The artifact's `subject` field points to the source image's manifest digest.
Discovery: `list_referrers(repo, "sha256:aaa...")` returns the artifact.

Trust model: two levels of signature enforcement are supported.

**Application-level** (primary): PKCS#7 signatures are stored in the OCI
signature artifact and verified in userspace by composefs tooling. This
works with standard OCI registries and doesn't require kernel configuration.

**Kernel-level** (optional): PKCS#7 blobs can be passed to
`FS_IOC_ENABLE_VERITY` via `enable_verity_raw_with_sig()`. The kernel
verifies against the `.fs-verity` keyring. Requires root to configure.

Both use the same PKCS#7 DER format over `fsverity_formatted_digest`,
so signatures are interchangeable between the two models.
