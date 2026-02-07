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

## Remaining

### Nice-to-have / follow-up

- [ ] PKCS#7 signing integration
  - Actual signature generation (currently only stores pre-built blobs)
  - Needs a signing key management story
  - Probably `openssl` or `ring` crate for PKCS#7 DER construction
- [ ] Registry push support for signature artifacts
  - Push artifact manifest + blobs to registry alongside the image
  - Requires registry write support (not yet in composefs-rs)
- [ ] Registry pull support for signature artifacts
  - Query `/referrers/{digest}` API during pull
  - Download and store signature artifacts locally
- [ ] Per-layer EROFS persistence
  - Currently per-layer digests are computed transiently
  - Could store per-layer EROFS in repo for later verification
- [ ] `cfsctl` CLI integration
  - `cfsctl sign` / `cfsctl verify` commands
  - `cfsctl seal --sign` to seal + create signature artifact in one step
- [ ] Cosign/sigstore integration
  - Verify cosign signatures on the signature artifact itself
  - The artifact is "just another OCI manifest" so cosign can sign it

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

Trust model: the signature artifact provides composefs fsverity digests for
each component. With PKCS#7 signatures, the kernel enforces the digest at
`FS_IOC_ENABLE_VERITY` time. Without signatures (digest-only mode), the
artifact provides a verifiable record of expected digests but enforcement
is up to the consumer.
