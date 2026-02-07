# OCI Sealing Specification for Composefs

This document defines how composefs integrates with OCI container images to provide cryptographic verification of complete filesystem trees. The specification is based on original design discussion in [composefs/composefs#294](https://github.com/composefs/composefs/issues/294).

## Problem Statement

Container images need cryptographic verification that efficiently covers the entire filesystem tree without requiring re-hashing of all content. Current OCI signature mechanisms (cosign, GPG) can sign manifests, but verifying the complete filesystem tree at runtime is extremely expensive because the only known digests are those of the tar layers.

Hence verifying the integrity of an individual file would require re-synthesizing the entire tarball (using tar-split or equivalent) and computing its digest.

## Solution

The core primitive of composefs is fsverity, which allows incremental online verification of individual files. The complete filesystem tree metadata is itself stored as a file which can be verified in the same way. The critical design question is how to embed the composefs digest within OCI image metadata such that external signatures can efficiently cover the entire filesystem tree.

## Design Goals

The OCI sealing specification aims to provide efficient verification where a signature on an OCI manifest cryptographically covers the entire filesystem tree without re-hashing content. The specification defines standardized metadata locations for composefs digests and supports future format evolution without breaking existing images.

Incremental verification must be supported, enabling verification of individual layers or the complete flattened filesystem. The design accommodates both registry-provided sealed images and client-side sealing workflows while maintaining backward compatibility with existing OCI tooling and registries.

## Core Design

### Composefs Digest Storage

The composefs fsverity digest is stored as a label in the OCI image config:

```json
{
  "config": {
    "Labels": {
      "containers.composefs.fsverity": "sha256:a3b2c1d4e5f6..."
    }
  }
}
```

The config represents the container's identity rather than transport metadata. Manifests are transport artifacts that can vary across different distribution mechanisms. Adding the composefs label creates a new config and thus a new manifest, establishing the sealed image as a distinct artifact. This means sealing an image produces a new image with a different config digest, where the original unsealed image and sealed image coexist as separate artifacts that registries treat as distinct versions.

### Digest Type

The primary digest is the fs-verity digest of the EROFS image containing the merged, flattened filesystem. This digest provides fast verification at mount time through kernel fs-verity checks and is deterministic: the same input layers always produce the same EROFS digest. The digest covers the complete filesystem tree including all metadata such as permissions, timestamps, and extended attributes.

### Merged Filesystem Representation

The config label contains the digest of the merged, flattened filesystem. This represents the final filesystem state after extracting all layers in order, applying whiteouts (`.wh.` files), merging directories where the most-derived layer wins for metadata, and building the final composefs EROFS image.

### Per-Layer Digests (Future Extension)

Per-layer composefs digests may be added as manifest annotations:

```json
{
  "manifests": [
    {
      "layers": [
        {
          "digest": "sha256:...",
          "annotations": {
            "containers.composefs.layer.fsverity": "sha256:..."
          }
        }
      ]
    }
  ]
}
```

Per-layer digests enable incremental verification during pull, create caching opportunities where shared layers have known composefs digests, and enable runtime choice between flattened versus layered mounting strategies.

### Trust Chain

The trust chain for composefs-verified OCI images flows from external signatures through the manifest to the complete filesystem:

```
External signature (cosign/sigstore/GPG)
  ↓ signs
OCI Manifest (includes config descriptor)
  ↓ digest reference
OCI Config (includes containers.composefs.fsverity label)
  ↓ fsverity digest
Composefs EROFS image
  ↓ contains
Complete merged filesystem tree
```

## Verification Process

Verification begins by fetching the manifest from the registry and verifying the external signature on the manifest. The config descriptor is extracted from the manifest, and the config is fetched and verified to match the descriptor digest. The `containers.composefs.fsverity` label is extracted from the config, and the composefs image is mounted with fsverity verification. The kernel verifies the EROFS matches the expected fsverity digest.

The security property is that signature verification happens once, while filesystem verification is delegated to kernel fs-verity with lazy or eager verification depending on mount options.

## Metadata Schema

### Config Labels

The image config contains the following labels:

The `containers.composefs.fsverity` label (string) contains the fsverity digest of the merged composefs EROFS in the format `<algorithm>:<digest>` where algorithm is `sha256` or `sha512`.

The `containers.composefs.version` label (string, optional) contains the seal format version such as `1.0`.

### Descriptor Annotations

A descriptor may have the following annotation:

The `containers.composefs.layer.fsverity` annotation (string, optional) contains the fsverity digest of that individual layer.

### Label versus Annotation Semantics

Config labels store the authoritative digest because the config represents container identity while the manifest is a transport artifact. Labels are part of the container specification and create a new artifact (sealed image) rather than mutating metadata. Manifest annotations are retained for discovery purposes, allowing registries to identify sealed images without parsing configs and enabling clients to optimize pull strategies.

## Verification Modes

### Eager Verification

Eager verification occurs during image pull. The composefs image is immediately created and its digest is verified against the config label. This makes the container ready to mount immediately after pull and is suitable for boot scenarios where operations should be read-only.

### Lazy Verification

Lazy verification defers composefs creation until first mount. The pull operation stores layers and config but doesn't build the composefs image. On mount, the composefs image is built and verified against the label. This mode is suitable for application containers where many images may be pulled but only some are actually used.

## Security Model

### Registry-Provided Sealed Images

For images sealed by the registry or vendor, the seal is computed during the build process and the seal label is embedded in the published config. An external signature covers the manifest. Clients verify the chain: signature → manifest → config → composefs. Trust is placed in the image producer and the signature key.

### Client-Sealed Images

For images sealed locally by the client, the client pulls an image that may be unsigned and computes the seal locally. The client stores the sealed config in its local repository. On boot or mount, the client can re-fetch the manifest from the network to verify freshness. Trust is placed in the network fetch (TLS) and local verification.

### Kernel-Level vs Application-Level Signatures

composefs supports two complementary signature mechanisms:

**Application-level signatures** are stored in OCI signature artifacts (see "Signature Artifacts" above). The PKCS#7 blobs are verified in userspace by composefs tooling or policy engines. This is the primary model: it works with standard OCI registries, doesn't require kernel configuration, and integrates naturally with container signing workflows (cosign, notation, etc.).

**Kernel-level signatures** use the Linux kernel's `.fs-verity` keyring. When a CA certificate is loaded into the keyring, the kernel requires a valid PKCS#7 signature when `FS_IOC_ENABLE_VERITY` is called — unsigned files cannot have verity enabled at all. This provides stronger enforcement (the kernel itself rejects unsigned content) but requires root access to configure the keyring and is independent of OCI semantics.

Both models use the same PKCS#7 DER format over the same `fsverity_formatted_digest` structure, so signatures are interchangeable. An OCI signature artifact's PKCS#7 blobs can be passed to `FS_IOC_ENABLE_VERITY`, and kernel-level signatures can be stored in OCI artifacts.

For the composefs repository object store, verity is always enabled without signatures (the fsverity digest itself is the trust anchor, verified against the expected value from the OCI config or signature artifact). Kernel-level signature enforcement is an optional, additional layer for environments that require it.

## Attack Mitigation

### Digest Mismatch

If a config label doesn't match the actual EROFS, the mount operation fails the fsverity check. Verification APIs can detect this condition before mounting.

### Signature Bypass

Any attempt to modify the config label without updating the signature fails because the signature covers the manifest, which covers the config digest. Any config change produces a new digest, breaking the signature chain.

### Rollback Attack

For application containers, re-fetching the manifest on boot checks for freshness. For host systems, embedding the manifest in the boot artifact prevents rollback.

### Layer Confusion

Per-layer fsverity annotations allow verification before merging. Implementations that maintain digest maps can link layer SHA256 digests to fsverity digests.

## Relationship to Booting with composefs

OCI sealing is independent from but complementary to composefs boot verification (UKI, BLS, etc.). These are separate mechanisms operating at different stages of the system lifecycle with different trust models.

OCI sealing provides runtime verification of container images distributed through registries. The trust chain typically flows from external signatures (cosign, GPG) through OCI manifests to composefs digests.

Boot verification is designed to be rooted in extant hardware mechanisms such as Secure Boot. The composefs digest is embedded directly in boot artifacts (UKI `.cmdline` section, BLS entry `options` field) and verified during early boot by the initramfs.

These mechanisms work together in a complete workflow where a sealed OCI image can be pulled from a registry, verified through OCI sealing, and then used to build a boot artifact with the composefs digest embedded for boot verification. However, each mechanism operates independently with its own trust anchor and threat model.

## Signature Artifacts

In addition to embedding the composefs digest in the image config, a separate OCI artifact can carry composefs fsverity digests (and optionally PKCS#7 signatures) for each component of the image. This follows the [OCI Referrers](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers) pattern: the artifact references the source image manifest via the `subject` field, making it discoverable through the registry `/referrers` API — similar to how cosign attaches signatures.

### Artifact Structure

The signature artifact is an OCI image manifest with:

- `artifactType` set to `application/vnd.composefs.signature.v1`
- An empty config descriptor with media type `application/vnd.oci.empty.v1+json` (the 2-byte `{}` blob), per OCI artifacts guidance
- A `subject` descriptor pointing to the source image manifest, enabling referrer discovery
- A manifest-level `composefs.algorithm` annotation encoding the fsverity algorithm as `{hash}-{blocksizebits}` (e.g. `sha512-12` for SHA-512 with 4096-byte blocks, `sha256-12` for SHA-256 with 4096-byte blocks)

Each layer in the artifact represents one signed component. Layers use media type `application/vnd.composefs.signature.v1+pkcs7`. The layer blob is either a PKCS#7 DER signature or empty (zero bytes) for digest-only entries where the digest is recorded but no cryptographic signature is attached.

### Layer Annotations

Each layer descriptor carries two annotations:

- `composefs.signature.type` — what this entry covers. Values are:
  - `manifest` — the OCI manifest JSON
  - `config` — the OCI config JSON
  - `layer` — an individual composefs layer EROFS
  - `merged` — the merged (flattened) composefs filesystem
- `composefs.digest` — the fsverity digest as a hex string

### Layer Ordering

Layers MUST appear in the following order: manifest, config, layers (in manifest order), merged. Multiple `layer` entries appear in the same order as the layers in the source image manifest. Multiple `merged` entries may appear if rolling merges are recorded.

### Example Artifact Manifest

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.composefs.signature.v1",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:...",
      "size": 0,
      "annotations": {
        "composefs.signature.type": "manifest",
        "composefs.digest": "abcdef..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:...",
      "size": 0,
      "annotations": {
        "composefs.signature.type": "config",
        "composefs.digest": "123456..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:...",
      "size": 0,
      "annotations": {
        "composefs.signature.type": "layer",
        "composefs.digest": "aabbcc..."
      }
    },
    {
      "mediaType": "application/vnd.composefs.signature.v1+pkcs7",
      "digest": "sha256:...",
      "size": 0,
      "annotations": {
        "composefs.signature.type": "merged",
        "composefs.digest": "ddeeff..."
      }
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
    "size": 7682
  },
  "annotations": {
    "composefs.algorithm": "sha512-12"
  }
}
```

## External Signing with openssl CLI

The PKCS#7 signatures used in composefs signature artifacts can be produced with the `openssl` command-line tool, without linking against libssl. This is useful for CI pipelines, air-gapped signing environments, or any context where shelling out to `openssl` is simpler than integrating a library.

### Constructing the `fsverity_formatted_digest`

The PKCS#7 signature must cover a specific byte structure called `fsverity_formatted_digest` (defined in the kernel at `include/uapi/linux/fsverity.h`). This is the same structure that the kernel reconstructs internally when verifying a signature.

**For SHA-256** (32-byte digest, total 44 bytes):

```
Bytes 0-7:   46 53 56 65 72 69 74 79  ("FSVerity" ASCII magic)
Bytes 8-9:   01 00                    (algorithm 1 = SHA-256, little-endian u16)
Bytes 10-11: 20 00                    (digest size 32 = 0x20, little-endian u16)
Bytes 12-43: <32 bytes of raw digest>
```

**For SHA-512** (64-byte digest, total 76 bytes):

```
Bytes 0-7:   46 53 56 65 72 69 74 79  ("FSVerity" ASCII magic)
Bytes 8-9:   02 00                    (algorithm 2 = SHA-512, little-endian u16)
Bytes 10-11: 40 00                    (digest size 64 = 0x40, little-endian u16)
Bytes 12-75: <64 bytes of raw digest>
```

### Shell commands for the complete workflow

```bash
# Generate a test key pair (one-time setup)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj '/CN=composefs-test'

# Given a hex fsverity digest (e.g. from cfsctl or fsverity-utils):
DIGEST_HEX="a3b2c1d4..."

# Construct the formatted_digest structure (SHA-256 example):
python3 -c "
import sys, struct
magic = b'FSVerity'
alg = struct.pack('<H', 1)      # SHA-256
size = struct.pack('<H', 32)
digest = bytes.fromhex('$DIGEST_HEX')
sys.stdout.buffer.write(magic + alg + size + digest)
" > /tmp/formatted_digest.bin

# Sign with openssl smime (PKCS#7 detached, DER output, no attributes):
openssl smime -sign -binary -in /tmp/formatted_digest.bin \
    -signer cert.pem -inkey key.pem -outform DER -noattr \
    -out signature.pkcs7.der

# Verify the signature:
openssl smime -verify -binary -in signature.pkcs7.der \
    -content /tmp/formatted_digest.bin \
    -inform DER -CAfile cert.pem
```

The `-CAfile` flag establishes the trust root for verification. The signing certificate (or its issuing CA) must be provided here. For self-signed certificates, the certificate itself serves as its own CA. **Do not use `-noverify`** — it disables certificate chain validation and defeats the purpose of signature verification.

The critical flags are:

- `-binary`: treat input as raw bytes, no MIME canonicalization
- `-noattr`: omit authenticated attributes (the kernel expects a bare signature)
- `-outform DER`: produce DER encoding, not PEM — the kernel expects DER

### Using `fsverity-utils` instead

```bash
# fsverity-utils can compute the digest and sign in one step:
fsverity sign myfile signature.der --key=key.pem --cert=cert.pem
```

This produces an identical PKCS#7 DER blob that can be used in composefs signature artifacts.

### Interoperability

Signatures produced by the `openssl` CLI, `fsverity-utils`, and composefs-rs's signing library are all interchangeable — they produce standard PKCS#7 DER blobs over the same `fsverity_formatted_digest` structure.

### Relationship to Config Labels

The signature artifact and the config label (`containers.composefs.fsverity`) serve complementary purposes. The config label embeds the merged digest directly in the image identity, making it available without fetching additional artifacts. The signature artifact provides per-component digests (manifest, config, individual layers, merged) and supports attaching PKCS#7 signatures without modifying the source image. Both mechanisms can be used together.

## Future Directions

### Dumpfile Digest as Canonical Identifier

The fsverity digest ties implementations to a specific EROFS format. A dumpfile digest (SHA256 of the composefs dumpfile format) would enable format evolution. This would be stored as an additional label `containers.composefs.dumpfile.sha256` alongside the fsverity digest.

The dumpfile format is format-agnostic, meaning the same dumpfile can generate different EROFS versions. This simplifies standardization since the dumpfile format is simpler than EROFS and provides future-proofing to migrate to composefs-over-squashfs or other formats.

The challenge is that verification becomes slower as it requires parsing a saved EROFS from disk to dumpfile format. Caching the dumpfile digest to fsverity digest mapping introduces complexity and security implications. A use case split might apply dumpfile digests to application containers (for format flexibility) while using fsverity digests for host boot (for speed with minimal skew).

### Integration with zstd:chunked

Both zstd:chunked and composefs add new digests to OCI images. The zstd:chunked table-of-contents (TOC) has high overlap with the composefs dumpfile format, as both are metadata about filesystem structure that identify files and their content. The TOC currently uses SHA256 while composefs requires fsverity.

Adding fsverity to zstd:chunked TOC entries would allow using the TOC digest as a canonical composefs identifier. This would support a direct TOC → dumpfile → composefs pipeline, with a single metadata format serving both zstd:chunked and composefs use cases.

### Three-Digest Model

To support both flattened and layered mounting strategies, three digests could be stored per image: a base image digest, a derived layers digest, and a flattened digest. This would enable mounting a single flattened composefs for speed, mounting base and derived separately to avoid metadata amplification, or verifying the base from upstream while only rebuilding derived layers. This aligns with the existing `org.opencontainers.image.base.digest` standard.

## References

**Design discussion**: [composefs/composefs#294](https://github.com/composefs/composefs/issues/294)

**Experimental implementations**:
- [composefs_experiments](https://github.com/allisonkarlitskaya/composefs_experiments)
- [composefs-oci-experimental](https://github.com/cgwalters/composefs-oci-experimental)

**Related issues**:
- [containers/container-libs#108](https://github.com/containers/container-libs/issues/108) - fsverity in zstd:chunked TOC
- [containers/container-libs#112](https://github.com/containers/container-libs/issues/112) - per-layer vs flattened
- [composefs/composefs#409](https://github.com/composefs/composefs/issues/409) - non-root mounting

**Standards**:
- [OCI Image Specification](https://github.com/opencontainers/image-spec)
- [Canonical JSON](https://wiki.laptop.org/go/Canonical_JSON)

## Contributors

This specification synthesizes ideas from Colin Walters (original design proposals and iteration), Allison Karlitskaya (implementation and practical refinements), and Alexander Larsson (security model and non-root mounting insights). Significant assistance from Claude Sonnet 4.5 was used in synthesis.
