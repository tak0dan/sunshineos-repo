"""Stage A trust primitives for the Evolution Engine.

The production bootstrap must be a small Rust executable with a pinned trust
root, but the *protocol* can be specified and tested independently.  This
package implements the protocol-level rules:

* the repository index must be signed by a currently trusted key;
* artifacts must match signed SHA-256 digests;
* key rotation must be signed by an already-trusted key (never auto-trusted
  because it was downloaded from the same server);
* bootstrap protocol/core compatibility must be checked before transformation;
* the Core handoff entrypoint must itself be a signed, verified artifact.

Cryptographic primitive verification is injected as a callable so tests remain
dependency-free.  A GPG-backed verifier is provided for real deployments.
"""
from .model import (
    Artifact,
    KeyRotation,
    SignedDocument,
    StageAReport,
    TrustIndex,
    TrustPolicy,
    TrustRoot,
    canonical_bytes,
    gpg_verifier,
    sha256_file,
    verify_receipt,
    verify_stage_a,
    verify_signed_document,
)

__all__ = [
    "Artifact",
    "KeyRotation",
    "SignedDocument",
    "StageAReport",
    "TrustIndex",
    "TrustPolicy",
    "TrustRoot",
    "canonical_bytes",
    "gpg_verifier",
    "sha256_file",
    "verify_receipt",
    "verify_stage_a",
    "verify_signed_document",
]
