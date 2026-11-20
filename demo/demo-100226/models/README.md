# Model registry

One directory per checkpoint: `models/<id>/manifest.yaml` plus a detached Ed25519 signature `manifest.yaml.sig` (base64).
Unsigned, tampered or invalid manifests are rejected at load. Trusted public keys: `MODEL_REGISTRY_PUBKEYS` (PEM).
See `Consumption/MODEL_REGISTRY.md`.
