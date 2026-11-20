# Model Registry (INF-002 / INF-004)

Code: `server/inference/registry.ts`. Entries live in `models/<id>/manifest.yaml` with a detached base64 Ed25519 signature `manifest.yaml.sig`.

* **Fail closed:** a manifest that is missing, unsigned, signed by an untrusted key, tampered, or malformed is rejected and never registered. With no trusted keys configured (`MODEL_REGISTRY_PUBKEYS`, PEM) nothing loads.
* **Digest pinning:** `digest: sha256:<64 hex>`; `verifyArtifact()` hashes a weights file/bundle and refuses mismatches.
* **Promotion:** `staging` -> `approved` via `promote(id, evalScore)`. Blocked unless the license is on the allowlist (`MODEL_LICENSE_ALLOWLIST`, default Apache-2.0, MIT, BSD-3-Clause; unverified placeholders are rejected) and the eval score meets `eval.passThreshold`. Only approved models are returned by `resolve(role)`.
* **Signing:** `openssl pkeyutl -sign -rawin -inkey key.pem -in manifest.yaml | base64 > manifest.yaml.sig` (Ed25519). Cosign/gpg integration can wrap the same check later.

Not yet wired: the gateway still uses env-configured model names (it does not resolve through the registry), and eval records/no-regression gates arrive with INF-008. No real checkpoint manifests are committed; pin released checkpoints at build time.

## Contract Changes
New manifest schema consumed by the registry (matches the build plan's `models/<checkpoint>/manifest.yaml`); signature file is new.

## Eval-gated promotion (INF-008/INF-009)
`promoteWithEval()` and `POST /api/models/:id/promote` (role `model_curator` only) take the score from `eval/results` records produced by `npm run eval -- --runner gateway ...`, not from the request. See `eval/README.md`.
