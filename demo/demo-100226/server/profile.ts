/**
 * Deployment profile helpers. The profile (cloud | onprem | airgap) is chosen by
 * cs3-launcher.mjs and exported to the console as CS3_PROFILE.
 *
 * - Firestore is only used when explicitly configured via FIREBASE_* variables,
 *   and never on airgap.
 * - The platform never generates demo, mock or simulated telemetry. CS3_DEMO_MODE is a removed
 *   switch: when it is set to "true" the console refuses to start (see assertNoDemoMode).
 */
export type CS3Profile = 'cloud' | 'onprem' | 'airgap';

export function getProfile(): CS3Profile {
  const raw = (process.env.CS3_PROFILE || 'cloud').trim().toLowerCase();
  return raw === 'onprem' || raw === 'airgap' ? raw : 'cloud';
}

export function isOfflineProfile(): boolean {
  return getProfile() !== 'cloud';
}

export function isAirgapProfile(): boolean {
  return getProfile() === 'airgap';
}

export function isDemoMode(): boolean {
  return process.env.CS3_DEMO_MODE === 'true';
}

/** Fails closed so an old deployment config cannot silently run without the (removed) demo data. */
export function assertNoDemoMode(): void {
  if (isDemoMode()) {
    throw new Error(
      'CS3_DEMO_MODE=true is no longer supported: the platform only renders real telemetry from real endpoints. Unset CS3_DEMO_MODE.'
    );
  }
}
