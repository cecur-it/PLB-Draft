import { initializeApp, getApps } from 'firebase/app';
import { initializeFirestore, doc, setDoc, getFirestore } from 'firebase/firestore';
import { isAirgapProfile } from './profile';
import type { User } from '../src/types';
import { secondaryProfileProjection } from '../src/lib/accountProfile';

let firestoreInstance: any = null;

export function getResolvedFirebaseConfig() {
  // Firebase configuration is supplied explicitly; onprem/airgap require FIREBASE_* values.
  return {
    apiKey: process.env.FIREBASE_API_KEY || process.env.VITE_FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || process.env.VITE_FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID || process.env.VITE_FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID,
    measurementId: process.env.FIREBASE_MEASUREMENT_ID,
    firestoreDatabaseId: process.env.FIREBASE_DATABASE_ID || process.env.VITE_FIREBASE_DATABASE_ID || '(default)',
  };
}

/** True when Firestore may be used: never on airgap, and only with a resolved apiKey + projectId. */
export function isFirestoreEnabled(): boolean {
  if (isAirgapProfile()) return false;
  const config = getResolvedFirebaseConfig();
  return Boolean(config.apiKey && config.projectId);
}

export function getBackendFirestore() {
  if (firestoreInstance) return firestoreInstance;
  if (!isFirestoreEnabled()) {
    throw new Error('Firestore is not configured for this deployment profile.');
  }

  const config = getResolvedFirebaseConfig();
  const app = getApps().length === 0 ? initializeApp(config) : getApps()[0];
  firestoreInstance = config.firestoreDatabaseId && config.firestoreDatabaseId !== '(default)'
    ? initializeFirestore(app, {}, config.firestoreDatabaseId)
    : getFirestore(app);

  return firestoreInstance;
}

export const firestoreUserProjection = secondaryProfileProjection;

/** Persists public profile fields only; credential hashes never leave the account registry. */
export async function syncUserToFirestore(user: User) {
  if (!isFirestoreEnabled()) return;
  try {
    const db = getBackendFirestore();
    const userDocRef = doc(db, 'users', user.id);
    // Replace the secondary profile document so legacy credential or unknown fields are not retained.
    await setDoc(userDocRef, firestoreUserProjection(user));
    console.log(`[FirestoreSync] Synchronized profile for user '${user.username}' (${user.id}) to Firestore.`);
  } catch (err) {
    console.warn(`[FirestoreSync] Failed to sync user '${user.username}' to Firestore:`, err);
  }
}
