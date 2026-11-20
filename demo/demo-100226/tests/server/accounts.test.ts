import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BOOTSTRAP_ADMIN_ID,
  commitUser,
  hydrateUserRegistry,
  persistUser,
  validateProfileUpdate,
  validateRegistration,
} from '../../server/accounts';
import { SOCDatabase } from '../../server/db';
import { firestoreUserProjection } from '../../server/firestoreSync';
import { sanitizeUser } from '../../server/routes/auth';
import type { User } from '../../src/types';

function account(overrides: Partial<User> = {}): User {
  return {
    id: 'usr-test-operator',
    username: 'operator',
    email: 'operator@example.invalid',
    passwordHash: 'credential-hash-that-must-not-leak',
    role: 'analyst',
    displayName: 'Test Operator',
    title: 'Analyst',
    department: 'Security Operations',
    avatar: '/avatars/av-1.svg',
    createdAt: '2026-01-01T00:00:00.000Z',
    lastLogin: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

test('commitUser awaits persistence before exposing a new account locally', async () => {
  const database = new SOCDatabase();
  database.users.splice(0);
  const user = account();
  let persisted: User | undefined;

  const committed = await commitUser(database, user, async (value) => {
    persisted = value;
    assert.equal(database.getUserById(user.id), undefined);
  });

  assert.deepEqual(persisted, user);
  assert.deepEqual(committed, user);
  assert.deepEqual(database.getUserById(user.id), user);
});

test('failed durable commits do not create or mutate the local registry', async () => {
  const database = new SOCDatabase();
  database.users.splice(0);
  const user = account();

  await assert.rejects(
    commitUser(database, user, async () => {
      throw new Error('database unavailable');
    }),
    /database unavailable/,
  );
  assert.equal(database.getUserById(user.id), undefined);

  const existing = account({ displayName: 'Original Name' });
  database.createUser(existing);
  await assert.rejects(
    commitUser(database, { ...existing, displayName: 'Changed Name' }, async () => {
      throw new Error('update was not durable');
    }),
    /update was not durable/,
  );
  assert.equal(database.getUserById(existing.id)?.displayName, 'Original Name');
});

test('persistUser requires a confirmed PostgreSQL write only in PostgreSQL mode', async (t) => {
  const previous = process.env.CS3_PERSISTENCE;
  t.after(() => {
    if (previous === undefined) delete process.env.CS3_PERSISTENCE;
    else process.env.CS3_PERSISTENCE = previous;
  });

  process.env.CS3_PERSISTENCE = 'postgres';
  await assert.rejects(persistUser(account(), async () => false), /persistence is unavailable/);

  process.env.CS3_PERSISTENCE = 'memory';
  let called = false;
  await persistUser(account(), async () => {
    called = true;
    return false;
  });
  assert.equal(called, false);
});

test('hydration sanitizes stored avatars and retains the environment-derived bootstrap hash', async (t) => {
  const previous = process.env.CS3_BOOTSTRAP_ADMIN_PASSWORD;
  process.env.CS3_BOOTSTRAP_ADMIN_PASSWORD = 'test-only-bootstrap-password';
  t.after(() => {
    if (previous === undefined) delete process.env.CS3_BOOTSTRAP_ADMIN_PASSWORD;
    else process.env.CS3_BOOTSTRAP_ADMIN_PASSWORD = previous;
  });

  const database = new SOCDatabase();
  const local = database.getUserById(BOOTSTRAP_ADMIN_ID);
  assert.ok(local);
  const stored = {
    ...local,
    passwordHash: 'persisted-hash-must-not-override-rotation',
    displayName: 'Persisted Administrator Name',
    avatar: 'https://example.invalid/legacy-avatar.png',
  };

  assert.equal(await hydrateUserRegistry(database, async () => [stored]), 1);
  const hydrated = database.getUserById(BOOTSTRAP_ADMIN_ID);
  assert.equal(hydrated?.displayName, 'Persisted Administrator Name');
  assert.equal(hydrated?.passwordHash, local.passwordHash);
  assert.equal(hydrated?.avatar, '/avatars/av-2.svg');
});

test('public and Firestore projections exclude credential hashes and unknown persisted fields', () => {
  const record = account() as User & { unexpectedSecret?: string };
  record.unexpectedSecret = 'must-not-be-copied';

  for (const projection of [sanitizeUser(record), firestoreUserProjection(record)]) {
    assert.equal('passwordHash' in projection, false);
    assert.equal('unexpectedSecret' in projection, false);
    assert.equal(projection.username, record.username);
  }
});

test('registration enforces the UI password minimum and profile edits cannot smuggle avatars', () => {
  const body = {
    username: 'new-operator',
    email: 'new@example.invalid',
    password: '12345',
    role: 'analyst',
    displayName: 'New Operator',
  };
  assert.match(validateRegistration(body).error || '', /at least 6 characters/);
  assert.equal(validateRegistration({ ...body, password: '123456' }).error, undefined);
  assert.match(validateProfileUpdate({ avatar: 'https://example.invalid/a.png' }).error || '', /avatar upload or delete/i);
});
