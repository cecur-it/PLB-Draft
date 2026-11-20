import test from 'node:test';
import assert from 'node:assert/strict';
import { shouldCloseLoginModal } from '../../src/lib/authModalLifecycle';

const admin = { id: 'admin' };
const analyst = { id: 'analyst' };

test('a verified login transition closes the sign-in modal', () => {
  assert.equal(shouldCloseLoginModal({ isOpen: true, tab: 'login', previousUser: null, currentUser: admin }), true);
  assert.equal(shouldCloseLoginModal({ isOpen: true, tab: 'login', previousUser: admin, currentUser: analyst }), true);
});

test('same-account reauthentication closes when the server returns a refreshed user', () => {
  assert.equal(shouldCloseLoginModal({ isOpen: true, tab: 'login', previousUser: admin, currentUser: { ...admin } }), true);
});

test('unrelated renders and failed authentication do not close the modal', () => {
  assert.equal(shouldCloseLoginModal({ isOpen: true, tab: 'login', previousUser: admin, currentUser: admin }), false);
  assert.equal(shouldCloseLoginModal({ isOpen: true, tab: 'login', previousUser: null, currentUser: null }), false);
});

test('logout, an already-closed modal, and account management do not trigger login closure', () => {
  assert.equal(shouldCloseLoginModal({ isOpen: true, tab: 'login', previousUser: admin, currentUser: null }), false);
  assert.equal(shouldCloseLoginModal({ isOpen: false, tab: 'login', previousUser: admin, currentUser: analyst }), false);
  assert.equal(shouldCloseLoginModal({ isOpen: true, tab: 'register', previousUser: admin, currentUser: { ...admin } }), false);
});
