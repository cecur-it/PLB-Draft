import { Router, Request, Response, NextFunction, raw } from 'express';
import bcrypt from 'bcryptjs';
import { db } from '../db';
import { recordCriticalAudit } from '../auditOutcome';
import { signToken, requireAuth, requireAction, requireSelf, AuthenticatedRequest } from '../middleware/auth';
import { getRoleSummary } from '../rbac';
import { UserRole, User } from '../../src/types';
import { syncUserToFirestore } from '../firestoreSync';
import { commitUser, getDefaultAvatar, validateProfileUpdate, validateRegistration } from '../accounts';
import { AvatarInputError, normalizeAvatar, sanitizeAvatar } from '../avatar';
import { AVATAR_SOURCE_MAX_BYTES } from '../../src/lib/avatar';

export const authRouter = Router();

// Administrator-managed registration never replaces the administrator's session.
authRouter.post('/register', requireAuth, requireAction('manage_users'), async (req: AuthenticatedRequest, res: Response) => {
  const validation = validateRegistration(req.body);
  if (validation.error) {
    res.status(400).json({ error: 'Invalid Account Fields', message: validation.error });
    return;
  }
  const account = validation.data;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  if (db.getUserByUsername(account.username)) {
    res.status(409).json({
      error: 'Account Conflict',
      message: `Username '${account.username}' is already registered in the SOC personnel registry.`,
    });
    return;
  }
  if (db.getUserByEmail(account.email)) {
    res.status(409).json({
      error: 'Account Conflict',
      message: `Email '${account.email}' is already registered with an existing operator account.`,
    });
    return;
  }

  const passwordHash = bcrypt.hashSync(account.password, bcrypt.genSaltSync(10));
  const newUser: User = {
    id: `usr-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    username: account.username,
    email: account.email,
    passwordHash,
    role: account.role,
    displayName: account.displayName,
    title: account.title,
    department: account.department,
    avatar: account.avatar,
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
  };

  try {
    await commitUser(db, newUser);
  } catch (error) {
    sendPersistenceError(res, 'registration', error);
    return;
  }
  void syncUserToFirestore(newUser);

  await recordCriticalAudit(res, {
    actorId: req.user?.id || 'unknown',
    actorUsername: req.user?.username || 'unknown',
    actorRole: req.user?.role || 'admin',
    action: 'USER_REGISTER_SUCCESS',
    panel: 'auth',
    targetResource: `${newUser.username} (${newUser.id})`,
    ipAddress: clientIp,
    status: 'SUCCESS',
    details: `Administrator '${req.user?.username || 'unknown'}' created SOC operator account '${newUser.username}' (${newUser.displayName}) with clearance level '${newUser.role}'.`,
  });

  res.status(201).json({ user: sanitizeUser(newUser), permissions: getRoleSummary(newUser.role) });
});

// Login endpoint (supports username or email)
authRouter.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  if (!username || !password) {
    res.status(400).json({ error: 'Missing Credentials', message: 'Username/Email and password required.' });
    return;
  }

  const user = db.getUserByUsername(username) || db.getUserByEmail(username);
  if (!user) {
    await recordCriticalAudit(res, {
      actorId: 'anonymous',
      actorUsername: username,
      actorRole: 'analyst' as UserRole,
      action: 'LOGIN_FAILED_UNKNOWN_USER',
      panel: 'auth',
      ipAddress: clientIp,
      status: 'DENY_403',
      details: `Failed authentication attempt for unknown identity '${username}'.`,
    });
    res.status(401).json({ error: 'Authentication Failed', message: 'Invalid credentials. Please verify username and password.' });
    return;
  }

  const isMatch = bcrypt.compareSync(password, user.passwordHash);
  if (!isMatch) {
    await recordCriticalAudit(res, {
      actorId: user.id,
      actorUsername: user.username,
      actorRole: user.role,
      action: 'LOGIN_FAILED_BAD_PASSWORD',
      panel: 'auth',
      ipAddress: clientIp,
      status: 'DENY_403',
      details: `Bad password attempt for account '${user.username}'.`,
    });
    res.status(401).json({ error: 'Authentication Failed', message: 'Invalid credentials. Please verify username and password.' });
    return;
  }

  let authenticatedUser: User;
  try {
    authenticatedUser = await commitUser(db, { ...user, lastLogin: new Date().toISOString() });
  } catch (error) {
    sendPersistenceError(res, 'login timestamp', error);
    return;
  }
  const token = signToken(authenticatedUser);

  await recordCriticalAudit(res, {
    actorId: authenticatedUser.id,
    actorUsername: authenticatedUser.username,
    actorRole: authenticatedUser.role,
    action: 'LOGIN_SUCCESS',
    panel: 'auth',
    ipAddress: clientIp,
    status: 'SUCCESS',
    details: `User '${authenticatedUser.username}' successfully authenticated with clearance role '${authenticatedUser.role}'.`,
  });

  res.json({
    token,
    user: sanitizeUser(authenticatedUser),
    permissions: getRoleSummary(authenticatedUser.role),
  });
});

// Current user profile & permissions
authRouter.get('/me', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const permissions = getRoleSummary(req.user.role);
  res.json({
    user: sanitizeUser(req.user),
    permissions,
  });
});

// The legacy /profile route is implicitly self-scoped; the explicit route also checks the target ID.
authRouter.patch('/profile', requireAuth, updateProfileHandler);
authRouter.patch('/users/:id/profile', requireAuth, requireSelf, updateProfileHandler);

async function updateProfileHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  const validation = validateProfileUpdate(req.body);
  if (validation.error) {
    res.status(400).json({ error: 'Invalid Profile Fields', message: validation.error });
    return;
  }

  let updated: User;
  try {
    updated = await commitUser(db, { ...req.user, ...validation.data });
  } catch (error) {
    sendPersistenceError(res, 'profile', error);
    return;
  }
  void syncUserToFirestore(updated);

  db.logAudit({
    actorId: updated.id,
    actorUsername: updated.username,
    actorRole: updated.role,
    action: 'PROFILE_UPDATED',
    panel: 'auth',
    ipAddress: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1',
    status: 'SUCCESS',
    details: `Updated profile details for operator '${updated.username}'.`,
  });

  res.json({ user: sanitizeUser(updated), permissions: getRoleSummary(updated.role) });
}

const avatarBody = raw({ type: () => true, limit: AVATAR_SOURCE_MAX_BYTES });
function parseAvatarBody(req: Request, res: Response, next: NextFunction): void {
  avatarBody(req, res, (error: any) => {
    if (!error) {
      next();
      return;
    }
    const oversized = error.type === 'entity.too.large' || error.status === 413;
    res.status(oversized ? 413 : 400).json({
      error: oversized ? 'Avatar Too Large' : 'Invalid Avatar Upload',
      message: oversized ? `Avatar source must not exceed ${AVATAR_SOURCE_MAX_BYTES} bytes.` : 'Avatar upload body could not be read.',
    });
  });
}

authRouter.put('/users/:id/avatar', requireAuth, requireSelf, parseAvatarBody, async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  const contentType = (req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  let avatar: string;
  try {
    avatar = await normalizeAvatar(req.body, contentType);
  } catch (error) {
    const status = error instanceof AvatarInputError ? error.statusCode : 400;
    res.status(status).json({
      error: 'Avatar Rejected',
      message: error instanceof AvatarInputError ? error.message : 'Avatar could not be normalized.',
    });
    return;
  }

  let updated: User;
  try {
    updated = await commitUser(db, { ...req.user, avatar });
  } catch (error) {
    sendPersistenceError(res, 'avatar', error);
    return;
  }
  void syncUserToFirestore(updated);
  db.logAudit({
    actorId: updated.id,
    actorUsername: updated.username,
    actorRole: updated.role,
    action: 'AVATAR_UPDATED',
    panel: 'auth',
    ipAddress: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1',
    status: 'SUCCESS',
    details: `Normalized and updated avatar for operator '${updated.username}'.`,
  });
  res.json({ user: sanitizeUser(updated), permissions: getRoleSummary(updated.role) });
});

authRouter.delete('/users/:id/avatar', requireAuth, requireSelf, async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  let updated: User;
  try {
    updated = await commitUser(db, { ...req.user, avatar: getDefaultAvatar(req.user.role) });
  } catch (error) {
    sendPersistenceError(res, 'avatar removal', error);
    return;
  }
  void syncUserToFirestore(updated);
  db.logAudit({
    actorId: updated.id,
    actorUsername: updated.username,
    actorRole: updated.role,
    action: 'AVATAR_REMOVED',
    panel: 'auth',
    ipAddress: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1',
    status: 'SUCCESS',
    details: `Removed custom avatar for operator '${updated.username}'.`,
  });
  res.json({ user: sanitizeUser(updated), permissions: getRoleSummary(updated.role) });
});

// List all registered SOC personnel (for team roster & audit verification)
authRouter.get('/users', requireAuth, requireAction('manage_users'), (req: AuthenticatedRequest, res: Response) => {
  const sanitizedList = db.users.map(sanitizeUser);
  res.json({ users: sanitizedList });
});

// Explicit projection keeps hydrated credential and unknown JSONB fields out of every public response.
export function sanitizeUser(u: User) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    displayName: u.displayName,
    email: u.email,
    avatar: sanitizeAvatar(u.avatar, getDefaultAvatar(u.role)),
    title: u.title,
    department: u.department,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin,
  };
}

function sendPersistenceError(res: Response, operation: string, error: unknown): void {
  console.error(`[accounts] ${operation} persistence failed:`, error instanceof Error ? error.message : 'unknown error');
  res.status(503).json({
    error: 'Account Persistence Unavailable',
    message: `The ${operation} change was not confirmed durable. No local account mutation was applied; please retry.`,
  });
}



