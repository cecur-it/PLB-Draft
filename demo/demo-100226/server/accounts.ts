import type { User, UserRole } from '../src/types';
import type { SOCDatabase } from './db';
import { sanitizeAvatar, sanitizeStoredAvatar } from './avatar';
import { listAllDocs, upsertDoc } from './pg/store';

export const BOOTSTRAP_ADMIN_ID = 'usr-bootstrap-admin';
export const ACCOUNT_FIELD_LIMITS = {
  username: 64,
  email: 254,
  password: 128,
  displayName: 80,
  title: 100,
  department: 100,
} as const;

export const AVATAR_PRESETS = ['/avatars/av-1.svg', '/avatars/av-2.svg', '/avatars/av-3.svg', '/avatars/av-4.svg', '/avatars/av-5.svg'] as const;
const VALID_ROLES: UserRole[] = ['analyst', 'admin', 'auditor', 'executive', 'model_curator', 'gpu_capacity_owner'];

export interface RegistrationAccount {
  username: string;
  email: string;
  password: string;
  role: UserRole;
  displayName: string;
  title: string;
  department: string;
  avatar: string;
}

type ValidationResult<T> = { data: T; error?: never } | { data?: never; error: string };

function requiredString(value: unknown, field: string, max: number): ValidationResult<string> {
  if (typeof value !== 'string' || !value.trim()) return { error: `${field} is required.` };
  const normalized = value.trim();
  if (normalized.length > max) return { error: `${field} must be at most ${max} characters.` };
  return { data: normalized };
}

function optionalString(value: unknown, field: string, max: number, fallback: string): ValidationResult<string> {
  if (value === undefined || value === null || value === '') return { data: fallback };
  return requiredString(value, field, max);
}

export function getDefaultAvatar(role: UserRole): string {
  if (role === 'admin') return '/avatars/av-2.svg';
  if (role === 'auditor') return '/avatars/av-3.svg';
  if (role === 'executive') return '/avatars/av-4.svg';
  if (role === 'model_curator' || role === 'gpu_capacity_owner') return '/avatars/av-5.svg';
  return '/avatars/av-1.svg';
}

function getDefaultTitle(role: UserRole): string {
  const titles: Record<UserRole, string> = {
    admin: 'Senior Security Operations Admin',
    analyst: 'Cyber Defense Incident Responder',
    auditor: 'Compliance & Threat Auditor',
    executive: 'Cyber Risk & Security Officer',
    model_curator: 'AI Model Curator',
    gpu_capacity_owner: 'GPU Capacity Owner',
  };
  return titles[role];
}

function getDefaultDepartment(role: UserRole): string {
  const departments: Record<UserRole, string> = {
    admin: 'SecOps Infrastructure & Engineering',
    analyst: 'Threat Detection & Incident Response',
    auditor: 'Governance, Risk & Compliance',
    executive: 'Executive Information Security',
    model_curator: 'AI Platform Operations',
    gpu_capacity_owner: 'AI Platform Operations',
  };
  return departments[role];
}

export function validateRegistration(body: any): ValidationResult<RegistrationAccount> {
  const username = requiredString(body?.username, 'Username', ACCOUNT_FIELD_LIMITS.username);
  if (username.error) return { error: username.error };
  const email = requiredString(body?.email, 'Email', ACCOUNT_FIELD_LIMITS.email);
  if (email.error) return { error: email.error };
  if (typeof body?.password !== 'string' || !body.password) return { error: 'Password is required.' };
  if (body.password.length < 6) return { error: 'Password must be at least 6 characters long.' };
  if (body.password.length > ACCOUNT_FIELD_LIMITS.password) {
    return { error: `Password must be at most ${ACCOUNT_FIELD_LIMITS.password} characters.` };
  }
  if (!VALID_ROLES.includes(body?.role)) return { error: `Role must be one of: ${VALID_ROLES.join(', ')}.` };
  const role = body.role as UserRole;
  const displayName = requiredString(body?.displayName, 'Full name', ACCOUNT_FIELD_LIMITS.displayName);
  if (displayName.error) return { error: displayName.error };
  const title = optionalString(body?.title, 'Title', ACCOUNT_FIELD_LIMITS.title, getDefaultTitle(role));
  if (title.error) return { error: title.error };
  const department = optionalString(body?.department, 'Department', ACCOUNT_FIELD_LIMITS.department, getDefaultDepartment(role));
  if (department.error) return { error: department.error };

  let avatar = getDefaultAvatar(role);
  if (body?.avatar !== undefined && body.avatar !== null && body.avatar !== '') {
    if (typeof body.avatar !== 'string' || !AVATAR_PRESETS.includes(body.avatar.trim() as (typeof AVATAR_PRESETS)[number])) {
      return { error: 'Registration avatar must be one of the built-in avatar presets.' };
    }
    avatar = body.avatar.trim();
  }

  return {
    data: {
      username: username.data.toLowerCase(),
      email: email.data.toLowerCase(),
      password: body.password,
      role,
      displayName: displayName.data,
      title: title.data,
      department: department.data,
      avatar,
    },
  };
}

export function validateProfileUpdate(body: any): ValidationResult<Pick<User, 'displayName' | 'title' | 'department'>> {
  if (body?.avatar !== undefined) {
    return { error: 'Avatar changes must use the authenticated avatar upload or delete endpoint.' };
  }
  const updates: Partial<Pick<User, 'displayName' | 'title' | 'department'>> = {};
  for (const field of ['displayName', 'title', 'department'] as const) {
    if (body?.[field] === undefined) continue;
    const label = field === 'displayName' ? 'Full name' : field[0].toUpperCase() + field.slice(1);
    const result = requiredString(body[field], label, ACCOUNT_FIELD_LIMITS[field]);
    if (result.error) return { error: result.error };
    updates[field] = result.data;
  }
  return { data: updates as Pick<User, 'displayName' | 'title' | 'department'> };
}

export async function persistUser(
  user: User,
  write: (user: User) => Promise<boolean> = (value) => upsertDoc('users', value.id, value)
): Promise<void> {
  if (process.env.CS3_PERSISTENCE !== 'postgres') return;
  if (!(await write(user))) throw new Error('PostgreSQL user persistence is unavailable.');
}

/** Await durability before exposing the mutation through the local registry. */
export async function commitUser(
  database: SOCDatabase,
  user: User,
  persist: (user: User) => Promise<void> = persistUser
): Promise<User> {
  const safeUser = { ...user, avatar: sanitizeAvatar(user.avatar, getDefaultAvatar(user.role)) };
  await persist(safeUser);
  return database.updateUser(safeUser.id, safeUser) || database.createUser(safeUser);
}

/** Merge the complete persisted registry, retaining the current environment-derived bootstrap hash. */
export async function hydrateUserRegistry(
  database: SOCDatabase,
  load: () => Promise<User[]> = () => listAllDocs<User>('users')
): Promise<number> {
  const persisted = await load();
  const users = new Map<string, User>();
  for (const user of persisted) {
    users.set(user.id, {
      ...user,
      avatar: await sanitizeStoredAvatar(user.avatar, getDefaultAvatar(user.role)),
    });
  }
  for (const local of database.users) {
    const stored = users.get(local.id);
    if (!stored) {
      users.set(local.id, { ...local, avatar: sanitizeAvatar(local.avatar, getDefaultAvatar(local.role)) });
    } else if (local.id === BOOTSTRAP_ADMIN_ID && process.env.CS3_BOOTSTRAP_ADMIN_PASSWORD) {
      users.set(local.id, { ...stored, passwordHash: local.passwordHash });
    }
  }
  database.users.splice(0, database.users.length, ...users.values());
  return persisted.length;
}
