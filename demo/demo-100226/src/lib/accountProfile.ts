import type { User } from '../types';

/** Public account fields permitted in secondary profile stores; credentials and unknown JSONB fields are excluded. */
export function secondaryProfileProjection(user: User) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    displayName: user.displayName,
    title: user.title,
    department: user.department,
    avatar: user.avatar,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
  };
}
