import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { User, UserRole } from '../types';
import { apiRequest, setStoredToken, clearStoredToken, getStoredToken } from '../lib/api';
import { doc, setDoc } from 'firebase/firestore';
import { db as firestoreDb } from '../lib/firebase';
import { secondaryProfileProjection } from '../lib/accountProfile';

function syncProfileToSecondary(profile: User, operation: string): void {
  if (!firestoreDb) return;
  try {
    const userRef = doc(firestoreDb, 'users', profile.id);
    void setDoc(userRef, secondaryProfileProjection(profile)).catch((syncErr) => {
      console.warn(`Firestore ${operation} sync note:`, syncErr);
    });
  } catch (syncErr) {
    console.warn(`Firestore ${operation} sync note:`, syncErr);
  }
}

interface RolePermissions {
  role: UserRole;
  allowedPanels: string[];
  allowedActions: string[];
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  role: UserRole;
  displayName: string;
  title?: string;
  department?: string;
  avatar?: string;
}

interface AuthContextType {
  user: User | null;
  permissions: RolePermissions | null;
  loading: boolean;
  login: (usernameOrEmail: string, password: string) => Promise<void>;
  register: (data: RegisterData) => Promise<User>;
  updateProfile: (updates: Partial<User>) => Promise<void>;
  uploadAvatar: (file: File) => Promise<void>;
  removeAvatar: () => Promise<void>;
  logout: () => void;
  canAccessPanel: (panelId: string) => boolean;
  canPerformAction: (actionId: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [permissions, setPermissions] = useState<RolePermissions | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Initialize auth: verify existing operator token or require explicit authentication
  const initAuth = useCallback(async () => {
    setLoading(true);
    const existingToken = getStoredToken();

    if (existingToken) {
      try {
        const res = await apiRequest<{ user: User; permissions: RolePermissions }>('/api/auth/me');
        setUser(res.user);
        setPermissions(res.permissions);
      } catch (err) {
        clearStoredToken();
        setUser(null);
        setPermissions(null);
      }
    } else {
      setUser(null);
      setPermissions(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    initAuth();
  }, [initAuth]);

  const login = async (usernameOrEmail: string, password: string) => {
    const res = await apiRequest<{ token: string; user: User; permissions: RolePermissions }>(
      '/api/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ username: usernameOrEmail, password }),
      }
    );
    setStoredToken(res.token);
    setUser(res.user);
    setPermissions(res.permissions);

    // Primary authentication must not wait for the best-effort secondary profile copy.
    syncProfileToSecondary(res.user, 'session');
  };

  const register = async (data: RegisterData): Promise<User> => {
    const res = await apiRequest<{ user: User; permissions: RolePermissions }>(
      '/api/auth/register',
      {
        method: 'POST',
        body: JSON.stringify(data),
      }
    );

    // This is a management operation: retain the signed-in administrator's token, user, and RBAC state.
    syncProfileToSecondary(res.user, 'profile registration');
    return res.user;
  };

  const updateProfile = async (updates: Partial<User>) => {
    if (!user) throw new Error('Authentication required.');
    // Prevent client-side role escalation attempts
    const sanitizedUpdates = { ...updates };
    delete (sanitizedUpdates as any).role;
    delete (sanitizedUpdates as any).id;
    delete (sanitizedUpdates as any).passwordHash;
    delete (sanitizedUpdates as any).avatar;

    const res = await apiRequest<{ user: User; permissions: RolePermissions }>(
      `/api/auth/users/${encodeURIComponent(user.id)}/profile`,
      {
        method: 'PATCH',
        body: JSON.stringify(sanitizedUpdates),
      }
    );
    setUser(res.user);
    setPermissions(res.permissions);

    // Firestore remains a best-effort secondary copy after the server confirms the account write.
    syncProfileToSecondary(res.user, 'profile update');
  };

  const uploadAvatar = async (file: File) => {
    if (!user) throw new Error('Authentication required.');
    const res = await apiRequest<{ user: User; permissions: RolePermissions }>(
      `/api/auth/users/${encodeURIComponent(user.id)}/avatar`,
      {
        method: 'PUT',
        headers: { 'Content-Type': file.type },
        body: file,
      }
    );
    setUser(res.user);
    setPermissions(res.permissions);
  };

  const removeAvatar = async () => {
    if (!user) throw new Error('Authentication required.');
    const res = await apiRequest<{ user: User; permissions: RolePermissions }>(
      `/api/auth/users/${encodeURIComponent(user.id)}/avatar`,
      { method: 'DELETE' }
    );
    setUser(res.user);
    setPermissions(res.permissions);
  };

  const logout = () => {
    clearStoredToken();
    setUser(null);
    setPermissions(null);
  };

  const canAccessPanel = (panelId: string): boolean => {
    if (!permissions) return false;
    return permissions.allowedPanels.includes(panelId);
  };

  const canPerformAction = (actionId: string): boolean => {
    if (!permissions) return false;
    return permissions.allowedActions.includes(actionId);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        permissions,
        loading,
        login,
        register,
        updateProfile,
        uploadAvatar,
        removeAvatar,
        logout,
        canAccessPanel,
        canPerformAction,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
