interface AuthModalUser {
  id: string;
}

interface AuthModalTransition {
  isOpen: boolean;
  tab: 'login' | 'register';
  previousUser: AuthModalUser | null;
  currentUser: AuthModalUser | null;
}

export function shouldCloseLoginModal({
  isOpen,
  tab,
  previousUser,
  currentUser,
}: AuthModalTransition): boolean {
  return isOpen && tab === 'login' && currentUser !== null && previousUser !== currentUser;
}
