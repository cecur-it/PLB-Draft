import React, { useState, useEffect, useMemo } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { Footer } from './components/Footer';
import { ForbiddenCard } from './components/ForbiddenCard';
import { LoginModal } from './components/LoginModal';
import { UserProfileModal } from './components/UserProfileModal';
import { PersonnelDirectoryModal } from './components/PersonnelDirectoryModal';
import { PanelGuideModal } from './components/PanelGuide';

import { OverviewPanel } from './components/panels/OverviewPanel';
import { IncidentsPanel } from './components/panels/IncidentsPanel';
import { CecurPanel } from './components/panels/CecurPanel';
import { ActivTrakPanel } from './components/panels/ActivTrakPanel';
import { SensorsPanel } from './components/panels/SensorsPanel';
import { FusionPanel } from './components/panels/FusionPanel';
import { ErrowPanel } from './components/panels/ErrowPanel';
import { AuditPanel } from './components/panels/AuditPanel';
import { ExecutivePanel } from './components/panels/ExecutivePanel';
import { PricingPanel } from './components/panels/PricingPanel';

import { SensorNode, CecurAlert, UserRole } from './types';
import { apiRequest } from './lib/api';
import { calculateSensorEps } from './lib/telemetry';
import {
  KeyRound,
  UserPlus,
  LogIn,
  AlertCircle,
  Lock,
  User as UserIcon,
  Fingerprint,
  Bell,
  X,
} from 'lucide-react';

const AVATAR_PRESETS = [
  { id: 'av-1', label: 'SecOps Tier 1', url: '/avatars/av-1.svg' },
  { id: 'av-2', label: 'Chief Engineer', url: '/avatars/av-2.svg' },
  { id: 'av-3', label: 'GRC Lead', url: '/avatars/av-3.svg' },
  { id: 'av-4', label: 'CISO Executive', url: '/avatars/av-4.svg' },
  { id: 'av-5', label: 'Threat Hunter', url: '/avatars/av-5.svg' },
];

function AuthGateway() {
  const { login, register } = useAuth();
  const [tab, setTab] = useState<'login' | 'register'>('login');

  // Sign In state
  const [loginIdentifier, setLoginIdentifier] = useState('');
  const [loginPassword, setLoginPassword] = useState('');

  // Register state
  const [regDisplayName, setRegDisplayName] = useState('');
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState<UserRole>('analyst');
  const [regTitle, setRegTitle] = useState('');
  const [regDepartment, setRegDepartment] = useState('');
  const [regAvatar, setRegAvatar] = useState(AVATAR_PRESETS[0].url);

  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(loginIdentifier, loginPassword);
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify operator credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    if (regPassword.length < 6) {
      setError('Password must contain at least 6 characters for SOC policy compliance.');
      setSubmitting(false);
      return;
    }

    try {
      await register({
        displayName: regDisplayName,
        username: regUsername,
        email: regEmail,
        password: regPassword,
        role: regRole,
        title: regTitle,
        department: regDepartment,
        avatar: regAvatar,
      });
    } catch (err: any) {
      setError(err.message || 'Registration failed. Ensure username and email are unique.');
    } finally {
      setSubmitting(false);
    }
  };

  const roleDescriptions: Record<UserRole, { title: string; desc: string; badgeColor: string }> = {
    analyst: {
      title: 'SOC Defense Analyst',
      desc: 'SIEM alert triage, sensor telemetry, incident cases, Vendetta EDR, and ActivTrak insider risk.',
      badgeColor: 'border-[#00E5FF]/30 text-[#00E5FF] bg-[#00E5FF]/10',
    },
    admin: {
      title: 'Security Administrator',
      desc: 'Full authority, offensive Errow scans, and target allowlist management.',
      badgeColor: 'border-[#00FF66]/30 text-[#00FF66] bg-[#00FF66]/10',
    },
    auditor: {
      title: 'GRC Compliance Auditor',
      desc: 'Immutable audit log inspections, compliance verification (ISO/PCI), and read-only telemetry.',
      badgeColor: 'border-[#FFB300]/30 text-[#FFB300] bg-[#FFB300]/10',
    },
    executive: {
      title: 'Executive Leadership (CISO)',
      desc: 'High-level MTTD/MTTR metrics, strategic threat posture score, and compliance frameworks.',
      badgeColor: 'border-purple-500/30 text-purple-400 bg-purple-950/40',
    },
    model_curator: {
      title: 'AI Model Curator',
      desc: 'Reviews and promotes signed model checkpoints; no SOAR execution or database administration.',
      badgeColor: 'border-sky-500/30 text-sky-300 bg-sky-950/40',
    },
    gpu_capacity_owner: {
      title: 'GPU Capacity Owner',
      desc: 'Owns inference GPU capacity and quotas; no model promotion or SOAR execution.',
      badgeColor: 'border-sky-500/30 text-sky-300 bg-sky-950/40',
    },
  };

  return (
    <div className="min-h-screen bg-[#060B12] text-[#FFFFFF] flex flex-col justify-between font-sans selection:bg-[#00E5FF]/30 selection:text-white">
      {/* Centered Command Gateway */}
      <main className="flex-1 flex items-center justify-center p-4 sm:p-8 w-full">
        <div className="w-full max-w-lg">
          {/* Command Gateway Authentication Card */}
          <div className="w-full bg-[#0C1B2B] border border-[#1A3959] border-t-4 border-t-[#00E5FF] rounded-md shadow-2xl overflow-hidden flex flex-col">
            {/* Card Title Bar */}
            <div className="px-6 py-5 bg-[#12283E] border-b border-[#1A3959] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-[#00E5FF] rounded-md">
                  <Fingerprint className="w-4.5 h-4.5" />
                </div>
                <div>
                  <h2 className="text-base font-display font-bold text-[#FFFFFF] tracking-normal">
                    CECUR-IT Command Gateway
                  </h2>
                  <p className="text-xs text-[#94A3B8]">
                    Authenticate operator clearance to stream live SOC telemetry
                  </p>
                </div>
              </div>
            </div>

            {/* Tab Navigation */}
            <div className="flex border-b border-[#1A3959] bg-[#12283E]">
              <button
                id="gateway-tab-signin"
                onClick={() => {
                  setTab('login');
                  setError(null);
                }}
                className={`flex-1 py-3 text-xs font-semibold uppercase tracking-wider flex items-center justify-center gap-2 border-b-2 transition-colors font-sans cursor-pointer ${
                  tab === 'login'
                    ? 'border-[#00E5FF] text-[#FFFFFF] bg-[#0C1B2B] font-bold'
                    : 'border-transparent text-[#94A3B8] hover:text-[#FFFFFF]'
                }`}
              >
                <LogIn className="w-3.5 h-3.5 text-[#00E5FF]" />
                <span>Sign In</span>
              </button>
            </div>

            {/* Form Container */}
            <div className="p-6 overflow-y-auto space-y-4 max-h-[75vh]">
              {error && (
                <div className="p-3 bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs rounded flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span className="font-sans">{error}</span>
                </div>
              )}

              {tab === 'login' ? (
                <form onSubmit={handleLogin} className="space-y-4">
                  <div className="p-3.5 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs space-y-1">
                    <div className="text-[#F4F4F5] font-semibold flex items-center gap-1.5 font-display">
                      <Lock className="w-3.5 h-3.5 text-[#00E5FF]" />
                      Zero-Trust RBAC Enforcement
                    </div>
                    <p className="text-[#8B92A5] leading-relaxed text-xs font-sans">
                      Enter your registered operator identifier (username or official email) and account password to verify clearance and initialize real-time event telemetry.
                    </p>
                    <p className="text-[#8B92A5] leading-relaxed text-xs font-sans">
                      New accounts can only be created by an authenticated administrator. Contact your SOC administrator for access.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-[#8B92A5] mb-1.5 uppercase tracking-wider font-sans">
                      Operator Identifier
                    </label>
                    <div className="relative">
                      <UserIcon className="w-4 h-4 absolute left-3 top-2.5 text-[#5A6072]" />
                      <input
                        id="gateway-login-identifier"
                        type="text"
                        value={loginIdentifier}
                        onChange={(e) => setLoginIdentifier(e.target.value)}
                        placeholder="e.g. analyst, admin, auditor, executive or user email"
                        required
                        className="w-full pl-9 pr-3.5 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-sm text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-sans"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-[#8B92A5] mb-1.5 uppercase tracking-wider font-sans">
                      Account Password
                    </label>
                    <div className="relative">
                      <Lock className="w-4 h-4 absolute left-3 top-2.5 text-[#5A6072]" />
                      <input
                        id="gateway-login-password"
                        type="password"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        placeholder="Enter account password"
                        required
                        className="w-full pl-9 pr-3.5 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-sm text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-sans"
                      />
                    </div>
                  </div>

                  <button
                    id="gateway-btn-signin"
                    type="submit"
                    disabled={submitting}
                    className="w-full py-3 bg-[#00E5FF] hover:bg-[#33EBFF] text-[#0A0B0E] font-extrabold text-xs uppercase tracking-wider rounded transition-colors flex items-center justify-center gap-2 disabled:opacity-50 font-sans cursor-pointer shadow-md"
                  >
                    <KeyRound className="w-4 h-4 text-[#0A0B0E]" />
                    <span>{submitting ? 'Verifying Credentials...' : 'Authenticate & Unlock Console'}</span>
                  </button>

                  <div className="pt-2 border-t border-[#2A2F3A] text-center">
                    <p className="text-xs text-[#8B92A5] font-medium font-mono">
                      Operator accounts are created by an administrator through Personnel → Create Operator.
                    </p>
                  </div>

                </form>
              ) : (
                <form onSubmit={handleRegister} className="space-y-3.5">
                  <div className="p-3 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs text-[#8B92A5]">
                    <span className="font-semibold text-[#F4F4F5]">Zero-Trust Registration:</span> Operator profile is persisted in database with SHA-256/bcrypt hashed credentials and RBAC clearances.
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-[#8B92A5] mb-1 uppercase font-sans">
                        Full Operator Name *
                      </label>
                      <input
                        id="gateway-reg-displayname"
                        type="text"
                        value={regDisplayName}
                        onChange={(e) => setRegDisplayName(e.target.value)}
                        placeholder="e.g. Samantha Wu"
                        required
                        className="w-full px-3 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-sans"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-[#8B92A5] mb-1 uppercase font-sans">
                        Unique Username *
                      </label>
                      <input
                        id="gateway-reg-username"
                        type="text"
                        value={regUsername}
                        onChange={(e) => setRegUsername(e.target.value)}
                        placeholder="e.g. samantha.wu"
                        required
                        className="w-full px-3 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-mono"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-[#8B92A5] mb-1 uppercase font-sans">
                        Official Email *
                      </label>
                      <input
                        id="gateway-reg-email"
                        type="email"
                        value={regEmail}
                        onChange={(e) => setRegEmail(e.target.value)}
                        placeholder="e.g. s.wu@cecur-it.io"
                        required
                        className="w-full px-3 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-sans"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-[#8B92A5] mb-1 uppercase font-sans">
                        Secure Password *
                      </label>
                      <input
                        id="gateway-reg-password"
                        type="password"
                        value={regPassword}
                        onChange={(e) => setRegPassword(e.target.value)}
                        placeholder="Min. 6 characters"
                        required
                        minLength={6}
                        className="w-full px-3 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-sans"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-[#8B92A5] mb-1.5 uppercase font-sans">
                      Assigned Clearance & Role *
                    </label>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {(['analyst', 'admin', 'auditor', 'executive'] as UserRole[]).map((r) => (
                        <div
                          key={r}
                          id={`gateway-select-role-${r}`}
                          onClick={() => setRegRole(r)}
                          className={`p-2.5 rounded border cursor-pointer transition-all ${
                            regRole === r
                              ? 'border-[#00E5FF] bg-[#00E5FF]/15 text-[#F4F4F5]'
                              : 'border-[#2A2F3A] bg-[#1A1E26] hover:bg-[#2A2F3A] text-[#8B92A5]'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-semibold capitalize font-sans text-[#F4F4F5]">{r}</span>
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${roleDescriptions[r].badgeColor}`}>
                              {r.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-[11px] text-[#8B92A5] leading-snug font-sans">
                            {roleDescriptions[r].desc}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-[#8B92A5] mb-1 uppercase font-sans">
                        Operational Title
                      </label>
                      <input
                        id="gateway-reg-title"
                        type="text"
                        value={regTitle}
                        onChange={(e) => setRegTitle(e.target.value)}
                        placeholder="e.g. Senior Threat Hunter"
                        className="w-full px-3 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-sans"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-[#8B92A5] mb-1 uppercase font-sans">
                        Department
                      </label>
                      <input
                        id="gateway-reg-department"
                        type="text"
                        value={regDepartment}
                        onChange={(e) => setRegDepartment(e.target.value)}
                        placeholder="e.g. Threat Intel & SecOps"
                        className="w-full px-3 py-2 bg-[#1A1E26] border border-[#2A2F3A] rounded text-xs text-[#F4F4F5] focus:outline-none focus:border-[#00E5FF] placeholder-[#5A6072] font-sans"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-[#8B92A5] mb-1.5 uppercase font-sans">
                      Operator Avatar Preset
                    </label>
                    <div className="flex items-center gap-2.5">
                      {AVATAR_PRESETS.map((p) => (
                        <button
                          key={p.id}
                          type="button"
                          onClick={() => setRegAvatar(p.url)}
                          className={`relative rounded-full p-0.5 border transition-all ${
                            regAvatar === p.url ? 'border-[#00E5FF] scale-105 ring-2 ring-[#00E5FF]/30' : 'border-[#2A2F3A] hover:border-[#8B92A5] opacity-80'
                          }`}
                        >
                          <img src={p.url} alt={p.label} className="w-8 h-8 rounded-full object-cover" />
                        </button>
                      ))}
                    </div>
                  </div>

                  <button
                    id="gateway-btn-register"
                    type="submit"
                    disabled={submitting}
                    className="w-full py-3 bg-[#00E5FF] hover:bg-[#33EBFF] text-[#0A0B0E] font-extrabold text-xs uppercase tracking-wider rounded transition-colors flex items-center justify-center gap-2 disabled:opacity-50 font-sans cursor-pointer shadow-md"
                  >
                    <UserPlus className="w-4 h-4 text-[#0A0B0E]" />
                    <span>{submitting ? 'Creating Profile & Syncing Database...' : 'Create Account & Unlock Console'}</span>
                  </button>

                  <div className="pt-2 border-t border-[#2A2F3A] text-center">
                    <button
                      type="button"
                      onClick={() => {
                        setTab('login');
                        setError(null);
                      }}
                      className="text-xs text-[#8B92A5] hover:text-[#F4F4F5] font-medium transition-colors cursor-pointer font-mono"
                    >
                      Already have an account? Sign In →
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

function MainLayout() {
  const { user, loading, canAccessPanel } = useAuth();
  const [activePanel, setActivePanel] = useState<string>('overview');
  const [liveSensors, setLiveSensors] = useState<SensorNode[]>([]);
  const [sseStatus, setSseStatus] = useState<'connected' | 'reconnecting' | 'offline'>('offline');
  const [notification, setNotification] = useState<{ title: string; message: string; type: 'info' | 'alert' } | null>(null);

  // Modal dialog states
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const [loginModalTab, setLoginModalTab] = useState<'login' | 'register'>('login');
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);
  const [isDirectoryModalOpen, setIsDirectoryModalOpen] = useState(false);
  const [isPanelGuideOpen, setIsPanelGuideOpen] = useState(false);

  // Dynamic EPS calculation from sensors with memoization
  const totalEps = useMemo(() => calculateSensorEps(liveSensors), [liveSensors]);

  // SSE Real-time Telemetry Stream
  useEffect(() => {
    if (!user) return;

    let eventSource: EventSource | null = null;

    try {
      eventSource = new EventSource('/api/events');

      eventSource.onopen = () => {
        setSseStatus('connected');
      };

      eventSource.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data);
          if (payload.type === 'HEARTBEAT' || payload.type === 'INITIAL_STATE' || payload.type === 'SENSOR_TELEMETRY_UPDATE') {
            if (payload.sensors) {
              setLiveSensors(payload.sensors);
            }
          } else if (payload.type === 'NEW_ALERT' || payload.type === 'NEW_CECUR_ALERT') {
            const alert: CecurAlert = payload.alert || payload.payload;
            if (alert) {
              setNotification({
                title: `Cecur SIEM Alert Lvl ${alert.ruleLevel}`,
                message: alert.ruleTitle || alert.description,
                type: alert.ruleLevel >= 10 ? 'alert' : 'info',
              });
              setTimeout(() => setNotification(null), 4500);
            }
          }
        } catch (err) {
          console.error('Failed to parse SSE event:', err);
        }
      };

      eventSource.onerror = () => {
        setSseStatus(eventSource?.readyState === EventSource.CONNECTING ? 'reconnecting' : 'offline');
      };
    } catch (err) {
      console.warn('SSE stream not reachable:', err);
    }

    return () => {
      eventSource?.close();
    };
  }, [user]);

  // Fetch initial sensor telemetry
  useEffect(() => {
    const loadSensors = async () => {
      try {
        const res = await apiRequest<{ total: number; sensors: SensorNode[] }>('/api/sensors');
        setLiveSensors(res.sensors);
      } catch (err) {
        // Fallback gracefully on permission restriction
      }
    };
    if (user) {
      loadSensors();
    }
  }, [user]);

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-950 flex flex-col items-center justify-center text-cyan-400 font-mono text-xs space-y-3">
        <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <div className="text-zinc-400">Authenticating Operator Security Context...</div>
      </div>
    );
  }

  // Enforce authentication gate
  if (!user) {
    return <AuthGateway />;
  }

  const renderActivePanel = () => {
    // If user's role lacks access according to server RBAC policy
    if (!canAccessPanel(activePanel)) {
      return (
        <div className="p-6 lg:p-8 max-w-5xl mx-auto">
          <ForbiddenCard
            panelName={activePanel}
            onOpenLogin={() => setIsLoginModalOpen(true)}
            onOpenProfile={() => setIsProfileModalOpen(true)}
            onNavigateToAllowed={() => setActivePanel('overview')}
          />
        </div>
      );
    }

    switch (activePanel) {
      case 'overview':
        return <OverviewPanel onNavigate={setActivePanel} liveSensors={liveSensors} />;
      case 'incidents':
        return <IncidentsPanel />;
      case 'cecur':
        return <CecurPanel />;
      case 'activtrak':
        return <ActivTrakPanel />;
      case 'sensors':
        return <SensorsPanel sensors={liveSensors} />;
      case 'fusion':
        return <FusionPanel />;
      case 'errow':
        return <ErrowPanel />;
      case 'audit':
        return <AuditPanel />;
      case 'executive':
        return <ExecutivePanel />;
      case 'pricing':
        return <PricingPanel />;
      default:
        return <OverviewPanel onNavigate={setActivePanel} liveSensors={liveSensors} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#060B12] text-[#FFFFFF] flex flex-col font-sans selection:bg-[#00E5FF]/30 selection:text-white">
      {/* Top Application Header */}
      <Header
        onOpenLogin={() => setIsLoginModalOpen(true)}
        onOpenProfile={() => setIsProfileModalOpen(true)}
        onOpenDirectory={() => setIsDirectoryModalOpen(true)}
        onOpenGuide={() => setIsPanelGuideOpen(true)}
        liveStatus={sseStatus}
        epsRate={totalEps}
      />

      {/* Main SOC Dashboard Grid Layout */}
      <div className="flex-1 grid grid-cols-1 md:grid-cols-[256px_1fr] overflow-hidden">
        {/* Persistent Navigation Column */}
        <Sidebar activePanel={activePanel} onSelectPanel={setActivePanel} />

        {/* Dynamic Telemetry Workspace Surface with Intentional Padding */}
        <main
          id="soc-main-content"
          className="overflow-y-auto bg-[#060B12] relative scroll-smooth focus:outline-none flex flex-col justify-between"
          tabIndex={-1}
        >
          {/* Live Ingress Alert Toast */}
          {notification && (
            <div
              className={`fixed bottom-5 right-5 z-50 max-w-sm p-4 rounded-md border shadow-2xl transition-all ${
                notification.type === 'alert'
                  ? 'bg-[#0C1B2B] border-[#1A3959] border-l-4 border-l-rose-500 text-[#FFFFFF]'
                  : 'bg-[#0C1B2B] border-[#1A3959] border-l-4 border-l-[#00E5FF] text-[#FFFFFF]'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  <Bell className={`w-4 h-4 shrink-0 mt-0.5 ${notification.type === 'alert' ? 'text-rose-400' : 'text-[#00E5FF]'}`} />
                  <div>
                    <div className="font-sans text-xs font-bold uppercase tracking-wide text-[#FFFFFF]">
                      {notification.title}
                    </div>
                    <p className="text-xs mt-1 text-[#94A3B8] font-sans leading-relaxed">
                      {notification.message}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setNotification(null)}
                  className="text-[#64748B] hover:text-[#FFFFFF] text-xs p-1 cursor-pointer"
                  aria-label="Dismiss alert"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* Active Workspace View */}
          <div className="w-full flex-1">
            {renderActivePanel()}
          </div>

          {/* Footer Component */}
          <Footer />
        </main>
      </div>

      {/* Security Profile & Credentials Modal */}
      <UserProfileModal
        isOpen={isProfileModalOpen}
        onClose={() => setIsProfileModalOpen(false)}
        onOpenLogin={() => {
          setIsProfileModalOpen(false);
          setIsLoginModalOpen(true);
        }}
      />

      {/* Personnel & Access Directory Modal */}
      <PersonnelDirectoryModal
        isOpen={isDirectoryModalOpen}
        onClose={() => setIsDirectoryModalOpen(false)}
        onOpenAccountManager={() => {
          setIsDirectoryModalOpen(false);
          setLoginModalTab('register');
          setIsLoginModalOpen(true);
        }}
      />

      <PanelGuideModal
        panelId={activePanel}
        isOpen={isPanelGuideOpen}
        onClose={() => setIsPanelGuideOpen(false)}
      />

      {/* Sign In & Profile Registration Modal */}
      <LoginModal
        isOpen={isLoginModalOpen}
        initialTab={loginModalTab}
        onClose={() => {
          setIsLoginModalOpen(false);
          setLoginModalTab('login');
        }}
      />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainLayout />
    </AuthProvider>
  );
}
