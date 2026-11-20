import { Router, Response } from 'express';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth';
import { getAIStatus } from '../ai/cecurAI';
import { getErrowStatus } from '../connectors/errowClient';
import { getResolvedFirebaseConfig, isFirestoreEnabled } from '../firestoreSync';

export const systemRouter = Router();

// Environment & connector secrets health diagnostic
systemRouter.get('/environment-status', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const aiStatus = getAIStatus();
  const errowStatus = getErrowStatus();
  const fbConfig = getResolvedFirebaseConfig();

  const isJwtCustom = Boolean(process.env.JWT_SECRET && process.env.JWT_SECRET !== 'cecur-it-soc-jwt-secret-key-production-change-me');
  const indexerUrl = process.env.CECUR_INDEXER_URL || 'http://127.0.0.1:9200';
  const clusterName = process.env.CECUR_CLUSTER_NAME || 'cecur-prod-cluster';

  res.json({
    inference: {
      configured: aiStatus.inferenceActive,
      backend: aiStatus.inferenceBackend,
      profile: aiStatus.inferenceProfile,
      model: aiStatus.ollamaModel,
    },
    firebase: {
      configured: isFirestoreEnabled(),
      projectId: fbConfig.projectId,
      firestoreDatabaseId: fbConfig.firestoreDatabaseId,
      authDomain: fbConfig.authDomain,
    },
    errow: {
      mode: errowStatus.mode,
      configured: errowStatus.configured,
      credentialConfigured: errowStatus.credentialConfigured,
      reachability: errowStatus.reachability,
      verified: errowStatus.verified,
      baseUrl: errowStatus.baseUrl || null,
    },
    auth: {
      jwtSecretConfigured: isJwtCustom,
    },
    cecurIndexer: {
      url: indexerUrl,
      cluster: clusterName,
    },
  });
});

// Pricing & Consumption Economics diagnostic endpoint
systemRouter.get('/pricing', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  res.json({
    tiers: [
      {
        id: 'tier-1',
        name: 'DEFENSE ESSENTIALS',
        priceMonthly: 2800,
        scope: 'Up to 250 Endpoints',
        aiQuota: 'Baseline / Metered',
        features: ['SIEM + CS3 Sensor Taps', 'Read-Only Incident Queue', '30-Day Hot Firestore Retention'],
      },
      {
        id: 'tier-2',
        name: 'ADVANCED ENTERPRISE XDR',
        priceMonthly: 6500,
        scope: 'Up to 1,000 Endpoints',
        aiQuota: '10,000 AI Fuel Credits/mo',
        features: [
          'Includes Tier 1 + ActivTrak Insider Risk',
          'Asset Fusion Blast Radius Topology',
          'CS3 Agent Copilot (10k AI Fuel Credits/mo)',
          '90-Day Retention + SOAR Playbooks',
        ],
      },
      {
        id: 'tier-3',
        name: 'CRITICAL INFRASTRUCTURE',
        priceMonthly: 14500,
        scope: 'Unlimited Fleet Scope',
        aiQuota: 'Uncapped CS3-AI inference',
        features: [
          'Includes Tier 2 + errow Offensive Recon',
          'CS3-AI inference gateway, uncapped',
          'Full GRC Compliance Attestation Engine',
          '365-Day BigQuery Immutable Cold Retention',
        ],
      },
    ],
    metering: {
      overageRatePerTx: 0.05,
      annualRetainerDiscount: 0.20,
      unitDefinition: '1 Unit = 1 Incident Triage or 1 Remediation Script Generation',
    },
  });
});
