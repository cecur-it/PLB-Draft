import { Router, Response } from 'express';
import { db } from '../db';
import { requireAuth, requirePanel, AuthenticatedRequest } from '../middleware/auth';
import { postureScore } from '../posture';
import { calculateHotCacheEpsEstimate, summarizeSensorHealth } from '../cecur/overviewMetrics';

export const overviewRouter = Router();

overviewRouter.get('/', requireAuth, requirePanel('overview'), (_req: AuthenticatedRequest, res: Response) => {
  const activeIncidents = db.incidents.filter((i) => i.status !== 'RESOLVED');
  const criticalIncidents = activeIncidents.filter((i) => i.severity === 'CRITICAL');
  const sensorSummary = summarizeSensorHealth(db.sensors);
  const now = new Date();

  const { score } = postureScore();
  const epsEstimate = calculateHotCacheEpsEstimate(db.cecurLogs, now);
  const avgDropped = Number(
    (db.sensors.reduce((acc, s) => acc + s.droppedPackets, 0) / (db.sensors.length || 1)).toFixed(2)
  );
  const highRiskUsers = db.activtrakSessions.filter((s) => s.riskScore >= 75).length;

  res.json({
    posture: {
      score,
      status: score === null ? 'NO_DATA' : score > 75 ? 'GUARDED' : score > 50 ? 'ELEVATED_THREAT' : 'CRITICAL_CONDITION',
      lastAssessment: now.toISOString(),
    },
    metrics: {
      activeIncidentsCount: activeIncidents.length,
      criticalIncidentsCount: criticalIncidents.length,
      totalEps: epsEstimate.value,
      epsEstimate,
      avgDroppedPercentage: avgDropped,
      unacknowledgedAlertsCount: db.cecurAlerts.filter((a) => a.status === 'new').length,
      highRiskUsersCount: highRiskUsers,
      sensorSummary,
    },
    recentIncidents: db.incidents.slice(0, 3),
    recentAlerts: db.cecurAlerts.slice(0, 5),
    activeSensors: db.sensors,
  });
});
