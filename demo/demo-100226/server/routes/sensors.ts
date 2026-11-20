import { Router, Response } from 'express';
import { db } from '../db';
import { requireAuth, requirePanel, requireAction, AuthenticatedRequest } from '../middleware/auth';

export const sensorsRouter = Router();

// List all sensor nodes (Gated to analyst, admin, auditor)
sensorsRouter.get('/', requireAuth, requirePanel('sensors'), (req: AuthenticatedRequest, res: Response) => {
  res.json({
    count: db.sensors.length,
    sensors: db.sensors,
  });
});

// Sensors are not remotely controllable from this console: there is no control channel to the physical taps,
// so these actions are refused (and audited) rather than reporting a result that never happened.
const refuse = (action: string, verb: string) => (req: AuthenticatedRequest, res: Response) => {
  const sensor = db.sensors.find((s) => s.id === req.params.id);
  if (!sensor) {
    res.status(404).json({ error: 'Sensor node not found' });
    return;
  }
  db.logAudit({
    actorId: req.user?.id || 'unknown',
    actorUsername: req.user?.username || 'unknown',
    actorRole: req.user?.role || 'analyst',
    action,
    panel: 'sensors',
    targetResource: `${sensor.name} (${sensor.id})`,
    ipAddress: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1',
    status: 'ERROR',
    details: `${verb} not performed: no remote management channel is configured for sensors.`,
  });
  res.status(501).json({
    error: 'Not implemented',
    code: 'SENSOR_MANAGEMENT_UNAVAILABLE',
    performed: false,
    message: `Remote ${verb} was not performed because no sensor management channel exists; manage the sensor on its host.`,
  });
};

sensorsRouter.post('/:id/calibrate', requireAuth, requirePanel('sensors'), requireAction('sensor_calibrate'), refuse('CALIBRATE_SENSOR', 'calibration'));
sensorsRouter.post('/:id/reboot', requireAuth, requirePanel('sensors'), requireAction('sensor_reboot'), refuse('REBOOT_SENSOR_NODE', 'reboot'));
