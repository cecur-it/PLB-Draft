import { Router, Response } from 'express';
import { join } from 'node:path';
import { db } from '../db';
import { requireAuth, requireAction, AuthenticatedRequest } from '../middleware/auth';
import { ModelRegistry, RegistryError } from '../inference/registry';
import { loadEvalRecord } from '../inference/evalRecords';

export const modelsRouter = Router();

const registry = new ModelRegistry(process.env.CS3_MODELS_DIR || join(process.cwd(), 'models')).load();

modelsRouter.get('/', requireAuth, requireAction('view_model_registry'), (_req: AuthenticatedRequest, res: Response) => {
  res.json({
    models: registry.list().map((e) => ({ id: e.manifest.name, roles: e.manifest.roles, license: e.manifest.license, digest: e.manifest.digest, state: e.state })),
    rejected: registry.rejected.map((r) => ({ dir: r.dir, reason: r.reason })),
  });
});

// Promotion is evidence-based: the score comes from stored eval records, never from the request.
modelsRouter.post('/:id/promote', requireAuth, requireAction('promote_model'), (req: AuthenticatedRequest, res: Response) => {
  const id = req.params.id;
  const entry = registry.get(id);
  if (!entry) {
    res.status(404).json({ error: 'Not Found', message: 'Unknown model.' });
    return;
  }
  const audit = (status: 'ALLOW_200' | 'DENY_403', details: string) =>
    db.logAudit({
      actorId: req.user!.id, actorUsername: req.user!.username, actorRole: req.user!.role,
      action: 'MODEL_PROMOTE', panel: 'models', targetResource: id,
      ipAddress: (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1',
      status, details,
    } as any);
  try {
    const current = loadEvalRecord(id);
    if (!current) throw new RegistryError('no gateway eval record for this model');
    const baseline = loadEvalRecord(entry.manifest.eval.baseline);
    registry.promoteWithEval(id, current, baseline);
    audit('ALLOW_200', `Promoted ${id} to approved (score ${current.score}).`);
    res.json({ id, state: 'approved', score: current.score });
  } catch (e: any) {
    if (!(e instanceof RegistryError)) throw e;
    audit('DENY_403', `Promotion of ${id} refused: ${e.message}`);
    res.status(409).json({ error: 'Promotion Refused', message: e.message });
  }
});
