import { Router, Response } from 'express';
import { requireAuth, requirePanel, AuthenticatedRequest } from '../middleware/auth';
import { buildAssetFusionGraph } from '../fusion';

export const fusionRouter = Router();

// Asset graph built from PLB_Assets.csv, enrolled agents and ingested alerts (gated to analyst & admin).
fusionRouter.get('/', requireAuth, requirePanel('fusion'), (_req: AuthenticatedRequest, res: Response) => {
  res.json(buildAssetFusionGraph());
});
