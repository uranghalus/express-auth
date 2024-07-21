import express from 'express';

import MessageResponse from '../interfaces/MessageResponse';
import { AuthRouter } from './auth/auth.routes';
import { UserRouter } from './users/users.routes';
const router = express.Router();

router.get<{}, MessageResponse>('/', (req, res) => {
  res.json({
    message: 'API - 👋🌎🌍🌏',
  });
});

router.use('/auth', AuthRouter);
router.use('/users', UserRouter);

export default router;
