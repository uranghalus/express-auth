/* eslint-disable @typescript-eslint/comma-dangle */
import express, { NextFunction, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import {
  createUserByEmailAndPassword,
  findUserByEmail,
  findUserById,
} from '../users/users.services';
import { generateTokens } from '../../utils/jwt';
import {
  addRefreshTokenToWhitelist,
  deleteRefreshToken,
  findRefreshTokenById,
  revokeTokens,
} from './auth.services';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { hashToken } from '../../utils/hashToken';
const AuthRouter = express.Router();

AuthRouter.post('/register', async (req: Request, res: Response, next: any) => {
  try {
    const { email, password } = req.body as any;
    if (!email || !password) {
      res.status(400);
      res.send({ msg: 'You must provide an email and a password.' });
    }
    const existingUser = await findUserByEmail(email);

    if (existingUser) {
      res.send({ msg: 'Email Telah Terpakai' });
    }

    const user = await createUserByEmailAndPassword({ email, password });
    if (user) {
      const jti = uuidv4();
      const { accessToken, refreshToken } = generateTokens(user, jti);
      await addRefreshTokenToWhitelist({ jti, refreshToken, userId: user.id });

      res.send({
        accestoken: accessToken,
        refreshToken: refreshToken,
      });
    }
  } catch (error: any) {
    next(error);
  }
});
// Login
AuthRouter.post(
  '/login',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body as any;
      if (!email || !password) {
        res.status(400);
        res.send({ msg: 'You must provide an email and a password.' });
      }
      const user = await findUserByEmail(email);
      if (!user) {
        res.status(403);
        res.send({ msg: 'Email Not Found!.' });
      }
      const matchPassword = await bcrypt.compare(
        password,
        user?.password as string
      );
      if (!matchPassword) {
        res.status(403);
        res.send({ msg: 'Password Not Match!' });
      }

      const jti = uuidv4();
      const { accessToken, refreshToken } = generateTokens(user, jti);
      await addRefreshTokenToWhitelist({ jti, refreshToken, userId: user?.id });

      res.json({
        accessToken,
        refreshToken,
      });
    } catch (error) {
      next(error);
    }
  }
);
// Refresh Token
AuthRouter.post(
  '/refreshtoken',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        res.status(400);
        throw new Error('Missing refresh token.');
      }
      const payload: any = jwt.verify(
        refreshToken,
        process.env.JWT_REFRESH_SECRET!
      );
      const savedRefreshToken = await findRefreshTokenById(payload.jti);
      if (!savedRefreshToken || savedRefreshToken.revoked === true) {
        res.status(401);
        throw new Error('Unauthorized');
      }

      const hashedToken = hashToken(refreshToken);
      if (hashedToken !== savedRefreshToken.hashedToken) {
        res.status(401);
        throw new Error('Unauthorized');
      }

      const user = await findUserById(payload.userId);
      if (!user) {
        res.status(401);
        throw new Error('Unauthorized');
      }

      await deleteRefreshToken(savedRefreshToken.id);
      const jti = uuidv4();
      const { accessToken, refreshToken: newRefreshToken } = generateTokens(
        user,
        jti
      );
      await addRefreshTokenToWhitelist({
        jti,
        refreshToken: newRefreshToken,
        userId: user.id,
      });

      res.json({
        accessToken,
        refreshToken: newRefreshToken,
      });
    } catch (error) {
      next(error);
    }
  }
);
// Revoke Token
// Move this logic where you need to revoke the tokens( for ex, on password reset)
AuthRouter.post('/revokeRefreshTokens', async (req, res, next) => {
  try {
    const { userId } = req.body;
    await revokeTokens(userId);
    res.json({ message: `Tokens revoked for user with id #${userId}` });
  } catch (err) {
    next(err);
  }
});

export { AuthRouter };
