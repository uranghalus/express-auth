/* eslint-disable @typescript-eslint/comma-dangle */
import express, { NextFunction, Request, Response } from 'express';
import { isAuthenticated } from '../../middlewares';
import { findUserById } from './users.services';

const UserRouter = express.Router();

// Define a type for the user object with an optional password property
interface User {
  id?: string;
  name?: string;
  email?: string;
  password?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

UserRouter.get(
  '/profile',
  isAuthenticated,
  async (req: any, res: Response, next: NextFunction) => {
    try {
      const { userId } = req.payload;
      const user: User | null = await findUserById(userId);

      if (user) {
        delete user.password; // Safe to delete as 'password' is optional
      }

      res.json(user);
    } catch (error) {
      next(error);
    }
  }
);

export { UserRouter };
