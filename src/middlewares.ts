/* eslint-disable @typescript-eslint/comma-dangle */
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import ErrorResponse from './interfaces/ErrorResponse';

export function notFound(req: Request, res: Response, next: NextFunction) {
  res.status(404);
  const error = new Error(`🔍 - Not Found - ${req.originalUrl}`);
  next(error);
}

export function isAuthenticated(req: any, res: Response, next: NextFunction) {
  const { authorization } = req.headers;
  if (!authorization) {
    res.status(401);
    throw new Error('🚫 Un-Authorized 🚫');
  }
  try {
    const token = authorization.split(' ')[1];
    const payload = jwt.verify(token, process.env.JWT_SECRET!);
    req.payload = payload;
  } catch (error: any) {
    res.status(401);
    if (error.name === 'TokenExpiredError') {
      throw new Error(error.name);
    }
    throw new Error('🚫 Un-Authorized 🚫');
  }
  return next();
}
export function errorHandler(
  err: Error,
  req: Request,
  res: Response<ErrorResponse>
) {
  const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
  res.status(statusCode);
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? '🥞' : err.stack,
  });
}
