import { NextFunction, Response, Request } from "express";
import { JWT_SECRET_KEY, JwtPayload } from "../services/jwt";
import { StatusCodes } from "http-status-codes";
import {  tryCatchSync } from "../utils/tryCatch";
import jwt from "jsonwebtoken"

export interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
}

type AuthenticatedRequestHandler = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => void;

export const authMiddleware: AuthenticatedRequestHandler = (req, res, next) => {
  const token = req.headers.authorization?.split('Bearer ')[1];

  if(!token) {
    res.status(StatusCodes.UNAUTHORIZED).json({
      error: 'Missing auth token'
    })
    return;
  }

  const {data: decoded, error} = tryCatchSync(() => jwt.verify(token, JWT_SECRET_KEY!))

  if(error) {
    if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({ 
        error: 'Token expired' 
      });
    } else if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({ 
        error: 'Invalid token' 
      });
    } else {
      res.status(500).json({ 
        error: 'Token verification failed' 
      });
    }
  }

  req.user = decoded as JwtPayload;
  next();
}