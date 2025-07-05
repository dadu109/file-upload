import { User } from "../../generated/prisma";
import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import { prisma } from "../db";

export interface JwtPayload {
  userId: string;
  email: string;
  iat?: number;
  exp?: number;
}

type JWTTokens = {
    accessToken: string;
    refreshToken: string;
}

export const JWT_SECRET_KEY = process.env.JWT_SECRET

export const generateTokens = async (user: User): Promise<JWTTokens> => {
  const payload = {
    userId: user.id,
    email: user.email,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (15 * 60) // expires in 15 minutes
  }
  
  const accessToken = jwt.sign(payload, JWT_SECRET_KEY!);
  const refreshToken = crypto.randomBytes(32).toString('hex');
 
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    }
  });
  
  return {
    accessToken,
    refreshToken
  };
}

export const verifyAndRegenerateRefreshToken = async (refreshToken: string): Promise<JWTTokens | null> => {
  try {
    const tokenRecord = await prisma.refreshToken.findFirst({
      where: {
        token: refreshToken,
        expiresAt: {
          gt: new Date() // not expired
        }
      }
    });

    if (!tokenRecord) {
      return null;
    }

    const userRecord = await prisma.user.findUnique({
      where: {
        id: tokenRecord.userId
      }
    })

    if(!userRecord) {
      return null;
    }

    const newTokens = await generateTokens(userRecord); 

    await prisma.refreshToken.delete({
      where: {
        id: tokenRecord.id
      }
    });

    return newTokens;
  } catch (error) {
    console.error('Error verifying/regenerating refresh token:', error);
    return null;
  }
}