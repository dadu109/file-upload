import { User } from "../../generated/prisma";
import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import { prisma } from "../db";

type JWTTokens = {
    accessToken: string;
    refreshToken: string;
}

const SECRET_KEY = process.env.JWT_SECRET

export const generateTokens = async (user: User): Promise<JWTTokens> => {
  const payload = {
    userId: user.id,
    email: user.email,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (15 * 60) // expires in 15 minutes
  }
  
  const accessToken = jwt.sign(payload, SECRET_KEY!);
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

export const verifyAccessToken = ({accessToken}: {accessToken: string}): boolean => {
  try {
    jwt.verify(accessToken, SECRET_KEY!);
    return true;
  } catch (_) { // eslint-disable-line @typescript-eslint/no-unused-vars
    return false;
  }
}

export const verifyAndRegenerateRefreshToken = async ({
  refreshToken,
  user
}: {
    refreshToken: string,
    user: User
}): Promise<JWTTokens | null> => {
  try {
    const tokenRecord = await prisma.refreshToken.findFirst({
      where: {
        token: refreshToken,
        userId: user.id,
        expiresAt: {
          gt: new Date() // not expired
        }
      }
    });

    if (!tokenRecord) {
      return null;
    }

    const newTokens = await generateTokens(user); 

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