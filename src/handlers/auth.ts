import { z } from 'zod';
import bcrypt from 'bcrypt'
import { type RequestHandler } from "express";
import { prisma } from "../db";
import { validateData } from '../middlewares/bodyValidationMiddleware';
import { RequestHandlerWithBody } from '../types';
import { tryCatch } from '../utils/tryCatch';
import { StatusCodes } from 'http-status-codes';
import { generateTokens } from '../services/jwt';

export const userSignupBody = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const userLoginBody = z.object({
  email: z.string().email(),
  password: z.string(),
});

const SALT_ROUNDS = 12;

const signupHandler: RequestHandlerWithBody<z.infer<typeof userSignupBody>> = async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, SALT_ROUNDS);

  const {data: user, error: userError} = await tryCatch(prisma.user.create({
    data: {
      email: req.body.email,
      hashedPassword,
    },
  }));

  if (userError) {
    console.log(userError);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      error: "Something went wrong while creating the user",
    }); 
    return
  }

  const {data: tokens, error} = await tryCatch(generateTokens(user));

  if (error) {
    console.log(error)
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      error: "Something went wrong",
    });
  }

  res.status(StatusCodes.OK).json(tokens);
}

const loginHandler: RequestHandlerWithBody<z.infer<typeof userLoginBody>> = async (req, res) => {
  const {data: user, error: userError} = await tryCatch(prisma.user.findUnique({where: {email: req.body.email}}));

  if (userError) {
    console.log(userError);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      error: "Something went wrong while retrieving the user",
    }); 
    return
  }

  if (!user) {
    res.status(StatusCodes.UNAUTHORIZED).json({
      error: "Incorrect email or password"
    })
    return
  }

  const isAuthenticated = await bcrypt.compare(req.body.password, user.hashedPassword)
  
  if (!isAuthenticated) {
    res.status(StatusCodes.UNAUTHORIZED).json({
      error: "Incorrect email or password"
    })
    return
  }

  const {data: tokens, error} = await tryCatch(generateTokens(user));

  if (error) {
    console.log(error)
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      error: "Something went wrong",
    });
  }

  res.status(StatusCodes.OK).json(tokens)
}

export const signupHandlers: RequestHandler[] = [
  validateData(userSignupBody),
  signupHandler
];

export const loginHandlers: RequestHandler[] = [
  validateData(userLoginBody),
  loginHandler
];