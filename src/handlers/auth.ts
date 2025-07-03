import { type RequestHandler } from "express";
import { prisma } from "../db";

export const signupHandler: RequestHandler = async (req, res) => {
  try {
    const user = await prisma.user.create({
      data: {
        name: "Alice",
        email: "alice@prisma1.io",
      },
    });
    res.status(200).json({
      userId: user.id,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      error: "Something went wrong while creating the user",
    });
  }
};
