import { type RequestHandler } from "express";

export const requestLoggerMiddleware: RequestHandler  = (req, res, next) => {
  console.log(`Recieved a ${req.method} request from ${req.host} at: ${Date.now()}`)
  next();
}