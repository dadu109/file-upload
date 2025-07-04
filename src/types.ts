import { RequestHandler } from "express";

export type RequestHandlerWithBody<T> = RequestHandler<unknown, unknown, T> 