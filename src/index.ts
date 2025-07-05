import express from 'express';
import { loginHandlers, signupHandlers } from './handlers/auth';
import { requestLoggerMiddleware } from './middlewares/requestLogger';
import './db'
import { AuthenticatedRequest, authMiddleware } from './middlewares/authMiddleware';

const HOST = process.env.HOST || 'localhost'
const PORT = process.env.PORT || '3000'

const app = express();
const protectedRouter = express.Router();

app.use(express.json());
app.use(requestLoggerMiddleware)
app.use("/protected", protectedRouter)

app.post('/signup', signupHandlers)
app.post('/login', loginHandlers)

protectedRouter.get('/user', authMiddleware, (req: AuthenticatedRequest, res) => {
  res.status(200).json({
    email: req.user?.email
  })
})

app.listen(3000, () => {
  console.log(`Starting the server at http://${HOST}:${PORT}`)
})