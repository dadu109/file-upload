import express from 'express';
import { loginHandlers, signupHandlers } from './handlers/auth';
import { requestLoggerMiddleware } from './middlewares/requestLogger';
import './db'

const HOST = process.env.HOST || 'localhost'
const PORT = process.env.PORT || '3000'

const app = express();
const protectedRouter = express.Router();

app.use(express.json());
app.use(requestLoggerMiddleware)
app.use("/protected", protectedRouter)

app.post('/signup', signupHandlers)
app.post('/login', loginHandlers)

protectedRouter.get('/', (req, res) => {
  res.status(200).json({
    siema1: 'test1'
  })
})

app.listen(3000, () => {
  console.log(`Starting the server at http://${HOST}:${PORT}`)
})