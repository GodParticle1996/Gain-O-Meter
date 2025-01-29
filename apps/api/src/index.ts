import 'dotenv/config'
import cors from 'cors'
import connectDatabase from './database/database'
import { config } from './config/app.config'
import cookieParser from 'cookie-parser'
import { HTTPSTATUS } from './config/http.config'
import authRoutes from './modules/auth/auth.routes'
import { asyncHandler } from './middlewares/asyncHandler'
import { errorHandler } from './middlewares/errorHandler'
import express, { NextFunction, Request, Response } from 'express'
import sessionRoutes from './modules/session/session.routes'
import passport from './middlewares/passport'

const app = express()
const BASE_PATH = config.BASE_PATH

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(
  cors({
    origin: config.APP_ORIGIN,
    credentials: true,
  }),
)

app.use(cookieParser())
app.use(passport.initialize())

app.get(
  '/',
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    res.status(HTTPSTATUS.OK).json({
      message: 'Health Check Successful',
    })
  }),
)

app.use(`${BASE_PATH}/auth`, authRoutes)

app.use(`${BASE_PATH}/session`, sessionRoutes)

app.use(errorHandler)

app.listen(config.PORT, async () => {
  console.log(`Server listening on port ${config.PORT} in ${config.NODE_ENV}`)
  await connectDatabase()
})
