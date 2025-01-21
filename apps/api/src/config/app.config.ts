import { getEnv } from '../common/utils/get-env'

const appConfig = () => ({
  NODE_ENV: getEnv('NODE_ENV', 'development'),
  APP_ORIGIN: getEnv('APP_ORIGIN', 'localhost'),
  PORT: getEnv('PORT', '5000'),
  BASE_PATH: getEnv('BASE_PATH', '/api/v1'),
  MONGO_URI: getEnv(
    'MONGO_URI',
    'mongodb+srv://GodParticle1996:IqrCIm1Xozu7Nbmv@gainometercluster1.fdlmb.mongodb.net/?retryWrites=true&w=majority&appName=GainOMeterCluster1',
  ),
  MONGO_DB_NAME: getEnv('MONGO_DB_NAME'),
  JWT: {
    SECRET: getEnv('JWT_SECRET'),
    EXPIRES_IN: getEnv('JWT_EXPIRES_IN', '15m'),
    REFRESH_SECRET: getEnv('JWT_REFRESH_SECRET'),
    REFRESH_EXPIRES_IN: getEnv('JWT_REFRESH_EXPIRES_IN', '30d'),
  },
  MAILER_SENDER: getEnv('MAILER_SENDER'),
  RESEND_API_KEY: getEnv('RESEND_API_KEY'),
})

export const config = appConfig()
