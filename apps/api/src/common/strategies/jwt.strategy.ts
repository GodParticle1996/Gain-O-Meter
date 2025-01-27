import {
  ExtractJwt,
  Strategy as JwtStrategy,
  StrategyOptionsWithRequest,
} from 'passport-jwt'
import { config } from '../../config/app.config'
import passport, { PassportStatic } from 'passport'
import { ErrorCode } from '../enums/error-code.enum'
import { userService } from '../../modules/user/user.module'
import { UnauthorizedException } from '../utils/catch-errors'

interface JwtPayload {
  userId: string
  sessionId: string
}

const options: StrategyOptionsWithRequest = {
  jwtFromRequest: ExtractJwt.fromExtractors([
    (req) => {
      const accessToken = req.cookies.accessToken
      if (!accessToken) {
        throw new UnauthorizedException(
          'Unauthorized access token',
          ErrorCode.AUTH_TOKEN_NOT_FOUND,
        )
      }
      return accessToken
    },
  ]),
  secretOrKey: config.JWT.SECRET,
  audience: ['user'],
  algorithms: ['HS256'],
  passReqToCallback: true,
}

export const setupJwtStrategy = (passport: PassportStatic) => {
  passport.use(
    new JwtStrategy(options, async (req, payload: JwtPayload, done) => {
      try {
        const user = await userService.findUserById(payload.userId)
        if (!user) {
          return done(null, false)
        }
        /* 
        We are able to attach the sessionId to the request object because we have modifed the request object by Express.js to include a sessionId property. Check the 
        file: src/@types/index.d.ts
        */
        req.sessionId = payload.sessionId

        // FIXME: We maybe need to check if the sessionId is valid and if it is expired
        return done(null, user)
      } catch (error) {
        return done(error, false)
      }
    }),
  )
}

export const authenticateJWT = passport.authenticate('jwt', { session: false })
