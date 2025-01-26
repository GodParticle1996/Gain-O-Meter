import jwt from 'jsonwebtoken'
import { ErrorCode } from '../../common/enums/error-code.enum'
import { VerificationEnum } from '../../common/enums/verification-code.enum'
import {
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
} from '@gainometer/base-ts-interfaces'
import {
  BadRequestException,
  HttpException,
  InternalServerException,
  NotFoundException,
  UnauthorizedException,
} from '../../common/utils/catch-errors'
import { config } from '../../config/app.config'
import { logger } from '../../common/utils/logger'
import { HTTPSTATUS } from '../../config/http.config'
import UserModel from '../../database/models/user.model'
import VerificationCodeModel from '../../database/models/verification.model'
import {
  RefreshTPayload,
  refreshTokenSignOptions,
  signJwtToken,
  verifyJwtToken,
} from '../../common/utils/jwt'
import SessionModel from '../../database/models/session.model'
import {
  ONE_DAY_IN_MS,
  anHourFromNow,
  calculateExpirationDate,
  fortyFiveMinutesFromNow,
  threeMinutesAgo,
} from '../../common/utils/date-time'
import { hashValue } from '../../common/utils/bcrypt'
import { sendEmail } from '../../mailers/mailer'
import {
  passwordResetTemplate,
  verifyEmailTemplate,
} from '../../mailers/templates/template'

export class AuthService {
  public async register(registerData: RegisterDto) {
    const { name, email, password } = registerData

    const existingUser = await UserModel.exists({
      email,
    })

    if (existingUser) {
      throw new BadRequestException(
        'User already exists with this email',
        ErrorCode.AUTH_EMAIL_ALREADY_EXISTS,
      )
    }
    const newUser = await UserModel.create({
      name,
      email,
      password,
    })

    const userId = newUser._id

    const verification = await VerificationCodeModel.create({
      userId,
      type: VerificationEnum.EMAIL_VERIFICATION,
      expiresAt: fortyFiveMinutesFromNow(),
    })

    // Sending verification email link
    const verificationUrl = `${config.APP_ORIGIN}/confirm-account?code=${verification.code}`
    await sendEmail({
      to: newUser.email,
      ...verifyEmailTemplate(verificationUrl),
    })

    return {
      user: newUser,
    }
  }

  public async login(loginData: LoginDto) {
    const { email, password, userAgent } = loginData

    logger.info(`Login attempt for email: ${email}`)
    const user = await UserModel.findOne({
      email: email,
    })

    if (!user) {
      logger.warn(`Login failed: User with email ${email} not found`)
      throw new BadRequestException(
        'Invalid email or password provided',
        ErrorCode.AUTH_USER_NOT_FOUND,
      )
    }

    const isPasswordValid = await user.comparePassword(password)
    if (!isPasswordValid) {
      logger.warn(`Login failed: Invalid password for email: ${email}`)
      throw new BadRequestException(
        'Invalid email or password provided',
        ErrorCode.AUTH_USER_NOT_FOUND,
      )
    }

    // Check if the user enable 2fa return user=null
    if (user.userPreferences.enable2FA) {
      logger.info(`2FA required for user ID: ${user._id}`)
      return {
        user: null,
        mfaRequired: true,
        accessToken: '',
        refreshToken: '',
      }
    }

    logger.info(`Creating session for user ID: ${user._id}`)
    const session = await SessionModel.create({
      userId: user._id,
      userAgent,
    })

    logger.info(`Signing tokens for user ID: ${user._id}`)
    const accessToken = signJwtToken({
      userId: user._id,
      sessionId: session._id,
    })

    const refreshToken = signJwtToken(
      {
        sessionId: session._id,
      },
      refreshTokenSignOptions,
    )

    logger.info(`Login successful for user ID: ${user._id}`)
    return {
      user,
      accessToken,
      refreshToken,
      mfaRequired: false,
    }
  }

  /*
  The main purpose is to implement a "sliding window" session mechanism, where sessions that are close to expiring (within one day) get automatically extended when used. This 
  helps maintain user sessions without requiring frequent re-logins while still maintaining security through regular token updates.

  The code first checks if a session needs to be refreshed by comparing the time remaining until session expiration with ONE_DAY_IN_MS (one day in milliseconds). It calculates 
  this by subtracting the current time (now) from the session's expiration time (session.expiredAt.getTime()). If the remaining time is less than or equal to one day, 
  sessionRequireRefresh becomes true.

  If a refresh is needed, the code updates the session's expiration date using calculateExpirationDate() with the configured refresh token expiration time 
  (config.JWT.REFRESH_EXPIRES_IN) and saves the updated session to the database.

  Then, it creates a new refresh token, but only if sessionRequireRefresh is true. The new token is created using signJwtToken() with the session ID as payload and some 
  refresh token options. If no refresh is needed, newRefreshToken remains undefined.
  */
  public async refreshToken(refreshToken: string) {
    const { payload } = verifyJwtToken<RefreshTPayload>(refreshToken, {
      secret: refreshTokenSignOptions.secret,
    })

    if (!payload) {
      throw new UnauthorizedException('Invalid refresh token')
    }

    const session = await SessionModel.findById(payload.sessionId)
    const now = Date.now()

    if (!session) {
      throw new UnauthorizedException('Session does not exist')
    }

    if (session.expiredAt.getTime() <= now) {
      throw new UnauthorizedException('Session expired')
    }

    const sessionRequireRefresh =
      session.expiredAt.getTime() - now <= ONE_DAY_IN_MS

    if (sessionRequireRefresh) {
      session.expiredAt = calculateExpirationDate(config.JWT.REFRESH_EXPIRES_IN)
      await session.save()
    }

    const newRefreshToken = sessionRequireRefresh
      ? signJwtToken(
          {
            sessionId: session._id,
          },
          refreshTokenSignOptions,
        )
      : undefined

    const accessToken = signJwtToken({
      userId: session.userId,
      sessionId: session._id,
    })

    return {
      accessToken,
      newRefreshToken,
    }
  }

  /* Here we are only taking the verification code and not the userId coz since a user will have to login to his email and then get the code, so we are sure that it is a valid 
  user and we dont need to verify the user again
  */
  public async verifyEmail(code: string) {
    const validCode = await VerificationCodeModel.findOne({
      code: code,
      type: VerificationEnum.EMAIL_VERIFICATION,
      // Here we only look for the code that is not expired. If the expiration time is > current time, then it is not expired and we find any such code
      expiresAt: { $gt: new Date() },
    })

    if (!validCode) {
      throw new BadRequestException('Invalid or expired verification code')
    }

    const updatedUser = await UserModel.findByIdAndUpdate(
      validCode.userId,
      {
        isEmailVerified: true,
      },
      /* By default, findOneAndUpdate() returns the document as it was before update was applied. If you set new: true, findOneAndUpdate() will instead give you the object 
      after update was applied.
      */
      { new: true },
    )

    if (!updatedUser) {
      throw new BadRequestException(
        'Unable to verify email address',
        ErrorCode.VALIDATION_ERROR,
      )
    }

    // Delete the verification code after successful verification
    await validCode.deleteOne()
    return {
      user: updatedUser,
    }
  }

  public async forgotPassword(email: string) {
    const user = await UserModel.findOne({
      email: email,
    })

    if (!user) {
      throw new NotFoundException('User not found')
    }

    // Check mail rate limit is 2 emails per 3 or 10 min
    const timeAgo = threeMinutesAgo()
    const maxAttempts = 2

    const count = await VerificationCodeModel.countDocuments({
      userId: user._id,
      type: VerificationEnum.PASSWORD_RESET,
      createdAt: { $gt: timeAgo },
    })

    if (count >= maxAttempts) {
      throw new HttpException(
        'Too many request, try again later',
        HTTPSTATUS.TOO_MANY_REQUESTS,
        ErrorCode.AUTH_TOO_MANY_ATTEMPTS,
      )
    }

    const expiresAt = anHourFromNow()
    const validCode = await VerificationCodeModel.create({
      userId: user._id,
      type: VerificationEnum.PASSWORD_RESET,
      expiresAt,
    })

    const resetLink = `${config.APP_ORIGIN}/reset-password?code=${
      validCode.code
    }&exp=${expiresAt.getTime()}`

    const { data, error } = await sendEmail({
      to: user.email,
      ...passwordResetTemplate(resetLink),
    })

    if (!data?.id) {
      throw new InternalServerException(`${error?.name} ${error?.message}`)
    }

    return {
      url: resetLink,
      emailId: data.id,
    }
  }

  public async resetPassword({ password, verificationCode }: ResetPasswordDto) {
    const validCode = await VerificationCodeModel.findOne({
      code: verificationCode,
      type: VerificationEnum.PASSWORD_RESET,
      expiresAt: { $gt: new Date() },
    })

    if (!validCode) {
      throw new NotFoundException('Invalid or expired verification code')
    }

    const hashedPassword = await hashValue(password)

    const updatedUser = await UserModel.findByIdAndUpdate(validCode.userId, {
      password: hashedPassword,
    })

    if (!updatedUser) {
      throw new BadRequestException('Failed to reset password!')
    }

    await validCode.deleteOne()

    await SessionModel.deleteMany({
      userId: updatedUser._id,
    })

    return {
      user: updatedUser,
    }
  }

  public async logout(sessionId: string) {
    return await SessionModel.findByIdAndDelete(sessionId)
  }
}
