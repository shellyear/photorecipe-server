import { Profile, VerifyCallback } from 'passport-google-oauth20'
import User, { IUser } from '../models/User'
import passport from 'passport'
import { Request, Response } from 'express'
import Config from '../config'
import { COOKIE_AUTH } from '../middlewares/auth'
import AuthService from '../services/authService'

const temporaryCodes = new Map<string, { userId: string; expiresAt: number }>() // Store codes and their associated user IDs (or sessions)

const googleStrategyCallback = async (
  accessToken: string,
  refreshToken: string,
  profile: Profile,
  done: VerifyCallback
) => {
  const email = profile?.emails?.[0]?.value

  if (!email) {
    return done(new Error('No email found for this Google account.'))
  }

  let user = await User.findOne({ googleId: profile.id })
  if (!user) {
    user = new User({
      googleId: profile.id,
      email,
      name: profile.displayName,
      profilePicture: profile._json.picture,
      isVerified: true
    })
    await user.save()
  }
  return done(null, user)
}

const passportAuthenticateGoogle = passport.authenticate('google', {
  scope: ['profile', 'email']
})

const googleCallback = (req: Request, res: Response) => {
  const user = req.user as IUser
  if (user && user._id) {
    const tempCode = AuthService.generateTemporaryCode()
    temporaryCodes.set(tempCode, {
      userId: user._id.toString(),
      expiresAt: Date.now() + 5 * 60 * 1000 // Code valid for 5 minutes
    })

    res.send(`
        <script>
          window.opener.postMessage({ code: "${tempCode}" }, "${Config.FRONT_END_BASE_URL}");
          window.close();
        </script>
      `)
  }
}

const validateCodeAndGenerateToken = async (req: Request, res: Response) => {
  const { code } = req.body

  if (!code || !temporaryCodes.has(code)) {
    res.status(400).send('Invalid or expired code')
    return
  }

  const tempData = temporaryCodes.get(code)

  if (!tempData) return

  if (Date.now() > tempData.expiresAt) {
    temporaryCodes.delete(code) // Cleanup expired codes
    res.status(400).send('Code expired')
    return
  }

  const userId = tempData.userId
  const token = AuthService.generateJWT(userId, '30d')
  temporaryCodes.delete(code)

  res
    .cookie(COOKIE_AUTH, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    })
    .status(200)
    .send(`${COOKIE_AUTH} has been set in cookie`)
}

const login = async (
  req: Request<
    {},
    {},
    {
      email: string
      password: string
    }
  >,
  res: Response
) => {
  const { email, password } = req.body

  try {
    const user = await AuthService.authenticateUser(email, password)

    if (!user) {
      res.status(401).json({
        code: 'INVALID_CREDENTIALS',
        message: 'Incorrect email or password'
      })
      return
    }

    const token = AuthService.generateJWT(user._id, '7 days')

    res
      .cookie(COOKIE_AUTH, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      })
      .status(200)
      .json({ code: 'Login successful' })
  } catch (error) {
    console.error((error as Error).message, new Date())
    res
      .status(400)
      .json({ code: 'LOGIN_ERROR', message: 'Error during signing' })
  }
}

const register = async (req: Request, res: Response) => {
  const { email, password } = req.body

  try {
    const existingUser = await User.findOne({ email })
    if (existingUser && existingUser.isVerified) {
      res
        .status(400)
        .json({ code: 'EMAIL_IN_USE', message: 'Email already in use' })
      return
    }

    /* User exists but is not verified yet, resend verification email */
    if (existingUser && !existingUser.isVerified) {
      const verificationToken = AuthService.generateVerificationToken()
      existingUser.verificationToken = verificationToken
      existingUser.verificationTokenExpiresAt = new Date(
        Date.now() + 1 * 60 * 60 * 1000
      ) // 1 hour
      await existingUser.save()

      await AuthService.sendVerificationEmail(
        existingUser.email,
        existingUser.verificationToken
      )

      res.status(200).json({ message: 'Verification email resent' })
      return
    }

    /* If no existing user, create a new user */
    const user = await AuthService.createUser(email, password)
    await AuthService.sendVerificationEmail(user.email, user.verificationToken)
    res
      .status(201)
      .json({ message: 'User registered. Verification email sent.' })
  } catch (error) {
    console.error(error)
    res.status(500).json({
      code: 'REGISTRATION_ERROR',
      message: 'Error during registration'
    })
  }
}

const verifyEmail = async (req: Request, res: Response) => {
  const { token: verificationToken } = req.query

  try {
    const user = await AuthService.verifyEmail(verificationToken as string)

    if (!user) {
      res.status(400).json({
        code: 'INVALID_TOKEN',
        message: 'Invalid or expired verification token'
      })
      return
    }

    const token = AuthService.generateJWT(user._id.toString(), '90d')
    res
      .cookie(COOKIE_AUTH, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 90 * 24 * 60 * 60 * 1000 // (90 days)
      })
      .status(200)
      .json({ message: 'User has been verified' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error verifying email' })
  }
}

const logout = (req: Request, res: Response) => {
  res.clearCookie(COOKIE_AUTH, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  })
  res.status(200).json({
    message: 'User has been logged out'
  })
}

const AuthController = {
  googleStrategyCallback,
  passportAuthenticateGoogle,
  googleCallback,
  validateCodeAndGenerateToken,
  login,
  register,
  verifyEmail,
  logout
}

export default AuthController
