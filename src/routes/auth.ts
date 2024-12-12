import express, { Request } from 'express'
import passport from 'passport'
import { Strategy } from 'passport-google-oauth20'
import bcrypt from 'bcrypt'
import User, { IUser } from '../models/User'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import Config from '../config'
import crypto from 'crypto'
import { COOKIE_AUTH } from '../middlewares/auth'
import nodemailer from 'nodemailer'

dotenv.config()

const JWT_SECRET = Config.JWT_SECRET

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: Config.SMTP_USER,
    pass: Config.SMTP_PASS
  }
})

passport.use(
  new Strategy(
    {
      clientID: Config.GOOGLE_CLIENT_ID,
      clientSecret: Config.GOOGLE_CLIENT_SECRET,
      callbackURL: `${Config.API_BASE_URL}/api/auth/google/callback` // this url is set in google OAuth client -> Authorized redirect URIs
    },
    async (accessToken, refreshToken, profile, done) => {
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
  )
)

const router = express.Router()
const temporaryCodes = new Map<string, { userId: string; expiresAt: number }>() // Store codes and their associated user IDs (or sessions)

/* OAuth flow routes */
router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
)

/* For retrieving google account info of the user. This route is fired on passport callbackURL */
router.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false
  }), // authenticate and retrieve google account info
  (req, res) => {
    const user = req.user as IUser
    if (user && user._id) {
      const tempCode = crypto.randomBytes(16).toString('hex')
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
)

router.post('/token', async (req, res) => {
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
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30 days' })

  temporaryCodes.delete(code)

  res
    .cookie(COOKIE_AUTH, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    })
    .status(200)
    .send(`${COOKIE_AUTH} has been set in cookie`)
})

/* Email & password routes */
router.post(
  '/login',
  async (
    req: Request<
      {},
      {},
      {
        email: string
        password: string
      }
    >,
    res
  ) => {
    const { email, password } = req.body

    try {
      const user = await User.findOne({ email })

      if (!user) {
        res.status(404).json({
          code: 'INVALID_CREDENTIALS',
          message: 'Please type correct email and password'
        })
        return
      }

      if (!user.email || !user.password) {
        res.status(401).json({
          code: 'INVALID_CREDENTIALS',
          message: 'Please type correct email and password'
        })
        return
      }

      const validPassword = await bcrypt.compare(password, user.password)
      if (!validPassword) {
        res.status(401).send({
          code: 'INVALID_CREDENTIALS',
          message: 'Please type correct email and password'
        })
        return
      }

      const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
        expiresIn: '7 days'
      })

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
)

router.post('/register', async (req, res) => {
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
      const verificationToken = crypto.randomBytes(32).toString('hex')
      existingUser.verificationToken = verificationToken
      existingUser.verificationTokenExpiresAt = new Date(
        Date.now() + 1 * 60 * 60 * 1000
      ) // 1 hour
      await existingUser.save()

      const verificationUrl = `${Config.FRONT_END_BASE_URL}/verify-email?token=${verificationToken}`
      const mailOptions = {
        from: Config.SMTP_USER,
        to: existingUser.email,
        subject: 'Verify your email',
        html: `    
          <p>Hello,</p>
          <p>Thank you for registering with us. Please click the link below to verify your email address:</p>
          <p><a href="${verificationUrl}" target="_blank">Click here to verify your email</a></p>
          <p><b>Once your email is verified, you will be automatically logged into your account and you can proceed to use the app right away. There is no need to log in again.</b></p>
          <p>If you did not register with us, please ignore this email.</p>
        `
      }

      await transporter.sendMail(mailOptions)

      res.status(200).json({ message: 'Verification email resent' })
      return
    }

    /* If no existing user, create a new user */
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    const verificationToken = crypto.randomBytes(32).toString('hex')

    const user = new User({
      email,
      password: hashedPassword,
      verificationToken,
      isVerified: false,
      verificationTokenExpiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000) // 1 hour
    })

    await user.save()

    const verificationUrl = `${Config.FRONT_END_BASE_URL}/verify-email?token=${verificationToken}`
    const mailOptions = {
      from: Config.SMTP_USER,
      to: user.email,
      subject: 'Verify your email',
      text: `          
        <p>Hello,</p>
        <p>Thank you for registering with us. Please click the link below to verify your email address:</p>
        <p><a href="${verificationUrl}" target="_blank">Click here to verify your email</a></p>
        <p><b>Once your email is verified, you will be automatically logged into your account and you can proceed to use the app right away. There is no need to log in again.</b></p>
        <p>If you did not register with us, please ignore this email.</p>
      `
    }

    await transporter.sendMail(mailOptions)
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
})

router.get('/verify-email', async (req, res) => {
  const { token: verificationToken } = req.query

  try {
    const user = await User.findOne({ verificationToken })

    if (!user) {
      res
        .status(400)
        .json({ code: 'INVALID_TOKEN', message: 'Invalid or expired token' })
      return
    }

    if (
      user.verificationTokenExpiresAt &&
      user.verificationTokenExpiresAt < new Date()
    ) {
      res.status(400).json({
        code: 'INVALID_TOKEN',
        message: 'Verification token has expired'
      })
      return
    }

    user.isVerified = true
    user.verificationToken = undefined
    user.verificationTokenExpiresAt = undefined
    await user.save()

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: '90 days'
    })

    res
      .cookie(COOKIE_AUTH, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 90 * 24 * 60 * 60 * 1000 // (90 days)
      })
      .status(200)
      .send('User has been verified')
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error verifying email' })
  }
})

router.post('/logout', (req, res) => {
  res.clearCookie(COOKIE_AUTH, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  })
  res.status(200).json({
    message: 'User has been logged out'
  })
})

export default router
