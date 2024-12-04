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

dotenv.config()

const JWT_SECRET = Config.JWT_SECRET

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
          profilePicture: profile._json.picture
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
  const token = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '30 days' })

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

    const user = await User.findOne({ email })

    if (!user || !user.password) {
      res.status(401).send('User not found')
      return
    }

    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
      res.status(401).send('Invalid password')
      return
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: '7 days'
    })
    res
      .cookie(COOKIE_AUTH, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      })
      .status(200)
      .send('Login successful')
  }
)

router.post('/register', async (req, res) => {
  const { email, password } = req.body
  const hashedPassword = await bcrypt.hash(password, 10)

  const user = new User({ email, password: hashedPassword })

  await user.save()
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30 days' })
  res
    .cookie(COOKIE_AUTH, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    })
    .status(201)
    .send('User registered')
})

router.post('/logout', (req, res) => {
  res.clearCookie(COOKIE_AUTH, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  })
  res.status(200).send('Logged out')
})

export default router
