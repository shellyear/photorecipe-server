import express, { Request } from 'express'
import passport from 'passport'
import { Strategy } from 'passport-google-oauth20'
import bcrypt from 'bcrypt'
import User, { IUser } from '../models/User'
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || ''

passport.use(
  new Strategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: '/auth/google/callback'
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
          name: profile.displayName
        })
        await user.save()
      }
      return done(null, user)
    }
  )
)

const router = express.Router()

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
  ): Promise<any> => {
    const { email, password } = req.body

    const user = await User.findOne({ email })

    if (!user || !user.password) {
      return res.status(401).send('User not found')
    }

    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) return res.status(401).send('Invalid password')

    const token = jwt.sign({ id: user._id }, JWT_SECRET)
    res.json({ token })
  }
)

router.post('/register', async (req, res) => {
  const { email, password } = req.body
  const hashedPassword = await bcrypt.hash(password, 10)

  const user = new User({ email, password: hashedPassword })
  await user.save()

  const token = jwt.sign({ id: user._id }, JWT_SECRET)
  res.json({ token })
})

router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
)

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const user = req.user as IUser
    if (user && user._id) {
      const token = jwt.sign({ id: user._id }, JWT_SECRET)
      res.json({ token })
    }
  }
)

export default router;
