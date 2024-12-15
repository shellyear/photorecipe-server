import express from 'express'
import passport from 'passport'
import { Strategy } from 'passport-google-oauth20'
import dotenv from 'dotenv'
import Config from '../config'
import AuthController from '../controllers/authController'

dotenv.config()

passport.use(
  new Strategy(
    {
      clientID: Config.GOOGLE_CLIENT_ID,
      clientSecret: Config.GOOGLE_CLIENT_SECRET,
      callbackURL: `${Config.API_BASE_URL}/api/auth/google/callback` // this url is set in google OAuth client -> Authorized redirect URIs
    },
    AuthController.googleStrategyCallback
  )
)

const router = express.Router()

/* OAuth flow routes */
router.get('/google', AuthController.passportAuthenticateGoogle)

/* For retrieving google account info of the user. This route is fired on passport callbackURL */
router.get(
  '/google/callback',
  passport.authenticate('google', {
    session: false
  }), // authenticate and retrieve google account info
  AuthController.googleCallback
)

router.post('/token', AuthController.validateCodeAndGenerateToken)

/* Email & password routes */
router.post('/login', AuthController.login)
router.post('/register', AuthController.register)
router.get('/verify-email', AuthController.verifyEmail)
router.post('/forgot-password', AuthController.forgotPassword)
router.post('/reset-password', AuthController.resetPassword)
router.post('/logout', AuthController.logout)

export default router
