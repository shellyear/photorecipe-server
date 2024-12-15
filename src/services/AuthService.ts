import crypto from 'crypto'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import User, { IUser } from '../models/User'
import nodemailer from 'nodemailer'
import Config from '../config'

const JWT_SECRET = Config.JWT_SECRET
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: Config.SMTP_USER,
    pass: Config.SMTP_PASS
  }
})

const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex')
}

const generateJWT = (userId: string, expiresIn: string = '7d') => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn })
}

const sendVerificationEmail = async (
  email: string,
  verificationToken: string
) => {
  const verificationUrl = `${Config.FRONT_END_BASE_URL}/verify-email?token=${verificationToken}`
  const mailOptions = {
    from: Config.SMTP_USER,
    to: email,
    subject: 'Verify your email',
    html: `
      <p>Hello,</p>
      <p>Thank you for registering with us. Please click the link below to verify your email address:</p>
      <p><a href="${verificationUrl}" target="_blank">Click here to verify your email</a></p>
      <p><b>Once your email is verified, you will be automatically logged into your account.</b></p>
      <p>If you did not register with us, please ignore this email.</p>
    `
  }
  await transporter.sendMail(mailOptions)
}

const createUser = async (
  email: string,
  password: string
): Promise<
  IUser & {
    verificationToken: string
    verificationTokenExpiresAt: Date
  }
> => {
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)
  const verificationToken = generateVerificationToken()

  const user = new User({
    email,
    password: hashedPassword,
    verificationToken,
    isVerified: false,
    verificationTokenExpiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000) // 1 hour
  }) as IUser & {
    verificationToken: string
    verificationTokenExpiresAt: Date
  }

  await user.save()
  return user
}

const authenticateUser = async (email: string, password: string) => {
  const user = (await User.findOne({ email })) as IUser
  if (!user || !user.password) return null
  const validPassword = await bcrypt.compare(password, user.password)
  return validPassword ? user : null
}

const verifyEmail = async (
  verificationToken: string
): Promise<IUser | null> => {
  const user = await User.findOne<IUser>({ verificationToken })

  if (
    !user ||
    (user.verificationTokenExpiresAt &&
      user.verificationTokenExpiresAt < new Date())
  ) {
    return null
  }

  user.isVerified = true
  user.verificationToken = undefined
  user.verificationTokenExpiresAt = undefined
  await user.save()
  return user
}

const generateTemporaryCode = () => {
  return crypto.randomBytes(16).toString('hex')
}

const AuthService = {
  generateVerificationToken,
  generateJWT,
  sendVerificationEmail,
  generateTemporaryCode,
  createUser,
  authenticateUser,
  verifyEmail
}

export default AuthService
