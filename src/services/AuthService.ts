import crypto from 'crypto'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import User, { IUser } from '../models/User'
import Config from '../config'

const JWT_SECRET = Config.JWT_SECRET

const generateToken = () => {
  return crypto.randomBytes(32).toString('hex')
}

const generateJWT = (userId: string, expiresIn: string = '7d') => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn })
}

const encryptString = async (
  str: string,
  rounds: number = 10
): Promise<string> => {
  const salt = await bcrypt.genSalt(rounds)
  const hashedString = await bcrypt.hash(str, salt)
  return hashedString
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
  const hashedPassword = await encryptString(password, 10)
  const verificationToken = generateToken()

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
  generateToken,
  generateJWT,
  encryptString,
  generateTemporaryCode,
  createUser,
  authenticateUser,
  verifyEmail
}

export default AuthService
