import { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import Config from '../config'

const JWT_SECRET = Config.JWT_SECRET
export const COOKIE_AUTH = 'auth_token'

export const verifyJWT = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies[COOKIE_AUTH]

  if (!token) {
    res.status(401).send('Unauthorized')
    return
  }

  jwt.verify(
    token,
    JWT_SECRET,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (err: any, decoded: Express.User | undefined) => {
      if (err) {
        return res.status(401).send('Invalid or expired token')
      }
      const { userId } = decoded as { userId: string }
      req.userId = userId
      next()
    }
  )
}
