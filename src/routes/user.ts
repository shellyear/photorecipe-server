import express from 'express'
import User from '../models/User'
import { verifyJWT } from '../middlewares/auth'

const router = express.Router()

router.get('/profile', verifyJWT, async (req, res) => {
  try {
    const user = await User.findById(req.userId)

    if (!user) {
      res
        .status(404)
        .json({ code: 'USER_NOT_FOUND', message: 'User not found' })
      return
    }

    res.status(200).json({
      email: user.email,
      name: user.name,
      isVerified: user.isVerified
    })
    return
  } catch (error) {
    console.error('Error fetching user data:', error)
    res.status(500).json({ message: 'Server error' })
    return
  }
})

export default router
