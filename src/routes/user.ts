import express from 'express'
import User from '../models/User'
import { COOKIE_AUTH, verifyJWT } from '../middlewares/auth'
import Config from '../config'

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
      isVerified: user.isVerified,
      profilePicture: user.profilePicture
    })
    return
  } catch (error) {
    console.error('Error fetching user data:', error)
    res.status(500).json({ message: 'Server error' })
    return
  }
})

router.delete('/delete-account', verifyJWT, async (req, res) => {
  const userId = req.userId

  try {
    const deletedUser = await User.findByIdAndDelete(userId)
    if (!deletedUser) {
      res
        .status(404)
        .json({ code: 'USER_NOT_FOUND', message: 'User not found' })
      return
    }
    res.clearCookie(COOKIE_AUTH, {
      httpOnly: true,
      secure: Config.NODE_ENV === 'production',
      sameSite: Config.NODE_ENV === 'production' ? 'none' : 'strict'
    })
    res.status(200).json({
      message: 'User has been deleted and logged out'
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error deleting user' })
  }
})

export default router
