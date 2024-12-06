import User from '../models/User'

export const cleanUpExpiredTokens = async () => {
  const now = new Date()
  await User.updateMany(
    {
      verificationTokenExpiresAt: { $lt: now }
    },
    {
      $unset: { verificationToken: '', verificationTokenExpiresAt: '' }
    }
  )
}

setInterval(cleanUpExpiredTokens, 60 * 60 * 1000) // cleanup every 1h
