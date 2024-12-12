import express from 'express'
import authRouter from './auth'
import recipeRouter from './recipe'
import userRouter from './user'

const router = express.Router()

router.use('/user', userRouter)
router.use('/auth', authRouter)
router.use('/recipe', recipeRouter)

export default router
