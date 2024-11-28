import express from 'express'
import authRouter from './auth'
import recipeRouter from './recipe'

const router = express.Router()

router.use('/auth', authRouter)
router.use('/recipe', recipeRouter)

export default router
