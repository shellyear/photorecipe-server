import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import routes from './routes'
import Config from './config'
import cookieParser from 'cookie-parser'
import { cleanUpExpiredTokens } from './jobs/cleanupJob'

const app = express()
app.use(express.json())
app.use(
  cors({
    origin: Config.FRONT_END_BASE_URL
  })
)
app.use(cookieParser())

mongoose
  .connect(Config.MONGO_ATLAS_CONNECTION_STRING, {})
  .then(() => {
    console.log('Mondodb connection has been established')
    app.use('/api', routes)
    app.listen(Config.PORT, () =>
      console.log(`Server running on port ${Config.PORT}`)
    )
    cleanUpExpiredTokens()
  })
  .catch((err) => {
    console.log(
      'Error while trying to establish connection to mongodb',
      err.message
    )
  })
