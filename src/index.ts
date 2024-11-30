import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import routes from './routes'
import Config from './config'

const app = express()
app.use(express.json())
app.use(
  cors({
    origin: 'http://localhost:3000'
  })
)

mongoose
  .connect(Config.MONGO_ATLAS_CONNECTION_STRING, {})
  .then(() => {
    console.log('Mondodb connection has been established')
    app.use('/api', routes)
    app.listen(Config.PORT, () =>
      console.log(`Server running on port ${Config.PORT}`)
    )
  })
  .catch((err) => {
    console.log(
      'Error while trying to establish connection to mongodb',
      err.message
    )
  })
