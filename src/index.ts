import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import routes from './routes'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
app.use(express.json())
app.use(
  cors({
    origin: 'http://localhost:3000'
  })
)

const port = process.env.PORT || 5000
const MONGO_ATLAS_URI = process.env.MONGO_ATLAS_CONNECTION_STRING || ''

mongoose
  .connect(MONGO_ATLAS_URI, {})
  .then(() => {
    console.log('Mondodb connection has been established')
    app.use('/api', routes)
    app.listen(port, () => console.log(`Server running on port ${port}`))
  })
  .catch((err) => {
    console.log(
      'Error while trying to establish connection to mongodb',
      err.message
    )
  })
