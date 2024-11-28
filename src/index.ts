import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import routes from './routes'

const app = express()
app.use(express.json())
app.use(
  cors({
    origin: 'http://localhost:3000'
  })
)

const port = process.env.PORT || 5000

app.use('/api', routes)
app.listen(port, () => console.log(`Server running on port ${port}`))

mongoose
  .connect('mongodb://localhost:27017/your_db_name', {})
  .then(() => {
    console.log('Mondodb connection has been established')

  })
  .catch((err) => {
    console.log(
      'Error while trying to establish connection to mongodb',
      err.message
    )
  })
