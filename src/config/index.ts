import dotenv from 'dotenv'

const NODE_ENV = process.env.NODE_ENV || 'development'
const isProd = NODE_ENV === 'production'

const envFile = `.env.${NODE_ENV}`
dotenv.config({ path: envFile })

const PORT = process.env.PORT || 5000

const Config = {
  NODE_ENV,
  PORT,
  API_BASE_URL: isProd
    ? process.env.API_BASE_URL
    : `${process.env.API_BASE_URL}:${PORT}`,
  FRONT_END_BASE_URL: process.env.FRONT_END_BASE_URL || 'http://localhost:3000',
  MONGO_ATLAS_CONNECTION_STRING:
    process.env.MONGO_ATLAS_CONNECTION_STRING ||
    'mongodb_atlas_connection_string',
  JWT_SECRET: process.env.JWT_SECRET || 'your_jwt_secret',
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || 'google_client_id',
  GOOGLE_CLIENT_SECRET:
    process.env.GOOGLE_CLIENT_SECRET || 'google_client_secret',
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || 'open_ai_api_key',
  SMTP_USER: process.env.SMTP_USER || 'smpt_user@gmail.com',
  SMTP_PASS: process.env.SMTP_PASS || 'googleAppPassword'
}
console.log({ NODE_ENV })
export default Config
