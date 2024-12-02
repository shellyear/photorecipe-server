import dotenv from 'dotenv'

dotenv.config()

const Config = {
  PORT: process.env.PORT || 5000,
  API_BASE_URL: process.env.API_BASE_URL || 'http://localhost:5000',
  FRONT_END_BASE_URL: process.env.FRONT_END_BASE_URL || 'http://localhost:3000',
  MONGO_ATLAS_CONNECTION_STRING:
    process.env.MONGO_ATLAS_CONNECTION_STRING ||
    'mongodb_atlas_connection_string',
  JWT_SECRET: process.env.JWT_SECRET || 'your_jwt_secret',
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || 'google_client_id',
  GOOGLE_CLIENT_SECRET:
    process.env.GOOGLE_CLIENT_SECRET || 'google_client_secret',
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || 'open_ai_api_key'
}

export default Config
