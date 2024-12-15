import { Document, Schema, model } from 'mongoose'

export interface IUser extends Document {
  _id: string
  email: string
  password?: string
  googleId?: string
  name?: string
  isVerified: boolean
  verificationToken?: string
  verificationTokenExpiresAt?: Date
}

const userSchema = new Schema(
  {
    email: { type: String, unique: true, required: true },
    password: { type: String },
    googleId: { type: String },
    name: { type: String },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String },
    verificationTokenExpiresAt: { type: Date }
  },
  { timestamps: true }
)

export default model<IUser>('User', userSchema)
