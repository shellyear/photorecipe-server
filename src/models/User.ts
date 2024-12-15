import { Document, Schema, model } from 'mongoose'

export interface IUser extends Document {
  _id: string
  email: string
  password?: string
  googleId?: string
  name?: string
  isVerified: boolean
  profilePicture?: string
  verificationToken?: string
  verificationTokenExpiresAt?: Date
  resetPasswordToken?: string
  resetPasswordExpires?: Date
}

const userSchema = new Schema(
  {
    email: { type: String, unique: true, required: true },
    password: { type: String },
    googleId: { type: String },
    name: { type: String },
    profilePicture: { type: String },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String },
    verificationTokenExpiresAt: { type: Date },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date }
  },
  { timestamps: true }
)

export default model<IUser>('User', userSchema)
