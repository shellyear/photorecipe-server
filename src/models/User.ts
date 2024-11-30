import { Document, Schema, model } from 'mongoose'

export interface IUser extends Document {
  email: string
  password?: string
  googleId?: string
  name?: string
}

const userSchema = new Schema({
  email: { type: String, unique: true },
  password: { type: String },
  googleId: { type: String },
  name: { type: String }
}, { timestamps: true })

export default model<IUser>('User', userSchema)
