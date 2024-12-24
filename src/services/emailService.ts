import nodemailer from 'nodemailer'
import Config from '../config'

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: Config.SMTP_USER,
    pass: Config.SMTP_PASS
  }
})

const sendPasswordResetEmail = async (email: string, resetToken: string) => {
  const resetLink = `${Config.FRONT_END_BASE_URL}/auth/reset-password?token=${resetToken}`

  const mailOptions = {
    from: 'your-email@gmail.com',
    to: email,
    subject: 'Password Reset Request',
    html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
  }

  await transporter.sendMail(mailOptions)
}

const sendVerificationEmail = async (
  email: string,
  verificationToken: string
) => {
  const verificationUrl = `${Config.FRONT_END_BASE_URL}/verify-email?token=${verificationToken}`
  const mailOptions = {
    from: Config.SMTP_USER,
    to: email,
    subject: 'Verify your email',
    html: `
        <p>Hello,</p>
        <p>Thank you for registering with us. Please click the link below to verify your email address:</p>
        <p><a href="${verificationUrl}" target="_blank">Click here to verify your email</a></p>
        <p><b>Once your email is verified, you will be automatically logged into your account.</b></p>
        <p>If you did not register with us, please ignore this email.</p>
      `
  }
  await transporter.sendMail(mailOptions)
}

const EmailService = {
  sendPasswordResetEmail,
  sendVerificationEmail
}

export default EmailService
