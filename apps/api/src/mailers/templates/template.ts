export const verifyEmailTemplate = (
  url: string,
  brandColor: string = '#2563EB',
) => ({
  subject: 'Confirm your Gain-O-Meter account',
  text: `Please verify your email address by clicking the following link: ${url}`,
  html: `
  <html>
  <head>
    <style>
      body, html {
        margin: 0;
        padding: 0;
        font-family: 'Helvetica Neue', Arial, sans-serif;
        background-color: #fdf2f8;
        color: #4a5568;
      }
      .container {
        max-width: 600px;
        margin: 20px auto;
        background-color: #ffffff;
        border-radius: 16px;
        box-shadow: 0px 4px 12px rgba(244, 114, 182, 0.1);
        overflow: hidden;
      }
      .header {
        background: linear-gradient(135deg, #ec4899 0%, #db2777 100%);
        padding: 30px 20px;
        text-align: center;
      }
      .logo-container {
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto;
        gap: 15px;
      }
      .logo {
        font-size: 28px;
        margin: 0 auto;
        font-weight: 700;
        color: #ffffff;
        text-transform: uppercase;
        letter-spacing: 1px;
      }
      .content {
        padding: 20px 20px;
        text-align: center;
        background-color: #fdf2f8;
      }
      .content h1 {
        font-size: 24px;
        color: #be185d;
        margin-bottom: 20px;
        font-weight: 600;
      }
      .content p {
        font-size: 16px;
        line-height: 1.5;
        color: #64748b;
        margin: 0 0 24px;
      }
      .button {
        display: inline-block;
        padding: 16px 32px;
        font-size: 16px;
        font-weight: 600;
        background-color: #ec4899;
        color: #ffffff !important;
        border-radius: 8px;
        text-decoration: none;
        transition: background-color 0.3s ease;
      }
      .button:hover {
        background-color: #db2777;
      }
      .footer {
        background-color: #fdf2f8;
        font-size: 14px;
        color: #94a3b8;
        text-align: center;
        padding: 0px 10px 20px 10px;
        border-top: 1px solid #fbcfe8;
      }
      .footer p {
        margin: 0;
        line-height: 1.5;
      }
      .divider {
        height: 3px;
        background: linear-gradient(90deg, #ec4899 0%, #db2777 100%);
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="logo-container">
          <div class="logo">Gain-O-Meter</div>
        </div>
      </div>
      <div class="divider"></div>
      <div class="content">
        <h1>Confirm Your Email Address</h1>
        <p>Thank you for signing up! Please confirm your account by clicking the button below.</p>
        <a href="${url}" class="button">Confirm Account</a>
      </div>
      <div class="footer">
        <p style="margin-top: 24px; font-size: 14px; color: #94a3b8;">If you did not create this account, please disregard this email.</p>
        <p>If you have any questions, feel free to reply to this email<br>or contact our support team.</p>
      </div>
    </div>
  </body>
  </html>
    `,
})

export const passwordResetTemplate = (
  url: string,
  brandColor: string = '#2563EB',
) => ({
  subject: 'Reset Your Password',
  text: `To reset your password, please click the following link: ${url}`,
  html: `
  <html>
  <head>
    <style>
      body, html {
        margin: 0;
        padding: 0;
        font-family: 'Helvetica Neue', Arial, sans-serif;
        background-color: #fdf2f8;
        color: #4a5568;
      }
      .container {
        max-width: 600px;
        margin: 20px auto;
        background-color: #ffffff;
        border-radius: 16px;
        box-shadow: 0px 4px 12px rgba(244, 114, 182, 0.1);
        overflow: hidden;
      }
      .header {
        background: linear-gradient(135deg, #ec4899 0%, #db2777 100%);
        padding: 30px 20px;
        text-align: center;
      }
      .logo-container {
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto;
        gap: 15px;
      }
      .logo {
        font-size: 28px;
        margin: 0 auto;
        font-weight: 700;
        color: #ffffff;
        text-transform: uppercase;
        letter-spacing: 1px;
      }
      .content {
        padding: 20px 20px;
        text-align: center;
        background-color: #fdf2f8;
      }
      .content h1 {
        font-size: 24px;
        color: #be185d;
        margin-bottom: 20px;
        font-weight: 600;
      }
      .content p {
        font-size: 16px;
        line-height: 1.5;
        color: #64748b;
        margin: 0 0 24px;
      }
      .button {
        display: inline-block;
        padding: 16px 32px;
        font-size: 16px;
        font-weight: 600;
        background-color: #ec4899;
        color: #ffffff !important;
        border-radius: 8px;
        text-decoration: none;
        transition: background-color 0.3s ease;
      }
      .button:hover {
        background-color: #db2777;
      }
      .footer {
        background-color: #fdf2f8;
        font-size: 14px;
        color: #94a3b8;
        text-align: center;
        padding: 0px 10px 20px 10px;
        border-top: 1px solid #fbcfe8;
      }
      .footer p {
        margin: 0;
        line-height: 1.5;
      }
      .divider {
        height: 3px;
        background: linear-gradient(90deg, #ec4899 0%, #db2777 100%);
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="logo-container">
          <div class="logo">Gain-O-Meter</div>
        </div>
      </div>
      <div class="divider"></div>
      <div class="content">
        <h1>Reset Your Password</h1>
        <p>We received a request to reset your password. Click the button below to proceed with resetting your password.</p>
        <a href="${url}" class="button">Reset Password</a>
      </div>
      <div class="footer">
        <p style="margin-top: 24px; font-size: 14px; color: #94a3b8;">If you did not request a password reset, you can safely ignore this email.</p>
        <p>If you have any questions, feel free to reply to this email<br>or contact our support team.</p>
      </div>
    </div>
  </body>
  </html>
    `,
})
