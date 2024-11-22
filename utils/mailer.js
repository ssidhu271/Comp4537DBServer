//ChatGPT helped with the creation of this file

const nodemailer = require('nodemailer');
const MESSAGE = require('../lang/messages/en/user');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    logger: true,
    debug: true,
});

// Send a password reset code
const sendResetCode = async (email, resetCode) => {
    const mailOptions = {
        from: `"${MESSAGE.email.fromName}" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: MESSAGE.messages.resetCodeEmailSubject,
        text: MESSAGE.messages.resetCodeEmailBody(resetCode),
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent: ', info.response);
    } catch (error) {
        console.error('Error sending email: ', error);
        throw new Error(MESSAGE.errors.emailSendFailure);
    }
};

module.exports = { sendResetCode };
