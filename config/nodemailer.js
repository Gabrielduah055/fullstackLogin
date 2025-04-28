import nodemailer from 'nodemailer';


const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USERNAME,
        pass: process.env.SMTP_PASSWORD,
    },
})

transporter.verify((error) => {
    if (error) {
        console.error('SMTP verification failed:', error);
    } else {
        console.log('SMTP configured correctly');
    }
});

export default transporter;