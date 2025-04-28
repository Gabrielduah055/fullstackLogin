import express from 'express';
import cors from 'cors';
import 'dotenv/config'
import connectDB from './config/mongodb.js';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';


const app = express();
const port = process.env.PORT || 5000;


connectDB()

app.use(express.json());
app.use(cors({credentials:true}));
app.use(cookieParser())


//api endpoints
app.use('/api/auth', authRoutes)
app.use('/api/user', userRoutes)
app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
