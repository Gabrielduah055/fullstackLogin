import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodels.js';
import transporter from '../config/nodemailer.js';



export const register = async (req, res) => {
    const { name, email, password } = req.body;
    
    // Input validation
    if (!name || !email || !password) {
        return res.status(400).json({ 
            message: 'Please fill all the fields',
            success: false 
        });
    }

    try {
        // Check for existing user first
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                message: 'Email already exists',
                success: false
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = new userModel({ 
            name, 
            email, 
            password: hashedPassword 
        });

        // Save user to database
        await newUser.save();

        // Generate JWT token
        const token = jwt.sign({ 
            id: newUser._id 
        }, process.env.JWT_SECRET, { 
            expiresIn: '1d' 
        });

        // Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 1000 * 60 * 60 * 24 * 7,
        });


        //Sending email verification
        const mainOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Verify your email',
            text: `Please verify your email by clicking on the following link to verify your email: ${email}`,
        }

        await transporter.sendMail(mainOptions)

        return res.status(200).json({
            message: 'Registration successful',
            success: true,
            token
        });
    } catch (error) {
        return res.status(500).json({
            message: error.message || 'Internal server error',
            success: false
        });
    }
};



export const login = async (req, res) => {
    const {email, password} = req.body;

    if(!email || !password){
        return res.status(400).json({message:'Please fill all the fields', success:false});
    }

    try {
        //finding the user
        const user = await userModel.findOne({email});
        if(!user){
            return res.status(400).json({message:'User not found', success:false});
        }

        //checking if the password is correct
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if(!isPasswordCorrect){
            return res.status(400).json({message:'Incorrect password', success:false});
        }

        //creating a token
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn:'1d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 1000 * 60 * 60 * 24 * 7,
        })

        return res.status(200).json({message:'Login successful', success:true});

    }catch(error){
        return res.status(500).json({message:error.message, success:false});
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.status(200).json({message:'Logout successful', success:true});

    } catch (error) {
        return res.status(500).json({message:error.message, success:false});
    }
}


//sending the otp to the user
export const sendVerifyOtp = async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await userModel.findById(userId);
      

        if(user.isAccountVerified){
            return res.status(400).json({message:'Account already verified', success:false});
        }

        const otp = String(Math.floor(10000 + Math.random() * 900000))
        user.verifyOTP = otp;

        user.verifyOTPExpire = Date.now() + 24 *60 * 60 * 1000; // 24 hours

        await user.save();

        const mainOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${otp} please verify your account  `
        }

        await transporter.sendMail(mainOptions)

        res.status(200).json({message:'OTP sent successfully', success:true});


    } catch (error) {
        return res.status(500).json({message:error.message, success:false});
        
    }
}

export const verifyEmail = async (req, res) => {
    const {userId, otp} = req.body;


    try {
        const userId = req.user.id;
        //finding the user
        const user = await userModel.findById(userId);

        if(!user){
            return res.status(400).json({message:'User not found', success:false});
        }

        if(user.verifyOTP === '' || user.verifyOTP !== otp){
            return res.status(400).json({message:'Invalid OTP', success:false});
        }

        if(user.verifyOTPExpire < Date.now()){
            return res.status(400).json({message:'OTP expired', success:false});
        }

        user.isAccountVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpire = 0;


        await user.save();

        return res.status(200).json({message:'Account verified successfully', success:true});
        console.log(res.body)

    
    } catch (error) {
        return res.status(500).json({message:error.message, success:false});
        
    }

    
}

export const isAuthenticated = async (req, res) => {
    try {
        return res.status(200).json({message:'User is authenticated', success:true});
    } catch (error) {
        return res.status(500).json({message:error.message, success:false});
        
    }
}

//sending the password reset otp to the user
export const resentOTP = async (req, res) => {
    const {email} = req.body;

    if(!email){
        return res.status(400).json({message:'Email is required', success:false});
    }

    try {
        const user = await userModel.findOne({email});

        if(!user){
            return res.status(400).json({message:'User not found', success:false});
        }

        if(user.isAccountVerified){
            return res.status(400).json({message:'Account already verified', success:false});
        }

        const otp = String(Math.floor(10000 + Math.random() * 900000))
        user.resetOTP = otp;

        user.resetOTPExpire = Date.now() + 24 *60 * 60 * 1000; // 24 hours

        await user.save();

        const mainOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP is ${otp} please reset your password  `
        }

        await transporter.sendMail(mainOptions)

        res.status(200).json({message:'OTP sent successfully', success:true});

    } catch (error) {
        return res.status(500).json({message:error.message, success:false});
    }
}

//reset password
export const resetPassword = async (req, res) => {
    const {userId, otp, password} = req.body;

    if(!userId || !otp || !password){
        return res.status(400).json({message:'Please fill all the fields', success:false});
    }

    try {
        const userId = req.user.id;
        //finding the user
        const user = await userModel.findById(userId);

        if(!user){
            return res.status(400).json({message:'User not found', success:false});
        }

        if(user.resetOTP === '' || user.resetOTP !== otp){
            return res.status(400).json({message:'Invalid OTP', success:false});
        }

        if(user.resetOTPExpire < Date.now()){
            return res.status(400).json({message:'OTP expired', success:false});
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetOTP = '';
        user.resetOTPExpire = 0;

        await user.save();

        return res.status(200).json({message:'Password reset successfully', success:true});

    } catch (error) {
        return res.status(500).json({message:error.message, success:false});
        
    }
}
