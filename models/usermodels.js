import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    verifyOTP: {
        type: String,
        default:''
    },
    verifyOTPExpire: {
        type:Number,
        default:0
    },
    isAccountVerified: {
        type: Boolean,
        default: false,
    },
    resetOTP: {
        type: String,
        default:''
    },
    resetOTPExpire: {
        type:Number,
        default:0
    }
})

const userModel =mongoose.model.user ||  mongoose.model('user', userSchema);

export default userModel;