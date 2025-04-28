import userModel from "../models/usermodels.js";

export const getUserData = async (req, res) => {
    try {
        const userId= req.user.id;
        //finding the user
        const user = await userModel.findById(userId);
        if(!user){
            return res.status(400).json({message:'User not found', success:false});
        }
        
        res.json({
            message:'User data fetched successfully',
            success:true,
            user:{
                name:user.name,
                isAccountVerified:user.isAccountVerified,
            }
        })

        return res.status(200).json({message:'User data fetched successfully', success:true, user});

    } catch (error) {
        return res.status(500).json({message:error.message, success:false});
    }
}