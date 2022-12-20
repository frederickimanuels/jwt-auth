import Users from "../models/UserModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export const getUsers = async(req,res) => {
    try{
        const users = await Users.findAll({
            attributes:['id','name','email']
        });
        res.json(users);
    } catch(error){
        console.log(error);
    }
}

export const Register = async(req,res) => {
    const { name, email, password, confPassword } = req.body;
    if( !(name && email && password && confPassword) ) return res.status(400).json({msg: "name, email, password, and confirm password cannot be empty"});
    if( password !== confPassword ) return res.status(400).json({msg: "Password dan Confirm Password tidak cocok"});
    const salt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(password, salt);
    // Check Email Registered
    try {
        const user = await Users.findOne({
            where:{
                email: req.body.email,
            },
            attributes:['email']
        });
        if (user) return res.status(400).json({msg: "Email already registered"}); 
    }catch(error){
        console.log(error)
        return res.status(400).json({msg:"Failed to inquiry database"});
    }
    // Create User
    try {
        await Users.create({
            name: name,
            email: email,
            password: hashPassword
        });
        res.json({msg:"Register Berhasil"});
    }catch(error){
        console.log(error);
    }
}

export const Login = async(req,res) => {
    try{
        const user = await Users.findAll({
            where:{
                email: req.body.email,
            }
        });
        const match = await bcrypt.compare(req.body.password, user[0].password);
        if(!match) return res.status(400).json({msg: "Wrong Password"});
        const userId = user[0].id;
        const name = user[0].name;
        const email = user[0].email;
        const accessToken = jwt.sign({userId,name,email}, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: '15s'
        });
        const refreshToken = jwt.sign({userId,name,email}, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: '1d'
        });
        await Users.update({refresh_token: refreshToken},{
            where:{
                id: userId
            }
        })
        res.cookie('refreshToken',refreshToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 1 Day
            // secure: true // if https
        })
        res.json({ accessToken })
    }catch(error){
        res.status(404).json({msg:"Email tidak ditemukan"});
    }
}

export const Logout = async(req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) return res.sendStatus(204);
    const user = await Users.findAll({
        where:{
            refresh_token: refreshToken
        }
    });
    if(!user[0]) return res.sendStatus(204);
    const userId = user[0].id;
    await Users.update({refresh_token: null},{
        where:{
            id: userId
        }
    });
    res.clearCookie('refreshToken');
    return res.sendStatus(200);
}