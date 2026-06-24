import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/db.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

const cookieOptions={
    httpOnly: true,
    secure: process.env.NODE_ENV==='production',
    sameSite: 'Strict',
    maxAge: 30 * 24 * 60 * 60 * 1000   //30 days
}

const generateToken = (id)=> {
    return jwt.sign({id}, process.env.JWT_SECRET,{
        expiresIn: '30d'
    });
}

router.post('/register',async(req,res)=>{try{
    const {name , email , password} = req.body;
    if (!name || !email || !password){
        return res.status(400).json({message: "Please provide all required fields"});
    }

    const userExists = await pool.query('SELECT * FROM users WHERE email = $1',[email]);

    if (userExists.rows.length>0){
        return res.status(400).json({message: "user already exists"});
    }

    const hashedPassword = await bcrypt.hash(password,10);

    const newUser = await pool.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',[name, email, hashedPassword]);

    const token = generateToken(newUser.rows[0].id)

    res.cookie('token', token, cookieOptions);

    return res.status(201).json({user : newUser.rows[0]});
    }catch(error){
        console.error("register error: ",error);
        return res.status(500).json({message: "Internal server error"});
    }
})


router.post('/login',async(req,res)=>{try{
    const {email, password} = req.body;
    if(!email || !password){
        return req.status(400).json({message : "please fill all the fields"});
    }

    const user = await pool.query("SELECT * FROM users where email = $1 ",[email]);

    if (user.rows.length === 0){
        return res.status(400).json({message :"invalid credentials"});
    }

    const userData= user.rows[0];

    const isMatch = await bcrypt.compare(password, userData.password);

    if (!isMatch){
        return res.status(400).json({message : "invalid credentials"});
    }

    const token = generateToken(userData.id);
    res.cookie("token",token,cookieOptions);
    res.json({user: userData.id, name:userData.name, email:userData.email});
    }catch(error){
        console.error("login error: ",error);
        return res.status(500).json({message: "Internal server error"});
}})

router.get('/me',protect, async(req,res)=>{try{
    res.json(req.user);
    }catch(error){
        console.error("Data fetch error: ",error);
        return res.status(500).json({message: "Internal server error"});
}})

router.post('/logout', async(req,res)=>{try{
    res.cookie('token', '', {...cookieOptions,maxAge: 1});
    res.json({message: "Logged out successfully"});
    }catch(error){
        console.error("logout error: ",error);
        return res.status(500).json({message: "Internal server error"});
}})

export default router;