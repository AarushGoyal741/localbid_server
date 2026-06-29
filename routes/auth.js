import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/db.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
};

const generateToken = (id, accountType) => {
    return jwt.sign(
        { id, accountType },
        process.env.JWT_SECRET,
        {
            expiresIn: '30d'
        }
    );
};

// ===================== REGISTER =====================

router.post('/register', async (req, res) => {
    try {
        const { name, email, password, accountType } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please provide all required fields"
            });
        }

        const userExists = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );

        if (userExists.rows.length > 0) {
            return res.status(400).json({
                success: false,
                message: "User already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await pool.query(
            `INSERT INTO users
            (name, email, password, account_type)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, email, account_type`,
            [name, email, hashedPassword, accountType]
        );

        const token = generateToken(
            newUser.rows[0].id,
            newUser.rows[0].account_type
        );

        res.cookie('token', token, cookieOptions);

        return res.status(201).json({
            success: true,
            message: "Registration successful",
            user: {
                id: newUser.rows[0].id,
                name: newUser.rows[0].name,
                email: newUser.rows[0].email,
                accountType: newUser.rows[0].account_type
            }
        });

    } catch (error) {
        console.error("Register Error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

// ===================== LOGIN =====================

router.post('/login', async (req, res) => {
    try {

        const { email, password, accountType } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please fill all the fields"
            });
        }

        const user = await pool.query(
            `SELECT
                id,
                name,
                email,
                password,
                account_type
            FROM users
            WHERE email = $1
            AND account_type = $2`,
            [email, accountType]
        );

        if (user.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        const userData = user.rows[0];

        const isMatch = await bcrypt.compare(
            password,
            userData.password
        );

        if (!isMatch) {
            return res.status(400).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        const token = generateToken(
            userData.id,
            userData.account_type
        );

        res.cookie("token", token, cookieOptions);

        return res.status(200).json({
            success: true,
            message: "Login successful",
            user: {
                id: userData.id,
                name: userData.name,
                email: userData.email,
                accountType: userData.account_type
            }
        });

    } catch (error) {
        console.error("Login Error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});

// ===================== CURRENT USER =====================

router.get('/me', protect, async (req, res) => {
    try {

        return res.status(200).json({
            success: true,
            user: {
                id: req.user.id,
                name: req.user.name,
                email: req.user.email,
                accountType: req.user.account_type
            }
        });

    } catch (error) {

        console.error("User Fetch Error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });

    }
});

// ===================== LOGOUT =====================

router.post('/logout', async (req, res) => {
    try {

        res.cookie('token', '', {
            ...cookieOptions,
            maxAge: 1
        });

        return res.status(200).json({
            success: true,
            message: "Logged out successfully"
        });

    } catch (error) {

        console.error("Logout Error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });

    }
});

export default router;