import jwt from 'jsonwebtoken';
import pool from '../config/db.js';

export const protect = async (req, res, next) => {
    try {

        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Not authorised. No token provided."
            });
        }

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const user = await pool.query(
            `SELECT
                id,
                name,
                email,
                account_type
            FROM users
            WHERE id = $1`,
            [decoded.id]
        );

        if (user.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: "User not found."
            });
        }

        req.user = user.rows[0];

        next();

    } catch (error) {

        console.error("Authentication Error:", error);

        return res.status(401).json({
            success: false,
            message: "Not authorised. Invalid or expired token."
        });

    }
};