import jwt from "jsonwebtoken";
import { db } from "./db.js";

export const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, async (err, user) => {
        if (err) return res.sendStatus(403);

        req.user = {
            ...user,
            ...(await db.get("SELECT id FROM users WHERE uuid = ?", user.uuid))
        };

        next();
    });
};

export const getIP = (req, res, next) => {
    req.clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    next();
};