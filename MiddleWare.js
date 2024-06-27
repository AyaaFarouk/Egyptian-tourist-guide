const express = require('express');
const router = express.Router();
const lodash = require('lodash');
const bcrypt = require('bcrypt');
const path = require('path');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const util = require('util');
const asyncSign = util.promisify(jwt.sign);
const asyncVerify = util.promisify(jwt.verify);
const user = require('./models/user');
const PasswordReset = require('./models/PasswordReset');
const UserVerification = require('./models/userverification');
require('dotenv').config();

const secretkey = "OAABB";
const AUTH_EMAIL= "egyptiantourguide2024@gmail.com"
const AUTH_PASS= "lmcz rkrn xlbg jbqe"

// nodemailer setup
let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: AUTH_EMAIL,
        pass: AUTH_PASS,
    },
});

const LoginUser = async (req, res) => {
    let { email, password } = req.body;
    email = email.trim();

    if (email === '' || password === '') {
        return res.json({
            status: 'FAILED',
            message: 'Empty credentials supplied'
        });
    } else {
        try {
            // Check if user exists
            const data = await user.find({ email });

            if (data.length) {
                // User exists
                if (!data[0].verified) {
                    return res.json({
                        status: 'FAILED',
                        message: 'Email hasn\'t been verified yet. Check your inbox.',
                        data: data
                    });
                } else {
                    const hashedPassword = data[0].password;
                    const result = await bcrypt.compare(password, hashedPassword);
                    if (result) {
                        // Password match
                        // Update adminRole to true
                        await user.updateOne({ email }, { adminRole: true });
                        // Fetch the updated user
                        const updatedUser = await user.findOne({ email });

                        const token = jwt.sign(
                            { userId: updatedUser._id, adminRole: updatedUser.adminRole },
                            secretkey,
                            { expiresIn: '1h' }
                        );

                        // Set the token in a cookie
                        res.cookie('token', token, { httpOnly: true, secure: true, maxAge: 3600000 }); // 1 hour expiration

                        return res.json({
                            status: 'SUCCESS',
                            message: 'Signin successful',
                            token: token,
                            data: updatedUser
                        });
                    } else {
                        return res.json({
                            status: 'FAILED',
                            message: 'Invalid password entered!'
                        });
                    }
                }
            } else {
                return res.json({
                    status: 'FAILED',
                    message: 'Invalid credentials entered!'
                });
            }
        } catch (err) {
            return res.json({
                status: 'FAILED',
                message: 'An error occurred while processing the login request'
            });
        }
    }
};

const AuthorizeUser = async (req, res, next) => {
    // Retrieve the token from the cookie
    const token = req.cookies.token;
    console.log("Login: (in Cookies) "+ token)
    if (!token) return res.status(400).send('Access denied.');

    try {
        const decoded = await asyncVerify(token, secretkey);
        if (!decoded.adminRole) return res.status(400).send('Not Authorized');
        next();
    } catch (error) {
        return res.status(401).send('Invalid token');
    }
};

const Logout = async (req, res) => {
    // Retrieve the token from the Authorization header
    const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];
    console.log("LogOut (in header): "+token)
    if (!token) return res.status(400).send('Access denied. No token provided.');

    try {
        const decoded = await asyncVerify(token, secretkey);

        // Check if the token is valid
        if (!decoded) {
            return res.status(401).send('Invalid token');
        }

        // Validate the token matches the one in cookies
        const cookieToken = req.cookies.token;
        if (token !== cookieToken) {
            return res.status(401).send('Token mismatch');
        }

        // Remove the token from the client-side storage
        res.clearCookie('token');
        await user.updateOne({ _id: decoded.userId }, { adminRole: false });

        // Retrieve the updated user information
        const updatedUser = await user.findById(decoded.userId);

        // Respond with the updated adminRole value
        return res.status(200).json({
            status: 'SUCCESS',
            message: 'Logout successful',
            adminRole: updatedUser.adminRole
        });
    } catch (error) {
        return res.status(401).send('Invalid token');
    }
};

module.exports = {
    AuthorizeUser,
    Logout,
    LoginUser,
};
