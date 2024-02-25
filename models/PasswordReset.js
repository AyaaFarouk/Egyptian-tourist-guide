const mongoose = require('mongoose')
const Schema = mongoose.Schema;

const PasswordResetSchema = new mongoose.Schema({
    userId:{
        type: "string",
    },
    email:{
        type: "string",
    },
    otp:{
        type: "string",
    },
    createdAt:{
        type: "Date",
    },
    expiredAt:{
        type: "Date",
    },
});

const PasswordReset = mongoose.model('PasswordReset', PasswordResetSchema)

module.exports = PasswordReset;