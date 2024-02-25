const mongoose = require('mongoose')
const Schema = mongoose.Schema;

const UserVerificationSchema = new mongoose.Schema({
    userId:{
        type: "string",
    },
    email:{
        type: "string",
        unique: true
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

const UserVerification = mongoose.model('UserVerification', UserVerificationSchema)

module.exports = UserVerification;