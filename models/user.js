const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const util = require('util')
const AsyncAsign = util.promisify(jwt.sign)
const lod = require('lodash')

const Schema = mongoose.Schema;

const UserSchema = new mongoose.Schema({
    name:{
        type: "string",
    },
    email:{
        type: "string",
    },
    password:{
        type: "string",
    },
    dateOfBirth:{
        type: "Date",
    },
    verified:{
        type: "Boolean",
    },
    role:{
        type: "string",
        enum:['admin','user'],
        default: 'user'
    }
}
    ,{
        toJSON:{
            transform: (doc,returnDoc) => lod.omit(returnDoc,['password','__v'])
        }
    }
);


const user = mongoose.model('user', UserSchema)

module.exports = user;