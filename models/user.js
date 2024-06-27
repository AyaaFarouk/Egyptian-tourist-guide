/*const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const util = require('util')
const AsyncAsign = util.promisify(jwt.sign)
const lod = require('lodash')

const Schema = mongoose.Schema;

const UserSchema = new mongoose.Schema({
    userId:{
        type: "string"
    },
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

module.exports = user;*/

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const util = require('util');
const AsyncAsign = util.promisify(jwt.sign);
const lod = require('lodash');

const Schema = mongoose.Schema;

const UserSchema = new mongoose.Schema({
  userId: {
    type: String,
  },
  name: {
    type: String,
  },
  email: {
    type: String,
  },
  password: {
    type: String,
  },
  dateOfBirth: {
    type: Date,
  },
  adminRole: {
    type: Boolean,
  },
  verified: {
    type: Boolean,
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user',
  },
}, {
  toJSON: {
    transform: (doc, returnDoc) => lod.omit(returnDoc, ['password', '__v']),
  },
});

UserSchema.pre('save', function (next) {
  if (!this.userId) {
    this.userId = this._id.toString();
  }
  next();
});

const user = mongoose.model('user', UserSchema);

module.exports = user;