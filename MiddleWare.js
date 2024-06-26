const jwt = require('jsonwebtoken')
const util = require('util')
const AsyncAsign = util.promisify(jwt.sign)


const secretkey = "OAABB"
const Authorieuser = async (req,res,next) =>
{
    const { authorization: token } = req.headers
    if (!token) return res.status(400).send("access denied..")

    const decoded = await asyncverify(token, secrtkey)
    if (!decoded.adminRole) return res.status(400).send("Not Authorized")
     next();
}