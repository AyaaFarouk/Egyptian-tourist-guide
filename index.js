const express = require('express')
const app = express()
const port =  process.env.PORT;
//const port =  5000;
//to connect frontend
const cors = require('cors')

//Connect to the database
require('./config/db')



// create user collection
const UserRouter = require('./api/user')
app.use(cors())
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/user',UserRouter)

//------------------------------------------------------------------------------------------------------------------------------------
// mongodb user model
const user = require('./models/user');

// mongodb user verification  model
const UserVerification = require('./models/userverification');

//password handler
const bcrypt = require('bcrypt');

//path for static verified page 
const path = require("path")

// mongodb PasswordReset model
const PasswordReset = require('./models/PasswordReset');

//email handler 
const nodemailer=require("nodemailer")
//env variables
require("dotenv").config()

const jwt = require('jsonwebtoken')
const util = require('util')
const AsyncAsign = util.promisify(jwt.sign)

//nodemailer stuff
let transporter = nodemailer.createTransport({
    service:"gmail",
    auth:{
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASS,
    },
});

//testing success
transporter.verify((error,success) => {
    if(error){
        console.log(error)
    }else{
        console.log("Ready for messages");
        console.log(success)
    }
});
//unique string
const { error } = require('console');

//password reset stuff
app.post("/user/forgetPassword", (req,res)=>{
    const {email}=req.body;
    if(!email)
    {
        res.json({
            status: "FAILED",
            message: "An email is required.",
        });
    }

//check if email exists
user
    .find({email})
    .then((data) => {
        if(data.length){
            //user exists
           //console.log(data , data.length , email)
            //check if user is verified
            if(!data[0].verified){
                res.json({
                    status: "FAILED",
                    message: "Email hasn't been verified yet. check your inbox",
                });
            }else{
                //proceed with email to reset password
                sendResetEmail(data[0],res);
            }

        }else{
            res.json({
                status: "FAILED",
                message: "No account with the supplied email exists!",
            });
        }
    })

    .catch(error => {
        console.log(error);
        res.json({
            status: "FAILED",
            message: "An error occurred while checking for existing user",
        });
    })
})

//generate OTP
const generateOTP = () => {
    try{
        return(otp= `${Math.floor(1000 + Math.random()*9000)}`);
    } catch(error){
        throw error ;
    }
};
const generate = generateOTP();

//send password reset email
const sendResetEmail = ({_id,email},res) => {

    //first, we clear all existing reset records
    PasswordReset
                .deleteMany({userId:_id})
                .then(result => {
                    //reset records deleted successfully
                    //Now we send the email
                    //mail options
                    const mailOptions = {
                        from: process.env.AUTH_EMAIL,
                        to: email,
                        subject: "Password Reset",
                        html: `<p>We heard that you lost the password.</p> <p>Don't worry, use the code below to reset it.</p> <p style="color:tomato; font-size:25px; letter-spacing:2px;"><b>${generate}</b></p><p>This code <b>expires in 1 hour(s)</b>.</p>`,
                    };
                    

                    //hash the reset string
                    const saltRounds = 10;
                    bcrypt
                    .hash(generate, saltRounds)
                    .then(hashedOTP => {
                        //set values in password reset collection
                        const newPasswordReset = new PasswordReset({
                            email,
                            userId: _id,
                            otp: hashedOTP,
                            createdAt: Date.now(),
                            expiredAt: Date.now() + 3600000
                        });

                        newPasswordReset
                        .save()
                        .then(() => {
                            transporter
                            .sendMail(mailOptions)
                            .then(()=>{
                                  //reset email sent and password reset record saved
                                  res.json({
                                    status: "PENDING",
                                    message: "Password reset email sent",
                                });
                            })
                            .catch(error => {
                                console.log(error);
                                res.json({
                                    status: "FAILED",
                                    message: "Password reset email failed",
                                });
    
                            })
                        })
                        .catch(error => {
                            console.log(error);
                            res.json({
                                status: "FAILED",
                                message: "Couldn't save password reset data!",
                            });

                        })
       
                    })
                    .catch(error => {
                        console.log(error);
                        res.json({
                            status: "FAILED",
                            message: "An error occurred while hashing the password reset data!",
                        });
                    })

                })
            .catch(error => {
                //error while clearing existing records
                console.log(error);
                res.json({
                    status: "FAILED",
                    message: "clearing existing password reset records failed"
                })
            })
}
//----------------------------------------------------------------------------------------------------
//actually reset the password
app.post("/user/resetpassword" , (req,res)=>{
    let{ email,otp,newPassword}=req.body;
    PasswordReset
    .find({email})
    .then(result=>{
        if(result.length>0){
            //paassword reset recover exists on so we proceed
const { expiredAt} = result[0];
const hashedOTP = result[0].otp
////checking for expired reset  string 

if(expiredAt <Date.now()){
    PasswordReset
    .deleteOne({email})
    .then(()=>{
        //reset record delete successfully
        res.json({
            status: "FAILED",
            message: "password reset link has expired"
        })
})
    .catch(error=>{
        //deletion failed
        console.log(error)
        res.json({
            status: "FAILED",
            message: "clearing password reset record failed  "
        })
    })
        } else{
//valid reset record exists so we validate
//first compare the hashed reset string
bcrypt
.compare(otp , hashedOTP)
.then((result)=>{
if(result){
//strings matches
//hashed password again
const saltRounds=10
bcrypt
.hash(newPassword, saltRounds)
.then(hashedNewPassword=>{
    //update user password
    user
    .updateOne({email},{password: hashedNewPassword})
    .then(()=>{
//upate complete now reset delete 
PasswordReset
.deleteOne({email})
.then(()=>{
//both user record and reset record updated
res.json({
    status: "SUCCESS",
    message: "password has been reset successfuly."
}) 
})
.catch((error)=>{
    console.log(error);
    res.json({
        status: "FAILED",
        message: "An error occured while finilzing password reset"
    }) 
})
    })
    .catch(error =>{
        console.log(error);
        res.json({
            status: "FAILED",
            message: "updating user password faild"
        })
    })
})
.catch((error)=>{
    console.log(error)
    res.json({
        status: "FAILED",
        message: "An error occured while hashing new password"
    })
})
}
else{
//existing record but incorrect reset string path
res.json({
    status: "FAILED",
    message: "invalid password reset details passed"
})
}


})
.catch(error=>{
    res.json({
        status: "FAILED",
        message: "comparing password reset string fails"
    })
})
        }
     } else{
            //password reset record doesnt exist
            res.json({
                status: "FAILED",
                message: "password reset reuest not found"
            })
        }
    })
    .catch(error=>{
        console.log(error);
        res.json({
            status: "FAILED",
            message: "checking for existing password reset record faild"
        })
    })
})



app.listen(port, ()=>{
    console.log(`server runnung on port ${port}`)
})