const express = require('express');
const router = express.Router()
const jwt = require('jsonwebtoken')
const util = require('util')
const AsyncAsign = util.promisify(jwt.sign)
const lod = require('lodash')
//server.js
const server = require('../server')

// mongodb user model
const user = require('./../models/user');

// mongodb PasswordReset model
const PasswordReset = require('./../models/PasswordReset');

// mongodb user verification  model
const UserVerification = require('../models/userverification');

//password handler
const bcrypt = require('bcrypt');

//path for static verified page 
const path = require("path")

//email handler 
const nodemailer=require("nodemailer")

//unique string
const {v4: uuidv4} = require("uuid");
const { error } = require('console');

//env variables
require("dotenv").config()

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
//----------------------------------------------------------------------------------
//Signup
router.post('/signup', (req,res)=>{
    let {name, email, password,role} = req.body;
    name = name.trim();
    email = email.trim();
    password = password.trim();
    

    if(name == "" || email == "" || password == "" )
    {
        res.json({
            status: "FAILED",
            message: "Empty input fields!" 
        });
    } 
    else if (!/^[a-zA-Z]*$/.test(name))
    {
        res.json({
            status: "FAILED",
            message: "Invalid name entered" 
        });
    }
    else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email))
    {
        res.json({
            status: "FAILED",
            message: "Invalid email entered" 
        });
    }
    else if (password.length < 8)
    {
        res.json({
            status: "FAILED",
            message: "password is too short!" 
        })
    }
    else
    {
        //checking if user already exists
        user.find({email}).then(result => {
            if(result.length)
            {
                //A user already exists
                res.json({
                    status: "FAILED",
                    message: "User with the provided email already exists"
                })
            }
            else 
            {
                //try to create new user

                //password handling
                const saltRounds = 10;
                bcrypt.hash(password,saltRounds).then(hashedPassword => {
                    const newUser = new user({
                        name,
                        email,
                        password:hashedPassword,
                        role,
                        verified:false
                    });

                newUser.save().then(result => {
                    //handle account verification 
                    sendVerificationEmail(result, res)

                })



            .catch(err => {
                res.json({
                    status: "FAILED",
                    message: "An error occurred while saving user account!"
                })
            })
                })
            
            .catch(err => {
                    res.json({
                        status: "FAILED",
                        message: "An error occurred while hashing password!"
                    })
                })
            }
            
        }).catch(err => {
            console.log(err);
            res.json({
                status: "FAILED",
                message: "An error occurred while checking for existing user!"
            })
        })
    }
 
})
//----------------------------------------------------------------------------------
//generate OTP
const generateOTP = () => {
    try{
        return(otp= `${Math.floor(1000 + Math.random()*9000)}`);
    } catch(error){
        throw error ;
    }
};
const generate = generateOTP();

//send verification email
const sendVerificationEmail = ({_id, email},res) => {

    const existingUser = user.findOne({email});
    if(!existingUser){
        res.json({
            status:"FAILED",
            message:"There is no account for the provided email.",
        });
    }

    //mail options 
    const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Verify Your Email",
        html: `<p>Verify your email with the code below</p><p style="color:tomato; font-size:25px; letter-spacing:2px;"><b>${generate}</b></p><p>This code <b>expires in 1 hour(s)</b>.</p>`,
    };

    //hash the uniqueString
    const saltRounds = 10;
bcrypt
      .hash(generate, saltRounds)
      .then((hashedOTP)=>{
        //set values in userVerification collection
        const newVerification = new UserVerification({
            userId:_id,
            email:email,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiredAt: Date.now() + 3600000,
        });

        newVerification
        .save()
        .then(()=>{
            transporter
            .sendMail(mailOptions)
            .then(()=>{
                //email sent and verification record saved
                res.json({
                    status:"PENDING",
                    message:"Verification email sent"
                })
            })
            .catch((error)=>{
                console.log(error)
                res.json({
                    status:"FAILED",
                    message:"Verification email failed",
                });
            })
        })

           .catch((error)=>{
              console.log(error)
              res.json({
                  status:"FAILED",
                  message:"Could't save verification email data!",
        });

    })
})
         .catch(() => {
             res.json({
             status:"FAILED",
             message:"An error occurred while hashing email data!",
       });
    })

};
//--------------------------------------------------------------------------------------------
//verify email
router.post("/verify",(req, res)=>{
    let{ email, otp } = req.body;

    if(!(email && otp)) throw Error("Empty otp details are not allowed");
    console.log(email)

    UserVerification
    .find({email})
    .then((result)=>{
        if(result.length>0){
            //user verification record exists so we proceed
            const {expiredAt} = result[0];
            const hashedOTP = result[0].otp;

            //checking for expired unique string
            if(expiredAt < Date.now()){
                //record has expired so we delete it 
                UserVerification
                .deleteOne({email})
                .then(result =>{
                    user
                     .deleteOne({email})
                     .then(() => {
                        res.json({
                            status:"FAILED",
                            message:"code has expired. please sign up again.",
                         });
                     })
                     .catch(error => {
                        console.log(error)
                        res.json({
                            status:"FAILED",
                            message:"Clearing user with expired unique string failed",
                         });
                     })  
                })
                .catch((error) => {
                    console.log(error);
                    res.json({
                        status:"FAILED",
                        message:"An error occured while clearing expired user verification record",
                     });
                })
            }else{
                //valid record exists so we validate the user string
                //first compare the hashed unique string

                bcrypt
                     .compare(otp, hashedOTP)
                     .then(result=>{
                        if(result){
                            //strings match 
                            user
                            .updateOne({email},{verified:true})
                            .then(()=>{
                                UserVerification
                                .deleteOne({email})
                                .then(() =>{
                                    // Here we send a status of "verified successful"
                                    res.json({
                                        status:"SUCCESS",
                                        message:"Email verified",
                                     });
                                })
                                .catch(error => {
                                    console.log(error)
                                    res.json({
                                        status:"Failed",
                                        message:"An error occurred while finalizing successful verification.",
                                     });
                                })
                            })
                            .catch(error => {
                                console.log(error)
                                res.json({
                                    status:"Failed",
                                    message:"An error occurred while updating user record to show verified.",
                                 });
                                
                            })
                        }else {
                            //existing record but incorrect verification details passed.
                            res.json({
                                status:"Failed",
                                message:"Invalid verification details passed. check your inbox.",
                             });
                        }
                        
                     })
                     .catch(error =>{
                        console.log(error)
                        res.json({
                            status:"Failed",
                            message:"An error occurred while comparing unique strings.",
                         });
                     })
            }
        } else {
            //user verification record doesn't exist
            res.json({
                status:"Failed",
                message:"Account record doesn't exist or has been verified already. please sign up or log in.",
             });
        }
    })
    .catch((error)=>{
        console.log(error);
        res.json({
            status:"Failed",
            message:"An error occurred while checking for existing user verification record",
         });
    })
});


//--------------------------------------------------------------------------------------------------------
//signin
router.post('/signin', (req,res)=>{
    let {email,password} = req.body;
    email = email.trim();

    if(email == "" || password == "")
    {
        res.json({
            status:"FAILED",
            message:"Empty credentails supplied"

        })
    }else{
        //check if user exist 
        user.find({email})
        .then(data => {
            if(data.length){
                //User exists 
                 
               //check if user is verifiec
                if(!data[0].verified){
                    res.json({
                        status: "FAILED",
                        message: "Email hasn't been verified yet. check your inbox.",
                        data: data
                    });
                }else{
                    const hashedPassword = data[0].password;
                    bcrypt.compare(password,hashedPassword).then(result =>{
                        if(result){
                            //password match 
                            const token = jwt.sign({ userId: data[0]._id }, process.env.secretKey);
                            res.json({
                                status: "SUCCESS",
                                message: "Signin successful",
                                token: token,
                                data: data
                            })
                        }else {
                            res.json({
                                status:"FAILED",
                                message:"Invalid password entered!"
                            })
                        }
                    })
                .catch(err => {
                    res.json({
                        status:"FAILED",
                        message:"An error occurred while comparing passwords"
                    })
                })
                }
                
            }else{
                res.json({
                    status:"FAILED",
                    message:"Invalid credentials entered!"
                })
            }
        })
    .catch(err => {
        res.json({
            status: "FAILED",
            message: "An error occurred while checking for existing user"
        })
    })
    }

})
//------------------------------------------------------------

//detect by upload image
const fs = require("fs");
const axios = require("axios");
const multer = require('multer')

const storage = multer.diskStorage({
    destination : function(req, file, cb){
        cb(null,'./uploads/')
    },

    filename : function(req, file, cb ){
        cb(null, new Date().toString().replace(/:/g,"-") + file.originalname)
    }

});
// Set up Multer to handle file uploads
const upload = multer({ storage : storage });

// Define a route handler for POST requests to '/detect'
router.post("/detect", upload.single("image"), async (req, res) => {
    try {
        // Read image file asynchronously from request body
        const image = fs.readFileSync(req.file.path, { encoding: "base64" });

        // Make a POST request to the Roboflow API
        const response = await axios({
            method: "POST",
            url: "https://detect.roboflow.com/monuments-detection/3",
            params: {
                api_key: "gBGAOaROepf97ZEZH36I"
            },
            data: image,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Send the response from the API to the client
        res.send(response.data);
    } 
    catch (error) {
        // Handle errors
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});
//-------------------------------------------------------------------------------------------------
//Say 
/*const say = require('say')
router.get('/Ramsses', async (req, res) => {
    say.speak("information about statue The Statue of Ramesses II, also known as Ramesses the Great who ruled Egypt during the 19th dynasty from 1279 to 1213 BC Here are some details about this statue: Material:  The statue is made of red granite Height The statue stands about 3.6 meters 12 feet tall Discovery The statue was discovered in several fragments by archaeologists working in Heliopolis in the 19th century. It was later reassembled. Significance The Statue of Ra Ramesses II is significant for several reasons. It is a powerful symbol of the might and grandeur of the New Kingdom of Egypt, particularly during the reign of Ramesses II, who is often regarded as one of Egypt's greatest pharaohs. information about Ramsses II's life ramses II ascended the throne at the young age of 25 and ruled for an impressive 66 years, making his reign one of the longest in ancient egyptian history. he was known for his military prowess and led several military campaigns in Nubia, Syria, and Canaan, defeated the enigmatic Sea People in a naval battle in the Nile Delta, and claimed victory over Egypt's Hittite rivals in the Battle of Kadesh a conflict that ended with the signing of the world's first treaty Beyond his military achievements, Ramsses II is also renowned for his monumental building projects. he initiated numerous construction project throughout egypt, including the famous temples of Abu Simbel, the Ramesseum, and the temple of Ramsses II. these grand structures were intended to showcase his power and reinforce the image of egyptian strength and prosperity Ramsses II also known for his extensive family, he had a large number of wives, including the renowned queen Nefertari, and numerous children, his family played an important role in his reign, and he took great care to secure their positions and create a dynasty that would last for generations")
});

router.get('/Khafre', async (req, res) => {
    say.speak("- information about statue The Statue of Khafre, also known as the “khafre enthroned”,  who ruled Egypt during the Fourth Dynasty of the Old Kingdom period, from 2559 to 2535 BC. Here are some details about this statue: Material: The statue is made of diorite, a hard, dark-grey to black volcanic rock. Height: It stands at about 168 cm (5 feet 6 inches) tall. Depiction: The statue depicts Khafre wearing the nemes headcloth with the royal cobra on his forehead. Discover: The statue was discovered in 1860 during excavations near the Great Sphinx of Giza in Egypt. - information about Khafre's life Khafre was the son of Pharaoh Khufu who built the Great Pyramid of Giza, Khafre married his sister Khamerernebti, Meresankh III, and perhaps two other queens. Khafre's reign is known for its monumental building projects, including the construction of the second-largest pyramid at Giza, known as the Pyramid of Khafre. This pyramid complex also includes the Great Sphinx, a colossal limestone statue with the body of a lion and the head of a pharaoh,  which many consider to bear Khafre’s features. In addition to his pyramid complex at Giza, Khafre is credited with building several other monuments, including temples and tombs in the vicinity of Giza and in other parts of Egypt. Khafre was succeeded by his son Menkaure, who continued the tradition of pyramid building at Giza.")
});

router.get('/Tutankhamun', async (req, res) => {
    
});*/

module.exports = router;