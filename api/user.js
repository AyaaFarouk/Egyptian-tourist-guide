const express = require('express');
const router = express.Router()
const jwt = require('jsonwebtoken')
const util = require('util')
const AsyncAsign = util.promisify(jwt.sign)
const lod = require('lodash')
//server.js
const server = require('../index')

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

const AUTH_EMAIL= "egyptiantourguide2024@gmail.com"
const AUTH_PASS= "lmcz rkrn xlbg jbqe"
//nodemailer stuff
let transporter = nodemailer.createTransport({
    service:"gmail",
    auth:{
        user: AUTH_EMAIL,
        pass: AUTH_PASS,
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
    let {userId,name, email, password,role} = req.body;
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
                        userId,
                        name,
                        email,
                        password:hashedPassword,
                        role,
                        verified:false,
                        adminRole:false
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
        from: AUTH_EMAIL,
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
                    console.log(hashedPassword)
                    console.log(password)
                    bcrypt.compare(password,hashedPassword).then(result =>{
                        console.log(password)
                        if(result){
                            //password match 
                            const secretKey = "OAABB"
                            const token = jwt.sign({ userId: data[0]._id }, secretKey, { expiresIn: '1h' });
                            console.log(token)
                            //console.log(userId)
                            console.log(data[0]._id)
                           // req.session.token = token;
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
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logout successful' });
  });

//------------------------------------------------------

//detect by upload image
const fs = require("fs");
const axios = require("axios");
const multer = require('multer')
const bodyParser = require('body-parser');

const storage = multer.diskStorage({
    destination : function(req, file, cb){
        cb(null,'/tmp')
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
            url: "https://classify.roboflow.com/oe-stat2/1",
            params: {
                api_key: "0H9DYFvGrPNR6It6xujZ",
            },
            data: image,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Process the response to check the top prediction confidence value
        /*const { confidence } = response.data;
        const result = confidence > 0.8 ? response.data : { result: null, confidence };*/
            
                const { top, confidence } = response.data;
                const result = confidence > 0.8 ? response.data : "null";

        // Send the processed result to the client
        res.send(result);
    } 
    catch (error) {
        // Handle errors
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});
//-------------------------------------------------------------------------------------------------
//OCR API


/*router.post("/ocr", upload.single("image"), async (req, res) => {
   try 
   {
// Read image file asynchronously from request body
 const image = fs.readFileSync(req.file.path, { encoding: "base64" });



const response = await axios ({
  method: 'POST',
  url: 'https://ocr-wizard.p.rapidapi.com/ocr',
  headers: {
    'content-type': 'application/x-www-form-urlencoded',
    'X-RapidAPI-Key': 'd05a7a8449msh6595df6f7787603p1e2378jsndac0edf38919',
    'X-RapidAPI-Host': 'ocr-wizard.p.rapidapi.com'
  },
  data: image,
});
         // Send the response from the API to the client
         res.send(response.data);
}

catch (error) {
	console.error(error.message);
    res.status(500).send("Internal Server Error")
}
});*/




const FormData = require('form-data');

router.post('/ocr',upload.single("image"), async (req, res) => {
  try {
    const image = req.file;

    const data = new FormData();
    data.append('srcImg', fs.createReadStream(image.path));
    data.append('Session', 'string');

    const options = {
        method: 'POST',
        url: 'https://pen-to-print-handwriting-ocr.p.rapidapi.com/recognize/',
        headers: {
          'x-rapidapi-key': '15ff027daamshe9b696d3d9378b2p17dfc9jsnca292b160be3',
          'x-rapidapi-host': 'pen-to-print-handwriting-ocr.p.rapidapi.com',
          ...data.getHeaders(),
        },
        data: data
      };

    const response = await axios.request(options);
    res.send(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
//----------------------------------------------------------------------------
//Face Swap
// Replace with your imgbb API key
const imgbbAPIKey = 'fe8b5ffd5a7a8afa78123aeab8d4f6e4';
  
const uploadToImgbb = async (filePath) => {
  const form = new FormData();
  form.append('image', fs.createReadStream(filePath));

  const response = await axios.post(`https://api.imgbb.com/1/upload?key=${imgbbAPIKey}`, form, {
    headers: {
      ...form.getHeaders(),
    },
  });

  return response.data.data.url;
};

/*router.post('/faceswap', upload.fields([{ name: 'TargetImage' }, { name: 'SourceImage' }]), async (req, res) => {
  try {
    const targetImage = req.files['TargetImage'][0];
    const sourceImage = req.files['SourceImage'][0];

    const targetImageUrl = await uploadToImgbb(targetImage.path);
    const sourceImageUrl = await uploadToImgbb(sourceImage.path);

    const options = {
      method: 'POST',
      url: 'https://faceswap-image-transformation-api.p.rapidapi.com/faceswapgroup',
      headers: {
        'x-rapidapi-key': 'd05a7a8449msh6595df6f7787603p1e2378jsndac0edf38919',
        'x-rapidapi-host': 'faceswap-image-transformation-api.p.rapidapi.com',
        'Content-Type': 'application/json'
      },
      data: {
        TargetImageUrl: targetImageUrl,
        SourceImageUrl: sourceImageUrl,
        MatchGender: true,
        MaximumFaceSwapNumber: 5
      }
    };

    const response = await axios.request(options);
    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while processing the request' });
  } finally {
    // Clean up uploaded files
    fs.unlinkSync(req.files['TargetImage'][0].path);
    fs.unlinkSync(req.files['SourceImage'][0].path);
  }
});*/
router.post('/faceswap', upload.fields([{ name: 'TargetImage' }, { name: 'SourceImage' }]), async (req, res) => {
  try {
    const targetImage = req.files['TargetImage'][0];
    const sourceImage = req.files['SourceImage'][0];

    const targetImageUrl = await uploadToImgbb(targetImage.path);
    const sourceImageUrl = await uploadToImgbb(sourceImage.path);

    const options = {
      method: 'POST',
      url: 'https://faceswap-image-transformation-api.p.rapidapi.com/faceswapgroup',
      headers: {
        'x-rapidapi-key': '97f591d464mshd213f9f039d30e6p16db87jsn939d9d6414b9',
        'x-rapidapi-host': 'faceswap-image-transformation-api.p.rapidapi.com',
        'Content-Type': 'application/json'
      },
      data: {
        TargetImageUrl: targetImageUrl,
        SourceImageUrl: sourceImageUrl,
        MatchGender: true,
        MaximumFaceSwapNumber: 5
      }
    };

    const response = await axios.request(options);
    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while processing the request' });
  } finally {
    // Clean up uploaded files
    fs.unlinkSync(targetImage.path);
    fs.unlinkSync(sourceImage.path);
  }
});

module.exports = router;

