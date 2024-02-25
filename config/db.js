const mongoose = require('mongoose');
//env variables
require("dotenv").config()

main().catch(err => console.log(err));

async function main()
{
    await mongoose.connect(process.env.mongoDB);
    console.log('Database connect successfully')
}
