const mongoose = require("mongoose");

const databaseName = "devrel-node-auth-db";
const appName = "devrel-tutorial-nodejs-authentication-geeksforgeeks";

const connectDB = async () => {
  try {
    const mongoUri = `${process.env.MONGO_URI_BASE}/${databaseName}?retryWrites=true&w=majority&appName=${appName}`;

    await mongoose.connect(mongoUri);

    console.log("MongoDB connected");
    console.log(`Database: ${databaseName}`);
    console.log(`App Name: ${appName}`);
  } catch (error) {
    console.error("MongoDB connection failed:");
    console.error(error.message);

    process.exit(1);
  }
};

module.exports = connectDB;