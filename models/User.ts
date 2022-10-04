import mongoose from "mongoose";

const User = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

export default mongoose.model("User", User);
