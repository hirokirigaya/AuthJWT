import * as dotenv from "dotenv";
dotenv.config();
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "./models/User";
import { Request, Response, NextFunction } from "express";

const app = express();

// Config JSON response
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Open Route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Hello World" });
});

// Protected Route
app.get("/user/:id", checkToken, async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  return res.status(200).json(user);
});

function checkToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  try {
    const secret = process.env.SECRET

    if (secret) {
      jwt.verify(token, secret);
      next();
    }

  } catch (error) {
    return res.status(400).json({ message: "Invalid token" });
  }
}
// Register Route

app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  if (!name) {
    return res.status(422).json({ message: "Name is required" });
  }
  if (!email) {
    return res.status(422).json({ message: "Email is required" });
  }
  if (!password) {
    return res.status(422).json({ message: "Password is required" });
  }
  if (!confirmPassword) {
    return res.status(422).json({ message: "Confirm Password is required" });
  }
  if (password !== confirmPassword) {
    return res
      .status(422)
      .json({ message: "Password and Confirm Password must be same" });
  }

  // Check if email already exists

  const userExists = await User.findOne({ email });

  if (userExists) {
    return res.status(422).json({ message: "Email already exists" });
  }

  // Hash password
  const salt = await bcrypt.genSalt(12);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create user

  const user = new User({
    name,
    email,
    password: hashedPassword,
  });

  try {
    await user.save();
    return res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    return res.status(500).json({ message: "Something went wrong" });
  }
});

// Login Route

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.status(422).json({ message: "Email is required" });
  }
  if (!password) {
    return res.status(422).json({ message: "Password is required" });
  }

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: "User does not exists" });
  }

  // Check if password is match
  if (user.password) {
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(422).json({
        message: "Wrong data, check if email or password is correct!",
      });
    }

    try {
      const secret = process.env.SECRET;

      if (!secret) {
        return res.status(500).json({ message: "Something went wrong" });
      }

      const token = jwt.sign({ id: user._id }, secret);

      return res
        .status(200)
        .json({ message: "Authencation successfuly!", token });
    } catch (error) {
      return res.status(500).json({ message: "Something went wrong" });
    }
  }
});

// Conect to database
const dbUser = process.env.DB_USER;
const dbPassword = encodeURIComponent(process.env.DB_PASSWORD || "");

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@authawt.9lz2caj.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(5000, () => {
      console.log("Server is running on port 5000");
    });
  })
  .catch((err: any) => {
    console.log(err);
  });
