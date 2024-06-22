import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    avatar: {
      type: String, //cloudinary url
      required: true,
    },
    coverImage: {
      type: String, //cloudinary url
    },
    watchHistory: [
      {
        type: Schema.Types.ObjectId,
        ref: "Videos",
      },
    ],
    password: {
      type: String,
      required: [true, "Password is required"],
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  // Hash the password only if it has been modified (or is new)
  if (!this.isModified("password")) {
    return next();
  }

  this.password = await bcrypt.hash(this.password, 10);
  next();
});
//Function Compaire the password with the user password
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Create generate token method
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    //payload
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName,
    },
    //secreate key
    process.env.ACCESS_TOKEN_SECRET,

    //Expire object
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    //payload
    {
      _id: this._id,
    },
    //secreate key
    process.env.REFRESH_TOKEN_SECRET,

    //Expire object
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};
export const User = mongoose.model("User", userSchema);
