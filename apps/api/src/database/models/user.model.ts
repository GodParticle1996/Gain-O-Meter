import mongoose, { Document, Schema } from "mongoose";
import { compareValue, hashValue } from "../../common/utils/bcrypt";

interface UserPreferences {
  enable2FA: boolean;
  emailNotification: boolean;
  twoFactorSecret?: string;
}

export interface UserDocument extends Document {
  name: string;
  email: string;
  password: string;
  isEmailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
  userPreferences: UserPreferences;
  comparePassword(value: string): Promise<boolean>;
}
const userPreferencesSchema = new Schema<UserPreferences>({
  enable2FA: { type: Boolean, default: false },
  emailNotification: { type: Boolean, default: true },
  twoFactorSecret: { type: String, required: false },
});

const userSchema = new Schema<UserDocument>(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      unique: true,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    userPreferences: {
      type: userPreferencesSchema,
      default: {},
    },
  },
  {
    timestamps: true,
    toJSON: {},
  }
);
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await hashValue(this.password);
  }
  next();
});

userSchema.methods.comparePassword = async function (value: string) {
  return compareValue(value, this.password);
};

userSchema.set("toJSON", {
  transform: function (doc, ret) {
    delete ret.password;
    delete ret.userPreferences.twoFactorSecret;
    return ret;
  },
});

const UserModel = mongoose.model<UserDocument>("User", userSchema);
export default UserModel;

/***
Pre-save Middleware for Password Hashing:
-----------------------------------------
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await hashValue(this.password);
  }
  next();
});
Purpose: This middleware is executed before a document is saved to the database.
Functionality: It checks if the password field has been modified. If it has, it hashes the password using the hashValue function and updates the password field with 
the hashed value.

JSON Transformation to Exclude Sensitive Fields:
------------------------------------------------
userSchema.set("toJSON", {
  transform: function (doc, ret) {
    delete ret.password;
    delete ret.userPreferences.twoFactorSecret;
    return ret;
  },
});
Purpose: This sets a transformation option for the toJSON method of the schema.
Functionality: When converting a document to JSON when fetching the data from the db, this function removes the password field and the twoFactorSecret from the 
userPreferences object. Prevents sensitive information from being exposed in API responses or logs.

Custom Method for Password Comparison:
--------------------------------------
userSchema.methods.comparePassword = async function (value: string) {
  return compareValue(value, this.password);
};
Purpose: Adds a custom method to the User model to compare a provided password with the hashed password stored in the database.
Functionality: Takes a string value (the password entered by the user) and compares it to the hashed password using the compareValue function.
Usage: Useful for authentication to verify that the provided password matches the stored hashed password.
***/
