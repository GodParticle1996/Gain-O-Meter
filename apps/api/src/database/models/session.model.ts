import mongoose, { Document, Schema } from "mongoose";
import { thirtyDaysFromNow } from "../../common/utils/date-time";

export interface SessionDocument extends Document {
  userId: mongoose.Types.ObjectId;
  userAgent?: string;
  expiredAt: Date;
  createdAt: Date;
}

const sessionSchema = new Schema<SessionDocument>({
  /*
  When you see ref: "User", it tells MongoDB that the userId field contains an ID that points to a document in the "User" collection. This is why the .populate("userId") method 
  in the getSessionById function works - it uses this reference to automatically fetch the complete user information instead of just having the ID.
  */
  userId: {
    type: Schema.Types.ObjectId,
    ref: "User",
    index: true,
    required: true,
  },
  userAgent: {
    type: String,
    required: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  expiredAt: {
    type: Date,
    required: true,
    default: thirtyDaysFromNow,
  },
});

const SessionModel = mongoose.model<SessionDocument>("Session", sessionSchema);

export default SessionModel;

/*
ref: "User" - What it means
Relationships: In MongoDB, you often have data that's related. In your case, a "Session" is related to a "User".  ref: "User" tells Mongoose that the userId 
field in your Session schema isn't just a random ObjectId. Instead, it's an ObjectId that should correspond to a document in the "User" collection.

Population: This sets the stage for a powerful feature called "population".  Imagine you fetch a session document. With ref, Mongoose allows you to easily 
"populate" that session with the actual user data it references, effectively joining the related information.

How it works
ObjectId: The type: Schema.Types.ObjectId ensures that userId stores a valid MongoDB ObjectId. This is how MongoDB uniquely identifies documents within collections.
Reference: ref: "User" creates the link. Mongoose now knows that this ObjectId should point to a document in the "User" collection.

Behind the scenes:  When you use Mongoose's .populate('userId') (more on this below), it performs an additional query to fetch the user document with the matching _id 
and replaces the userId in your session document with the full user object.

Example:
Fetch a session
const session = await SessionModel.findById(sessionId).populate('userId'); 

Now, session.userId will contain the full user document
console.log(session.userId.name);
*/
