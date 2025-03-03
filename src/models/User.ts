import mongoose, { Document } from "mongoose";

export interface IUser extends Document {
  username: string;
  credentialId: string;
  publicKey: string;
  counter: number;
}

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  credentialId: { type: String, required: true },
  publicKey: { type: String, required: true },
  counter: { type: Number, default: 0 }
});

export default mongoose.model<IUser>("User", UserSchema);
