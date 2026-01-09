import mongoose, { Document } from "mongoose";

export interface IUser extends Document {
  username: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  userHandle?: string; // FIDO: user.id bei Registrierung, fuer Discoverable Auth
  registrationPlatform?: string;
  serverChallenge?: string;
  iosChallenge?: string;
  clientDataHash?: string;
  createdAt?: Date;
}

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  credentialId: { type: String, required: true },
  publicKey: { type: String, required: true },
  counter: { type: Number, default: 0 },
  userHandle: { type: String, required: false, index: true }, // FIDO: user.id fuer Discoverable
  registrationPlatform: { type: String, required: false },
  serverChallenge: { type: String, required: false },
  iosChallenge: { type: String, required: false },
  clientDataHash: { type: String, required: false },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model<IUser>("User", UserSchema);
