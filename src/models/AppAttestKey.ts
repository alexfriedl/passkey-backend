import mongoose, { Document, Schema } from "mongoose";

export interface IAppAttestKey extends Document {
  username: string;
  keyId: string;
  publicKey: string;
  counter: number;
  appId: string;
  createdAt: Date;
  lastUsed: Date;
}

const AppAttestKeySchema = new Schema<IAppAttestKey>({
  username: { type: String, required: true },
  keyId: { type: String, required: true, unique: true },
  publicKey: { type: String, required: true },
  counter: { type: Number, default: 0 },
  appId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastUsed: { type: Date, default: Date.now }
});

// Index für schnelle Lookups
AppAttestKeySchema.index({ username: 1, keyId: 1 });

export default mongoose.model<IAppAttestKey>("AppAttestKey", AppAttestKeySchema);