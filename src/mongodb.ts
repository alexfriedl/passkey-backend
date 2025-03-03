import mongoose from "mongoose";

export async function connectDB() {
  const mongoUri =
    process.env.MONGODB_URI || "mongodb://localhost:27017/localkey";
  try {
    await mongoose.connect(mongoUri, {});
    console.log("MongoDB connected");
  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
}
