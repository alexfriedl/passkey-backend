import mongoose from 'mongoose';

const challengeSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  challenge: { type: String, required: true },
  expires: { type: Date, required: true, index: { expireAfterSeconds: 0 } }
});

const Challenge = mongoose.model('Challenge', challengeSchema);

export async function storeChallenge(username: string, challenge: string) {
  try {
    await Challenge.findOneAndUpdate(
      { username },
      {
        username,
        challenge,
        expires: new Date(Date.now() + 5 * 60 * 1000) // 5 Minuten TTL
      },
      { upsert: true, new: true }
    );
  } catch (error) {
    console.error('Error storing challenge:', error);
    throw error;
  }
}

export async function getChallenge(username: string): Promise<string | null> {
  try {
    const entry = await Challenge.findOne({
      username,
      expires: { $gt: new Date() }
    });
    return entry?.challenge || null;
  } catch (error) {
    console.error('Error getting challenge:', error);
    return null;
  }
}

export async function deleteChallenge(username: string) {
  try {
    await Challenge.deleteOne({ username });
  } catch (error) {
    console.error('Error deleting challenge:', error);
  }
}
