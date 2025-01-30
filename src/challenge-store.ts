const challengeStore = new Map<
  string,
  { challenge: string; expires: number }
>();

export function storeChallenge(username: string, challenge: string) {
  challengeStore.set(username, {
    challenge,
    expires: Date.now() + 5 * 60 * 1000,
  }); // 5 Minuten TTL
}

export function getChallenge(username: string): string | null {
  const entry = challengeStore.get(username);
  if (!entry || entry.expires < Date.now()) {
    challengeStore.delete(username);
    return null;
  }
  return entry.challenge;
}

export function deleteChallenge(username: string) {
  challengeStore.delete(username);
}
