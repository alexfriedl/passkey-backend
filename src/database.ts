import fs from "fs";
import { WebAuthnUser } from "./types"; // ✅ Import der Typen

const DB_PATH = "./db.json";

let users: { [key: string]: WebAuthnUser } = {};

try {
  users = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
} catch {
  users = {};
}

/**
 * Speichert einen WebAuthn-User mit Attestation-Daten
 */
export function saveUser(username: string, data: Partial<WebAuthnUser>) {
  users[username] = { ...users[username], ...data };
  fs.writeFileSync(DB_PATH, JSON.stringify(users, null, 2));
}

/**
 * Holt einen WebAuthn-User
 */
export function getUser(username: string): WebAuthnUser | null {
  return users[username] || null;
}
