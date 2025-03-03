import { Fido2AttestationResult, Fido2Lib } from "fido2-lib";
import {
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from "./challenge-store";
import { randomBytes } from "crypto";
import { createHash } from "crypto";
import cbor from "cbor";
import { promises as fs } from "fs";
import path from "path";

// --- User-Speicherung in JSON ---
interface User {
  username: string;
  credentialId: string; // Als Base64URL-kodierter String
  publicKey: string;
  counter: number;
}

const USERS_FILE = path.join(__dirname, "users.json");

async function loadUsers(): Promise<User[]> {
  try {
    const data = await fs.readFile(USERS_FILE, "utf8");
    return JSON.parse(data) as User[];
  } catch (err) {
    // Falls die Datei noch nicht existiert, gib ein leeres Array zurück
    return [];
  }
}

async function saveUsers(users: User[]): Promise<void> {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

// --- fido2-lib Konfiguration ---
const rpId = "www.appsprint.de";
const fido2 = new Fido2Lib({
  rpId,
  rpName: "LocalKeyApp",
  challengeSize: 32,
  attestation: "none", // Da iOS-App/DCAppAttestService ein eigenes Format liefert "apple-appattest"
  cryptoParams: [-7], // ECDSA P-256
  authenticatorAttachment: "platform",
  timeout: 60000,
});

/**
 * Registrierung: Optionen für FIDO2-Passkey-Registrierung generieren
 */
export async function generateRegistrationOptions(
  username: string
): Promise<PublicKeyCredentialCreationOptions> {
  // Hole die Optionen von fido2-lib. Dabei ist options.challenge ein ArrayBuffer.
  const options = await fido2.attestationOptions();

  // Konvertiere die Challenge in einen Base64URL-String und speichere ihn.
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  storeChallenge(username, challengeBase64);

  // Generiere eine User-ID und wandle sie in einen Base64URL-String um.
  const userIdBuffer = randomBytes(16);
  const userIdBase64 = arrayBufferToBase64Url(userIdBuffer);

  // Erstelle das Response-Objekt mit Challenge und User-ID als Strings.
  const response: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: challengeBase64, // als Base64URL-String
    user: {
      id: userIdBase64, // als Base64URL-String
      name: username,
      displayName: username,
    },
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      requireResidentKey: true,
      userVerification: "required",
    },
  };

  return response;
}

async function patchAttestationObject(attestationObjectBase64Url: string) {
  // Decode the attestation object from base64url
  const attestationBuffer = Buffer.from(
    attestationObjectBase64Url.replace(/-/g, "+").replace(/_/g, "/"),
    "base64"
  );
  const attObj = await cbor.decodeFirst(attestationBuffer);
  console.log("Decoded attestation object:", JSON.stringify(attObj, null, 2));

  // Change the format to "none" and clear the attestation statement.
  attObj.fmt = "none";
  attObj.attStmt = {};
  console.log("Patched attestation object:", JSON.stringify(attObj, null, 2));

  // (Optionally, you may want to adjust the authenticator data if needed.)
  // For instance, if your backend does extra checks on flags or AAGUID,
  // make sure the authData is in the expected form.

  // Re-encode the patched attestation object.
  const newAttestationBuffer = cbor.encode(attObj);
  return newAttestationBuffer.toString("base64url");
}

/**
 * Reassembles authenticator data from a Buffer.
 * If the original authData is only 37 bytes (no attested credential data),
 * this function simulates minimal attested data (dummy AAGUID and zero-length credential ID).
 */
function reassembleAuthData(authDataBuffer: Buffer): ArrayBuffer {
  const fixedPartLength = 37; // rpIdHash (32) + flags (1) + counter (4)
  if (authDataBuffer.length === fixedPartLength) {
    // No attested credential data is present.
    // Simulate minimal attested credential data:
    // - Dummy AAGUID: 16 bytes (all zeros)
    // - Credential ID Length: 2 bytes, set to 0
    const aaguid = Buffer.alloc(16, 0);
    const credIdLen = Buffer.alloc(2, 0);
    const dummyAttestedData = Buffer.concat([aaguid, credIdLen]);
    // Update the fixed part's flags to indicate attested data is present:
    const newFixed = Buffer.from(authDataBuffer.slice(0, fixedPartLength));
    newFixed[32] = newFixed[32] | 0x40; // Set AT flag (0x40) along with UP flag (already set as 0x01)
    const newAuthData = Buffer.concat([newFixed, dummyAttestedData]);
    return newAuthData.buffer.slice(
      newAuthData.byteOffset,
      newAuthData.byteOffset + newAuthData.byteLength
    );
  } else if (authDataBuffer.length > fixedPartLength) {
    // Attested data is already present. Return a clean copy:
    return authDataBuffer.buffer.slice(
      authDataBuffer.byteOffset,
      authDataBuffer.byteOffset + authDataBuffer.byteLength
    );
  } else {
    throw new Error("authDataBuffer is too short");
  }
}

/**
 * Registrierung: FIDO2-Passkey-Registrierung verifizieren
 */
export async function verifyRegistration(
  credential: any,
  username: string
): Promise<Fido2AttestationResult> {
  const challengeBase64 = getChallenge(username);
  if (!challengeBase64) {
    throw new Error("Challenge nicht gefunden oder abgelaufen.");
  }
  console.log("🔄 Geladene Challenge:", challengeBase64);
  console.log(
    "📥 Credential für Verifizierung:",
    JSON.stringify(credential, null, 2)
  );
  deleteChallenge(username);

  // Konvertiere id und rawId in ArrayBuffer
  credential.rawId = base64UrlToArrayBuffer(credential.rawId);
  credential.id = base64UrlToArrayBuffer(credential.id);

  // STEP 1: clientDataJSON anpassen
  {
    const clientDataBuffer = Buffer.from(
      credential.response.clientDataJSON,
      "base64"
    );
    let clientData;
    try {
      clientData = JSON.parse(clientDataBuffer.toString("utf8"));
    } catch (err) {
      throw new Error("Fehler beim Parsen von clientDataJSON");
    }
    clientData.challenge = challengeBase64;
    const newClientDataStr = JSON.stringify(clientData);
    credential.response.clientDataJSON =
      Buffer.from(newClientDataStr).toString("base64");
  }

  function base64UrlToBase64(base64url: string) {
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4 !== 0) {
      base64 += "=";
    }
    return base64;
  }

  function base64ToHex(base64: any) {
    const buffer = Buffer.from(base64, "base64");
    return buffer.toString("hex");
  }

  // console.log(
  //   "📥 Credential Attestation Object (Base64):",
  //   base64UrlToBase64(credential.response.attestationObject)
  // );

  console.log(
    "📥 Credential Attestation Object (Hex):",
    base64ToHex(base64UrlToBase64(credential.response.attestationObject))
  );

  // STEP 2: Attestation-Objekt anpassen
  {
    const attestationBuffer = Buffer.from(
      credential.response.attestationObject,
      "base64"
    );
    let attestationObj = await cbor.decodeFirst(attestationBuffer);
    attestationObj.fmt = "none";
    attestationObj.attStmt = {};

    // Get authData as a Buffer
    let authDataBuffer = Buffer.isBuffer(attestationObj.authData)
      ? attestationObj.authData
      : Buffer.from(attestationObj.authData);

    // Patch rpIdHash (first 32 bytes)
    const expectedRpIdHash = createHash("sha256")
      .update("www.appsprint.de")
      .digest();
    expectedRpIdHash.copy(authDataBuffer, 0, 0, 32);

    // Ensure the UP flag is set (bit 0, 0x01)
    authDataBuffer[32] = authDataBuffer[32] | 0x01;

    // Reassemble authData:
    const cleanAuthDataBuffer = reassembleAuthData(authDataBuffer);
    console.log("Clean authData length:", cleanAuthDataBuffer.byteLength);
    console.log(
      "Clean authData (hex):",
      Buffer.from(cleanAuthDataBuffer).toString("hex")
    );

    // Optionally log the AAGUID portion (bytes 37 to 52, if present):
    if (cleanAuthDataBuffer.byteLength >= 55) {
      const aaguidHex = Buffer.from(cleanAuthDataBuffer)
        .toString("hex")
        .substr(74, 32);
      console.log("AAGUID (hex):", aaguidHex);
    }

    attestationObj.authData = cleanAuthDataBuffer;

    const newAttestationBuffer = cbor.encode(attestationObj);
    credential.response.attestationObject =
      newAttestationBuffer.toString("base64");
  }

  try {
    // Patch the attestation object
    // Convert ftm from "apple-appattest" to "none" and remove attStmt
    const patchedAttestationObject = await patchAttestationObject(
      credential.response.attestationObject
    );
    console.log(
      "Patched attestation object (Base64URL):",
      patchedAttestationObject
    );
    credential.response.attestationObject = patchedAttestationObject;

    const attestationResult = await fido2.attestationResult(credential, {
      challenge: challengeBase64,
      origin: `https://${"www.appsprint.de"}`,
      factor: "either",
    });
    console.log("✅ Registrierung erfolgreich:", attestationResult);
    return attestationResult;
  } catch (error) {
    console.error("❌ Fehler bei fido2.attestationResult():", error);
    throw new Error("Fehler beim Verifizieren der Registrierung.");
  }
}

/**
 * Authentifizierung: Optionen für FIDO2-Login generieren
 */
export async function generateAuthenticationOptions(
  username: string
): Promise<PublicKeyCredentialRequestOptions> {
  const options = await fido2.assertionOptions();
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  storeChallenge(username, challengeBase64);

  return {
    ...options,
    challenge: options.challenge, // Laut Typdefinition als ArrayBuffer
    allowCredentials: options.allowCredentials?.map((cred) => ({
      ...cred,
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

/**
 * Authentifizierung: FIDO2-Login verifizieren
 */
export async function verifyAuthentication(
  assertion: any,
  publicKey: string,
  username: string
) {
  const challengeBase64 = getChallenge(username);
  if (!challengeBase64) {
    throw new Error("Challenge nicht gefunden oder abgelaufen.");
  }
  deleteChallenge(username);
  const users = await loadUsers();
  const user = users.find((u) => u.username === username);
  if (!user) {
    throw new Error("User not found.");
  }
  try {
    const assertionResult = await fido2.assertionResult(assertion, {
      challenge: challengeBase64,
      origin: `https://${rpId}`,
      factor: "either",
      publicKey,
      prevCounter: user.counter,
      userHandle: null,
    });
    // Aktualisiere den Counter
    user.counter = assertionResult.authnrData.get("counter") || user.counter;
    await saveUsers(users);
    console.log("✅ Authentifizierung erfolgreich:", assertionResult);
    return assertionResult;
  } catch (error) {
    console.error("❌ Fehler bei fido2.assertionResult():", error);
    throw new Error("Fehler beim Verifizieren der Authentifizierung.");
  }
}

/**
 * Konvertiert einen ArrayBuffer in einen Base64URL-kodierten String.
 */
export function arrayBufferToBase64Url(buffer: ArrayBuffer): any {
  const binary = new Uint8Array(buffer);
  let base64 = "";
  for (let i = 0; i < binary.byteLength; i++) {
    base64 += String.fromCharCode(binary[i]);
  }
  return Buffer.from(base64, "binary")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Konvertiert einen Base64URL-kodierten String in einen ArrayBuffer.
 */
export function base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const binary = Buffer.from(base64, "base64").toString("binary");
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}
