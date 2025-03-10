import { Fido2AttestationResult, Fido2Lib } from "fido2-lib";
import {
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from "./challenge-store";
import { createPublicKey, randomBytes } from "crypto";
import { createHash } from "crypto";
import cbor from "cbor";
import User, { IUser } from "./models/User";

function arrayBufferToBase64(buffer: ArrayBuffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// --- Funktionen zur User-Verwaltung in MongoDB --- //

/**
 * Lädt alle registrierten User aus der Datenbank.
 * @returns Promise, das ein Array von Usern zurückgibt.
 */
export async function loadUsersFromDB(): Promise<IUser[]> {
  try {
    const users = await User.find({});
    console.log("Geladene User aus der DB:", users);
    return users;
  } catch (error) {
    console.error("Fehler beim Laden der User-Daten aus der DB:", error);
    return [];
  }
}

/**
 * Speichert einen neuen User in der Datenbank.
 * @param userData - Die Daten des Users (username, credentialId, publicKey, counter)
 * @returns Promise, das den gespeicherten User zurückgibt.
 */
export async function saveUserToDB(userData: Partial<IUser>): Promise<IUser> {
  try {
    const newUser = new User(userData);
    const savedUser = await newUser.save();
    console.log("Neuer User in der DB gespeichert:", savedUser);
    return savedUser;
  } catch (error) {
    console.error("Fehler beim Speichern des Users in der DB:", error);
    throw error;
  }
}

/**
 * Aktualisiert den Counter eines registrierten Users in der Datenbank.
 * @param username - Der Benutzername des Users
 * @param newCounter - Der neue Counterwert
 * @returns Promise, das den aktualisierten User zurückgibt (oder null, falls nicht gefunden).
 */
export async function updateUserCounter(
  username: string,
  newCounter: number
): Promise<IUser | null> {
  try {
    const updatedUser = await User.findOneAndUpdate(
      { username },
      { counter: newCounter },
      { new: true }
    );
    console.log(`Counter für ${username} aktualisiert:`, updatedUser);
    return updatedUser;
  } catch (error) {
    console.error(
      `Fehler beim Aktualisieren des Counters für ${username}:`,
      error
    );
    throw error;
  }
}

// --- fido2-lib Konfiguration ---
const rpId = "www.appsprint.de";
const fido2 = new Fido2Lib({
  timeout: 60000,
  rpId: "www.appsprint.de",
  rpName: "LocalKeyApp",
  // rpIcon: optional, falls benötigt
  challengeSize: 32,
  authenticatorAttachment: "platform", // Plattform-Authenticator (z. B. Secure Enclave)
  authenticatorRequireResidentKey: false, // Erzwinge keinen resident key, damit iOS den Standard-Flow nutzt
  authenticatorUserVerification: "required", // Der Nutzer muss sich verifizieren (z. B. via Face ID/Touch ID)
  attestation: "none", // Keine herstellergebundene Attestation; iOS liefert dann evtl. ein eigenes Format
  cryptoParams: [-7], // ES256 (ECDSA P-256)
});

/**
 * Registrierung: Optionen für FIDO2-Passkey-Registrierung generieren
 */
export async function generateRegistrationOptions(
  username: string
): Promise<PublicKeyCredentialCreationOptions> {
  // Hole die Optionen von fido2-lib. Dabei ist options.challenge ein ArrayBuffer.
  const options = await fido2.attestationOptions();
  console.log("[Log] Original Challenge (Base64URL): " + arrayBufferToBase64(options.challenge));


  // Konvertiere die Challenge in einen Base64URL-String und speichere ihn.
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  
  console.log("[Log] Challenge als ArrayBuffer (Base64): " + arrayBufferToBase64(options.challenge));
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
      requireResidentKey: false,
      userVerification: "required",
    },
  };

  return response;
}

/**
 * Hilfsfunktion: Passt das Attestation-Objekt an (setzt fmt auf "none" und leert attStmt).
 */
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
 * Hilfsfunktion: Reassembles authenticator data aus einem Buffer.
 * Simuliert attested credential data, falls nicht vorhanden.
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
 * Registrierung: FIDO2-Passkey-Registrierung verifizieren.
 * Nach erfolgreicher Verifikation wird der User in der MongoDB gespeichert.
 */
export async function verifyRegistration(
  credential: any,
  username: string
): Promise<Fido2AttestationResult> {
  username = username.trim();
  const challengeBase64 = getChallenge(username);
  if (!challengeBase64) {
    throw new Error("Challenge nicht gefunden oder abgelaufen.");
  }
  console.log("🔄 Geladene Challenge:", challengeBase64);
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

  // console.log(
  //   "📥 Credential Attestation Object (Hex):",
  //   base64ToHex(base64UrlToBase64(credential.response.attestationObject))
  // );

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
  // (Weitere Anpassungen, z. B. Attestation-Objekt patchen und authData reassemblieren)

  try {
    // Patch attestation object und führe attestationResult aus
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

    // Nach erfolgreicher Registrierung: Prüfe, ob der User bereits existiert und speichere (falls nicht)
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      // Anstatt die (nicht vorhandene) Eigenschaft "credentialPublicKey" zu verwenden,
      // extrahieren wir den Public Key direkt aus "credentialPublicKeyPem".
      const publicKeyPEM = attestationResult.authnrData.get(
        "credentialPublicKeyPem"
      );
      if (!publicKeyPEM) {
        throw new Error("Public Key konnte nicht extrahiert werden.");
      }
      await saveUserToDB({
        username,
        credentialId: credential.id.toString(), // Als Base64URL‑String
        publicKey: publicKeyPEM, // Hier wird der extrahierte Public Key gespeichert
        counter: 0,
      });
      console.log("User erstellt für:", username);
    } else {
      console.log("User bereits vorhanden:", existingUser);
    }
    return attestationResult;
  } catch (error) {
    console.error("❌ Fehler bei fido2.attestationResult():", error);
    throw new Error("Fehler beim Verifizieren der Registrierung.");
  }
}

/**
 * Authentifizierung: Optionen für FIDO2-Login generieren.
 * Diese Funktion ruft fido2.assertionOptions() auf, speichert die Challenge und
 * setzt allowCredentials, falls der User in der Datenbank gefunden wird.
 * Wird kein registrierter User gefunden, wird ein Fehler geworfen.
 */
export async function generateAuthenticationOptions(
  username: string
): Promise<PublicKeyCredentialRequestOptions> {
  console.log("Erstelle Authentifizierungsoptionen für:", username);
  const options = await fido2.assertionOptions();
  console.log("FIDO2 assertionOptions erhalten:", options);

  // Konvertiere die generierte Challenge in einen Base64URL-String
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  console.log("Generierte Challenge (Base64URL):", challengeBase64);
  storeChallenge(username, challengeBase64);

  // Suche in der Datenbank nach dem registrierten User
  const user = await User.findOne({ username });
  console.log("Geladener User aus der DB:", user);
  if (!user) {
    // Wenn kein registrierter User gefunden wird, werfen wir einen Fehler.
    console.error("Kein registrierter User gefunden für:", username);
    throw new Error("Kein registrierter User gefunden.");
  }
  console.log("User gefunden für allowCredentials:", user);
  options.allowCredentials = [
    {
      type: "public-key",
      id: base64UrlToArrayBuffer(user.credentialId),
      // Cast explizit auf AuthenticatorTransport[] (iOS-Typ)
      transports: ["internal"] as AuthenticatorTransport[],
    },
  ];
  console.log("allowCredentials gesetzt:", options.allowCredentials);

  // Ergänze die Antwort um zusätzliche Felder, die der Client erwartet:
  const responseOptions = {
    ...options,
    challenge: challengeBase64, // Überschreibt die originale ArrayBuffer-Challenge
    rp: { name: "LocalKeyApp" }, // Dummy-Daten, ggf. anpassen
    user: { id: username, name: username },
  };

  console.log("Authentifizierungsoptionen:", responseOptions);
  return responseOptions as any;
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
  const user = await User.findOne({ username });
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
    // Aktualisiere den Counter in der DB mithilfe der update-Funktion
    await updateUserCounter(
      username,
      assertionResult.authnrData.get("counter") || user.counter
    );
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
