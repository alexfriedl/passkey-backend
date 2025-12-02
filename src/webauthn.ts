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
  return Buffer.from(new Uint8Array(buffer)).toString('base64');
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
const rpId = process.env.RPID || "localhost";
console.log("🔧 WebAuthn rpId configured as:", rpId);
const fido2 = new Fido2Lib({
  timeout: 60000,
  rpId: rpId,
  rpName: "LocalKeyApp",
  // rpIcon: optional, falls benötigt
  challengeSize: 32,
  authenticatorAttachment: "platform", // Plattform-Authenticator (z. B. Secure Enclave)
  authenticatorRequireResidentKey: false, // Erzwinge keinen resident key, damit iOS den Standard-Flow nutzt
  authenticatorUserVerification: "required", // Der Nutzer muss sich verifizieren (z. B. via Face ID/Touch ID)
  attestation: "none", // Privacy-first: iOS liefert meist 'none' Format
  cryptoParams: [-7], // ES256 (ECDSA P-256)
});

// Android Direct Attestation Configuration
const fido2AndroidDirect = new Fido2Lib({
  timeout: 60000,
  rpId: rpId,
  rpName: "LocalKeyApp",
  challengeSize: 32,
  authenticatorAttachment: "platform",
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "required",
  attestation: "direct", // Direct attestation für Android
  cryptoParams: [-7, -35, -257], // ES256, Ed25519, RS256
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
    rp: {
      name: "LocalKeyApp",
      id: rpId  // Use the configured rpId
    },
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
 * Android Direct Attestation: Optionen für FIDO2-Passkey-Registrierung mit direct attestation
 */
export async function generateAndroidDirectRegistrationOptions(
  username: string
): Promise<PublicKeyCredentialCreationOptions> {
  // Verwende Android Direct Attestation Konfiguration
  const options = await fido2AndroidDirect.attestationOptions();
  console.log("[Log] Android Direct Challenge (Base64URL): " + arrayBufferToBase64(options.challenge));

  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  console.log("[Log] Android Direct Challenge als ArrayBuffer (Base64): " + arrayBufferToBase64(options.challenge));
  storeChallenge(username, challengeBase64);

  const userIdBuffer = randomBytes(16);
  const userIdBase64 = arrayBufferToBase64Url(userIdBuffer);

  const response: PublicKeyCredentialCreationOptions = {
    ...options,
    rp: {
      name: "LocalKeyApp",
      id: rpId
    },
    challenge: challengeBase64,
    user: {
      id: userIdBase64,
      name: username,
      displayName: username,
    },
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      requireResidentKey: false,
      userVerification: "required",
    },
    attestation: "direct", // Explizit direct attestation anfordern
  };

  return response;
}

/**
 * Registrierung: FIDO2-Passkey-Registrierung verifizieren.
 * Nach erfolgreicher Verifikation wird der User in der MongoDB gespeichert.
 */
export async function verifyRegistration(
  credential: any,
  username: string
): Promise<Fido2AttestationResult> {
  console.log("\n🔍 DEBUG: === verifyRegistration START ===");
  console.log("🔍 DEBUG: Username:", username);
  console.log("🔍 DEBUG: Credential keys:", Object.keys(credential));
  console.log("🔍 DEBUG: Response keys:", credential.response ? Object.keys(credential.response) : 'No response object');
  
  // Log raw attestation object
  if (credential.response && credential.response.attestationObject) {
    console.log("🔍 DEBUG: Raw attestationObject base64 length:", credential.response.attestationObject.length);
    console.log("🔍 DEBUG: Raw attestationObject base64 (first 200 chars):", credential.response.attestationObject.substring(0, 200) + "...");
  }
  
  username = username.trim();
  const challengeBase64 = await getChallenge(username);
  if (!challengeBase64) {
    throw new Error("Challenge nicht gefunden oder abgelaufen.");
  }
  console.log("🔄 Geladene Challenge:", challengeBase64);
  // Don't delete challenge yet - might need it for iOS fallback

  // Konvertiere id und rawId in ArrayBuffer
  credential.rawId = base64UrlToArrayBuffer(credential.rawId);
  credential.id = base64UrlToArrayBuffer(credential.id);

  // Add detailed logging before calling fido2.attestationResult
  console.log("\n🔍 DEBUG: About to call fido2.attestationResult with:");
  console.log("🔍 DEBUG: - challenge:", challengeBase64);
  console.log("🔍 DEBUG: - origin:", process.env.ORIGIN || `https://${rpId}`);
  console.log("🔍 DEBUG: - factor:", "either");
  
  // Decode and log attestation object before passing to fido2-lib
  if (credential.response && credential.response.attestationObject) {
    try {
      const attestationBuffer = Buffer.from(credential.response.attestationObject, 'base64');
      const attestationObject = cbor.decodeFirstSync(attestationBuffer);
      
      console.log("\n🔍 DEBUG: Pre-fido2-lib attestation object analysis:");
      console.log("🔍 DEBUG: - fmt:", attestationObject.fmt);
      console.log("🔍 DEBUG: - attStmt keys:", Object.keys(attestationObject.attStmt || {}));
      
      if (attestationObject.attStmt && attestationObject.attStmt.dcAppAttest) {
        console.log("🔍 DEBUG: ✅ dcAppAttest present before fido2-lib processing");
        console.log("🔍 DEBUG: - dcAppAttest size:", attestationObject.attStmt.dcAppAttest.length, "bytes");
      } else {
        console.log("🔍 DEBUG: ❌ dcAppAttest NOT present before fido2-lib processing");
      }
    } catch (e) {
      console.log("🔍 DEBUG: Could not pre-analyze attestation object:", e);
    }
  }
  
  try {
    // Direkte Verifikation ohne Patching
    const attestationResult = await fido2.attestationResult(credential, {
      challenge: challengeBase64,
      origin: process.env.ORIGIN || `https://${rpId}`,
      factor: "either",
    });
    console.log("✅ Registrierung erfolgreich:", attestationResult);
    
    // Only delete challenge after successful verification
    deleteChallenge(username);

    // Nach erfolgreicher Registrierung: Prüfe, ob der User bereits existiert und speichere (falls nicht)
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      const publicKeyPEM = attestationResult.authnrData.get(
        "credentialPublicKeyPem"
      );
      if (!publicKeyPEM) {
        throw new Error("Public Key konnte nicht extrahiert werden.");
      }
      await saveUserToDB({
        username,
        credentialId: credential.id.toString(), // Als Base64URL‑String
        publicKey: publicKeyPEM,
        counter: 0,
      });
      console.log("User erstellt für:", username);
    } else {
      console.log("User bereits vorhanden:", existingUser);
    }
    return attestationResult;
  } catch (error) {
    console.error("❌ Fehler bei fido2.attestationResult():", error);
    // Re-throw the original error so we can detect clientDataJSON parsing errors
    throw error;
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
  await storeChallenge(username, challengeBase64);

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
  const challengeBase64 = await getChallenge(username);
  if (!challengeBase64) {
    throw new Error("Challenge nicht gefunden oder abgelaufen.");
  }
  await deleteChallenge(username);
  const user = await User.findOne({ username });
  if (!user) {
    throw new Error("User not found.");
  }
  
  // Use publicKey from database if not provided in request
  const userPublicKey = publicKey || user.publicKey;
  if (!userPublicKey) {
    throw new Error("PublicKey nicht gefunden.");
  }
  
  try {
    console.log('fido2.assertionResult called with:', {
      challenge: challengeBase64,
      origin: `https://${rpId}`,
      factor: "either",
      publicKey: userPublicKey?.substring(0, 50) + '...',
      prevCounter: user.counter,
      userHandle: null,
    });
    
    const assertionResult = await fido2.assertionResult(assertion, {
      challenge: challengeBase64,
      origin: `https://${rpId}`,
      factor: "either",
      publicKey: userPublicKey,
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
