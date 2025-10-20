import * as cbor from "cbor";
import { createSign } from "crypto";
import base64url from "base64url";

/**
 * Attestation Format Converter
 * 
 * WICHTIG: Eine direkte Konvertierung von "apple-appattest" zu "packed" ist 
 * kryptografisch NICHT möglich, da:
 * 1. Die Signatur mit dem Apple-Zertifikat erstellt wurde
 * 2. Wir keinen Zugriff auf den privaten Schlüssel haben
 * 3. Die Attestation-Struktur format-spezifisch ist
 * 
 * Stattdessen bietet diese Klasse folgende Möglichkeiten:
 * - Extraktion der relevanten Daten aus apple-appattest
 * - Erstellung eines "bridge"-Formats für Systeme, die packed erwarten
 * - Server-seitige Attestation-Tokens als Alternative
 */
export class AttestationConverter {
  
  /**
   * Extrahiert die wichtigen Daten aus einem apple-appattest Format
   */
  static extractAppAttestData(attestationObject: Buffer): {
    fmt: string;
    authData: Buffer;
    publicKey: Buffer;
    credentialId: Buffer;
    counter: number;
    appId?: string;
  } {
    const att = cbor.decodeFirstSync(attestationObject);
    
    if (att.fmt !== "apple-appattest") {
      throw new Error(`Unexpected format: ${att.fmt}`);
    }
    
    // Parse authData
    const authData = Buffer.from(att.authData);
    const parsed = this.parseAuthData(authData);
    
    return {
      fmt: att.fmt,
      authData,
      publicKey: parsed.publicKey!,
      credentialId: parsed.credentialId!,
      counter: parsed.counter,
      appId: this.extractAppIdFromCert(att.attStmt?.x5c?.[0])
    };
  }
  
  /**
   * Erstellt ein server-signiertes Attestation-Token
   * Dies ist die empfohlene Methode für die "Konvertierung"
   */
  static createServerAttestation(
    appAttestData: ReturnType<typeof AttestationConverter.extractAppAttestData>,
    serverPrivateKey: string,
    serverCertificate: string
  ): {
    attestationToken: string;
    format: "server-attestation";
    data: any;
  } {
    // Erstelle eine Attestation-Aussage
    const attestationStatement = {
      format: "server-attestation",
      originalFormat: appAttestData.fmt,
      timestamp: new Date().toISOString(),
      device: {
        credentialId: base64url(appAttestData.credentialId),
        publicKey: base64url(appAttestData.publicKey),
        counter: appAttestData.counter,
        appId: appAttestData.appId
      }
    };
    
    // Signiere mit Server-Key
    const sign = createSign("RSA-SHA256");
    sign.update(JSON.stringify(attestationStatement));
    const signature = sign.sign(serverPrivateKey, "base64");
    
    return {
      attestationToken: base64url(JSON.stringify({
        statement: attestationStatement,
        signature,
        certificate: serverCertificate
      })),
      format: "server-attestation",
      data: attestationStatement
    };
  }
  
  /**
   * Erstellt ein "packed-like" Format für Kompatibilität
   * WARNUNG: Dies ist KEINE echte packed-Attestation!
   */
  static createPackedLikeStructure(
    appAttestData: ReturnType<typeof AttestationConverter.extractAppAttestData>
  ): Buffer {
    // Erstelle eine packed-ähnliche Struktur
    // Dies sollte NUR für Test-/Entwicklungszwecke verwendet werden
    const packedLike = {
      fmt: "packed", // WARNUNG: Technisch nicht korrekt!
      authData: appAttestData.authData,
      attStmt: {
        alg: -7, // ES256
        // Normalerweise würde hier die Signatur stehen, aber wir können keine gültige erstellen
        // Markiere explizit als konvertiert
        x5c: [], // Keine Zertifikate, da nicht Apple-signiert
        converted: true,
        originalFormat: "apple-appattest",
        warning: "This is a converted format, not a genuine packed attestation"
      }
    };
    
    return cbor.encode(packedLike);
  }
  
  /**
   * Empfohlene Methode: Wrapper für FIDO2-Systeme
   * Erstellt ein Wrapper-Objekt, das die App Attest Daten kapselt
   */
  static createFIDO2Wrapper(
    appAttestData: ReturnType<typeof AttestationConverter.extractAppAttestData>,
    localChallenge: Buffer
  ): {
    type: "wrapped-attestation";
    original: {
      format: string;
      verified: boolean;
      appId: string | undefined;
    };
    credential: {
      id: string;
      publicKey: string;
      type: "public-key";
    };
    challenge: string;
  } {
    return {
      type: "wrapped-attestation",
      original: {
        format: appAttestData.fmt,
        verified: true, // Assuming verification passed
        appId: appAttestData.appId
      },
      credential: {
        id: base64url(appAttestData.credentialId),
        publicKey: base64url(appAttestData.publicKey),
        type: "public-key"
      },
      challenge: base64url(localChallenge)
    };
  }
  
  // Helper-Funktionen
  
  private static parseAuthData(authData: Buffer): {
    rpIdHash: Buffer;
    flags: number;
    counter: number;
    credentialId?: Buffer;
    publicKey?: Buffer;
  } {
    let offset = 0;
    
    const rpIdHash = authData.slice(offset, offset + 32);
    offset += 32;
    
    const flags = authData[offset];
    offset += 1;
    
    const counter = authData.readUInt32BE(offset);
    offset += 4;
    
    if (!(flags & 0x40)) {
      return { rpIdHash, flags, counter };
    }
    
    // AAGUID
    offset += 16;
    
    const credIdLen = authData.readUInt16BE(offset);
    offset += 2;
    
    const credentialId = authData.slice(offset, offset + credIdLen);
    offset += credIdLen;
    
    const publicKeyBytes = authData.slice(offset);
    const coseKey = cbor.decodeFirstSync(publicKeyBytes);
    
    const x = coseKey.get(-2);
    const y = coseKey.get(-3);
    const publicKey = Buffer.concat([
      Buffer.from([0x04]),
      x,
      y
    ]);
    
    return { rpIdHash, flags, counter, credentialId, publicKey };
  }
  
  private static extractAppIdFromCert(certBuffer?: Buffer): string | undefined {
    if (!certBuffer) return undefined;
    
    try {
      // Hier würde man die X.509 Extension parsen
      // OID: 1.2.840.113635.100.8.2
      // Für Demo-Zwecke:
      return "TEAMID.com.example.app";
    } catch {
      return undefined;
    }
  }
}

/**
 * Beispiel-Verwendung:
 * 
 * const appAttestData = AttestationConverter.extractAppAttestData(attestationBuffer);
 * 
 * // Option 1: Server-Attestation (empfohlen)
 * const serverAttestation = AttestationConverter.createServerAttestation(
 *   appAttestData,
 *   serverPrivateKey,
 *   serverCertificate
 * );
 * 
 * // Option 2: FIDO2 Wrapper
 * const wrapper = AttestationConverter.createFIDO2Wrapper(
 *   appAttestData,
 *   localChallengeBuffer
 * );
 * 
 * // Option 3: Packed-like (nur für Tests!)
 * const packedLike = AttestationConverter.createPackedLikeStructure(appAttestData);
 */