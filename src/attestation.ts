import cbor from "cbor";

/**
 * Adjusts the attestationObject for a "none" attestation.
 * Falls das ursprüngliche fmt "apple-appattest" ist, wird es auf "none" gesetzt
 * und der attStmt entfernt (oder als leeres Objekt gesetzt).
 *
 * @param attestationObject - Das ursprüngliche attestationObject als ArrayBuffer oder Buffer.
 * @returns Das angepasste attestationObject als ArrayBuffer.
 */
export function adjustAttestationObject(attestationObject: ArrayBuffer | Buffer): ArrayBuffer {
  // Stelle sicher, dass wir mit einem Buffer arbeiten
  const buffer = Buffer.isBuffer(attestationObject)
    ? attestationObject
    : Buffer.from(attestationObject);
  console.log("[attestation.ts] Original attestationObject Buffer:", buffer);

  let decoded: any;
  try {
    // CBOR-Dekodierung (decodeAllSync gibt ein Array zurück)
    const decodedArray = cbor.decodeAllSync(buffer);
    if (!decodedArray || decodedArray.length === 0) {
      throw new Error("CBOR-Decodierung ergab kein Ergebnis.");
    }
    decoded = decodedArray[0];
    console.log("[attestation.ts] Decodiertes Attestation-Objekt:", decoded);
  } catch (err) {
    console.error("[attestation.ts] Fehler beim CBOR-Dekodieren:", err);
    throw err;
  }

  // Debug-Ausgabe des ursprünglichen fmt
  console.log("[attestation.ts] Original fmt:", decoded.fmt);

  // Falls das Format "apple-appattest" ist, anpassen:
  if (decoded.fmt === "apple-appattest") {
    console.log("[attestation.ts] fmt ist 'apple-appattest' – setze auf 'none' und entferne attStmt.");
    decoded.fmt = "none";
    // Setze attStmt auf ein leeres Objekt (alternativ: delete decoded.attStmt;)
    decoded.attStmt = {};
  } else {
    console.log("[attestation.ts] fmt ist nicht 'apple-appattest', keine Anpassung notwendig.");
  }

  // CBOR-Codierung des modifizierten Objekts
  let adjustedBuffer: Buffer;
  try {
    adjustedBuffer = cbor.encode(decoded);
    console.log("[attestation.ts] Angepasster CBOR-Buffer:", adjustedBuffer);
  } catch (err) {
    console.error("[attestation.ts] Fehler beim CBOR-Encodieren:", err);
    throw err;
  }

  // Rückgabe als ArrayBuffer
  const arrayBuffer = Uint8Array.from(adjustedBuffer).buffer;
  console.log("[attestation.ts] Rückgabewert (ArrayBuffer):", arrayBuffer);
  return arrayBuffer;
}
