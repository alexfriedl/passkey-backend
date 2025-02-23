import cbor from 'cbor';

export async function adjustAttestationObject(attestationObjectBase64: string): Promise<string> {
  // Dekodiere den Base64-String in einen Buffer
  const attestationBuffer = Buffer.from(attestationObjectBase64, 'base64');
  // Dekodiere den CBOR-Block
  const attestation: any = await cbor.decodeFirst(attestationBuffer);
  // Prüfe das Feld "fmt"
  if (attestation.fmt === "apple-appattest") {
    console.log("[DEBUG] Attestation-Format 'apple-appattest' gefunden, setze auf 'none'");
    attestation.fmt = "none";
  }
  // Encodiere das Objekt wieder in CBOR
  const newAttestationBuffer = cbor.encode(attestation);
  // Gebe den neuen CBOR-Block als Base64-String zurück
  return newAttestationBuffer.toString('base64');
}