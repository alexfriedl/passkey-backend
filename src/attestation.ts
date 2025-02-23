import cbor from "cbor";

// Diese Funktion nimmt das CBOR‑codierte Attestation‑Objekt und passt es an,
// falls das Format "apple-appattest" erkannt wird oder "fmt" leer ist.
export function adjustAttestationObject(attestationObjectBuffer: Buffer): any {
  // CBOR-dekodieren
  const attObj = cbor.decodeAllSync(attestationObjectBuffer)[0];

  // Debug: Ausgabe des ursprünglichen fmt-Werts
  console.log("Original fmt:", attObj.fmt);

  // Falls kein fmt vorhanden oder es "apple-appattest" ist, setzen wir auf "none"
  if (!attObj.fmt || attObj.fmt === "" || attObj.fmt === "apple-appattest") {
    // Für den "none"-Flow entfernen wir das attStmt-Objekt, falls vorhanden
    attObj.fmt = "none";
    if (attObj.attStmt) {
      delete attObj.attStmt;
    }
    console.log("Adjusted fmt auf 'none'");
  }

  return attObj;
}
