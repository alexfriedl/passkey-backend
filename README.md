# 🚀 Passkey Backend mit WebAuthn

## 📌 **Überblick**
Dieses Projekt ist ein **Passkey-Backend**, das WebAuthn (FIDO2) verwendet, um sichere, passwortlose Anmeldungen zu ermöglichen. Es unterstützt **lokale Tests und die Nutzung von Secure Enclave auf iOS-Geräten**.

## 🎯 **Use Case & Vorteile**
### 🔐 **Use Case:**
- Ermöglicht **sichere, passwortlose Authentifizierung** mit Passkeys.
- Unterstützt **Registrierung & Anmeldung mit Face ID / Touch ID** auf iOS.
- Kann in mobile Apps oder Webanwendungen integriert werden.

### 🌟 **Vorteile:**
✅ **Kein Passwort erforderlich** → Weniger Sicherheitsrisiken.  
✅ **Hohe Sicherheit** → Nutzt Hardware-gestützte Secure Enclave.  
✅ **Einfache Nutzung** → Face ID / Touch ID für Login.  
✅ **Schutz vor Phishing** → Passkeys funktionieren nur mit der richtigen Domain.  

## ✨ Features
✅ Secure **Passkey registration & authentication**  
✅ Uses **fido2-lib** for WebAuthn operations  
✅ Supports **Apple Secure Enclave Attestation**  
✅ No **iCloud sync** – Passkeys are **locally stored**  
✅ Works with **iOS/macOS Passkey AutoFill & WebAuthn**  

---
## 🛠 **Lokale Entwicklung & Tests**

### **1️⃣ Voraussetzungen**
🔹 **Node.js** (mind. v16+) <br>
🔹 **Yarn** (oder npm) <br>
🔹 **ngrok** (zum Testen mit iOS)

### **2️⃣ Setup & Installation**
```sh
# Repository klonen
git clone https://github.com/alexfriedl/passkey-backend.git
cd passkey-backend

# Abhängigkeiten installieren
yarn install  # oder: npm install
```

### **3️⃣ Lokalen Server starten**
```sh
yarn dev  # oder: npm run dev
```
👉 **Server läuft auf:** `http://localhost:3000`

---
## 📲 **iOS-Tests mit Face ID / Touch ID**

### **1️⃣ Backend über ngrok verfügbar machen**
Da WebAuthn eine **registrierbare Domain (kein localhost)** erfordert, nutzen wir `ngrok`:
```sh
ngrok http 3000
```
🔗 **Kopiere die ausgegebene HTTPS-URL**, z. B.: `https://fdb2-xyz.ngrok-free.app`

### **2️⃣ `rp.id` im Code anpassen**
Öffne `src/webauthn.ts` und ändere:
```ts
const rpId = "fdb2-xyz.ngrok-free.app";  // Verwende deine ngrok-URL
```

### **3️⃣ Frontend unter ngrok aufrufen**
Öffne Safari auf dem iPhone:
```
https://fdb2-xyz.ngrok-free.app/register.html
```

👉 **Beim Registrieren Face ID / Touch ID nutzen!** <br>
❌ **Nicht die Passwort-App wählen!**

---
## 📝 **Ablauf der Registrierung mit `register.html`**
1. **Benutzername eingeben** und auf **Registrieren** klicken.
2. Der Client sendet eine Anfrage an `/register`, um die **WebAuthn-Options** zu erhalten.
3. `navigator.credentials.create()` startet die WebAuthn-Registrierung.
4. Der Benutzer authentifiziert sich mit **Face ID / Touch ID**.
5. Das erzeugte **Credential** wird an `/register/verify` gesendet.
6. Der Server validiert das Credential und speichert es.

---
## 📦 **Beispiel einer WebAuthn-Registrierungsanfrage**
Der Browser erhält dieses Objekt vom Server und übergibt es an die Funktion
navigator.credentials.create({ publicKey: options }) um den Erstellungsprozess zu starten.
Dar Ergebnis dieses Prozesses ist das **Credential Objekt**
```json
{
  "rp": {
    "name": "LocalKeyApp",
    "id": "2bfe-2003-ef-a727-8900-c92a-b95e-4072-b72d.ngrok-free.app"
  },
  "user": {
    "id": "d8qZIgZSdNqnvqtO5G8KPQ",
    "name": "Zuzzzzzzz",
    "displayName": "Zuzzzzzzz"
  },
  "challenge": "H9vGdjaNYxt6iNg5H4QNRI0PEcwDtPiBfqM60nNxorE",
  "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
  "timeout": 60000,
  "attestation": "direct",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "required",
    "userVerification": "required"
  }
}
```

---
## 📦 **Beispiel eines Credential Objekts**
Wird nach erfolgreicher Passkey-Erstellung vom Backend an die iOS App übergeben.
Enthält den Public Key als binäre Daten in Form von ArrayBuffers, die für den Sicherheitsnachweis und die Verifizierung der Registrierung verwendet werden.
```json
{
  id: "BeispielCredentialID123",      // String, der die ID repräsentiert
  rawId: ArrayBuffer { … },           // ArrayBuffer, der die binäre Form der ID enthält
  type: "public-key",                 // Immer "public-key"
  response: {
    clientDataJSON: ArrayBuffer { … },    // ArrayBuffer, der die vom Browser generierten Client-Daten enthält
    attestationObject: ArrayBuffer { … }  // ArrayBuffer, der die vom Authenticator erzeugten Attestierungsdaten enthält
  }
}
```

**id:**
Ein String, der die eindeutige Kennung des erzeugten Credentials darstellt.

**rawId:**
Die binäre Darstellung der Credential-ID. Diesen Wert verwendet man häufig in der Kommunikation mit dem Server – dabei muss er meist in ein Base64URL-Format umgewandelt werden.

**type:**
Hier steht immer "public-key", da es sich um ein PublicKeyCredential handelt.

**response:**
Das Response-Objekt enthält zwei wichtige ArrayBuffers:

**clientDataJSON:**
Enthält JSON-Daten (im binären Format), die Informationen wie den Challenge-Parameter, den Ursprungs-URL und den Typ der Anfrage (z. B. "webauthn.create") beinhalten.
attestationObject:
Enthält die vom Authenticator erzeugten Daten, die Details über den neu erstellten Schlüssel, die Attestation und weitere Metadaten beinhalten.

---
## 🔍 **Fehlersuche & Lösungen**

### 🚨 **Error: `clientData origin did not match expected origin`**
✔ **Lösung:** Stelle sicher, dass `rp.id` mit deiner ngrok-URL übereinstimmt.

### 🚨 **Error: `Ungültige Attestation: Nur Apple Secure Enclave wird akzeptiert`**
✔ **Lösung:** Wähle **Face ID / Touch ID** bei der Registrierung statt der Passwort-App.

### 🚨 **Error: `Failed to execute 'create' on 'CredentialsContainer'`**
✔ **Lösung:** Aktiviere **WebAuthn** unter Safari → Einstellungen → **Erweiterte Features**.

---
## 📜 **API-Endpunkte**

### 🔹 **1. Registrierung starten**
**POST** `/register`
```json
{
  "username": "alice"
}
```
🔹 **Antwort:** WebAuthn-Options-Objekt mit `challenge`

### 🔹 **2. Registrierung abschließen**
**POST** `/register/verify`
```json
{
  "username": "alice",
  "credential": { ... }
}
```
🔹 **Antwort:** `{ success: true }` bei Erfolg

### 🔹 **3. Anmeldung starten**
**POST** `/login`
```json
{
  "username": "alice"
}
```
🔹 **Antwort:** WebAuthn-Options-Objekt für Authentifizierung

### 🔹 **4. Anmeldung abschließen**
**POST** `/login/verify`
```json
{
  "username": "alice",
  "assertion": { ... }
}
```
🔹 **Antwort:** `{ success: true }` bei Erfolg

---
## 🐞 **Debugging**
Analyze iOS Frontend Errors with Safari:
![Debugging Safari](image.png)

---
## 🎯 **Zusätzliche Ressourcen**
📖 WebAuthn-Dokumentation: [webauthn.io](https://webauthn.io) <br>
🛠 FIDO2-Spezifikation: [fidoalliance.org](https://fidoalliance.org/specifications/)

---
💡 **Feedback oder Probleme?** Erstelle ein Issue oder PR! 🚀

