import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import bodyParser from "body-parser";
import {
  generateRegistrationOptions,
  verifyRegistration,
  generateAuthenticationOptions,
  verifyAuthentication,
} from "./webauthn";
import { saveUser, getUser } from "./database";
import { WebAuthnUser } from "./types";
import { AttestationResult, AssertionResult } from "fido2-lib";

const app = express();
app.use(cors());
app.use(bodyParser.json());

/**
 * Middleware to catch async errors in Express
 */
const asyncHandler =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve(fn(req, res, next)).catch(next);

/**
 * 1️⃣ Register: Generate Challenge & Options
 */
app.post(
  "/register",
  asyncHandler(async (req: Request, res: Response) => {
    const { username } = req.body as { username: string };
    if (!username) {
      res.status(400).json({ error: "Kein Benutzername angegeben" });
      return;
    }

    const options = await generateRegistrationOptions(username);
    const challengeBase64 = Buffer.from(
      new Uint8Array(options.challenge)
    ).toString("base64");

    const user: WebAuthnUser = {
      id: username,
      name: username,
      displayName: username,
      challenge: challengeBase64,
    };

    saveUser(username, user);
    res.json(options);
  })
);

/**
 * 2️⃣ Register: Verify Attestation & Store Credential
 */
app.post(
  "/register/response",
  asyncHandler(async (req: Request, res: Response) => {
    const { username, credential } = req.body as {
      username: string;
      credential: {
        id: string;
        rawId: string;
        response: {
          clientDataJSON: string;
          attestationObject?: string;
        };
      };
    };

    const user: WebAuthnUser | null = getUser(username);
    if (!user) {
      res.status(400).json({ error: "User nicht gefunden" });
      return;
    }

    if (!user.challenge) {
      res.status(400).json({ error: "Challenge nicht gefunden" });
      return;
    }

    const attestationObjectStr = credential.response.attestationObject ?? "";

    const formattedCredential: AttestationResult = {
      ...credential,
      id: Buffer.from(credential.id, "base64"),
      rawId: Buffer.from(credential.rawId, "base64"),
      response: {
        clientDataJSON: Buffer.from(
          credential.response.clientDataJSON,
          "base64"
        ).toString("utf8"),
        attestationObject: Buffer.from(attestationObjectStr, "base64").toString(
          "utf8"
        ),
      },
    };

    const verification = await verifyRegistration(
      formattedCredential,
      user.challenge
    );

    if (verification.success) {
      user.publicKey =
        Object.values(verification.credential ?? {})[0]?.publicKey ?? "";
      saveUser(username, user);
      res.json({ success: true });
    } else {
      console.log({ verification });
      res.status(400).json({ error: "Verifikation fehlgeschlagen" });
    }
  })
);

/**
 * 3️⃣ Authenticate: Generate Challenge for Authentication
 */
app.post(
  "/authenticate",
  asyncHandler(async (req: Request, res: Response) => {
    const { username } = req.body;
    const user = getUser(username);
    if (!user || !user.publicKey) {
      res.status(400).json({ error: "User nicht registriert" });
      return;
    }

    const options = await generateAuthenticationOptions(user.publicKey);
    const challengeBase64 = Buffer.from(
      new Uint8Array(options.challenge)
    ).toString("base64");

    saveUser(username, { challenge: challengeBase64 });
    res.json(options);
  })
);

/**
 * 4️⃣ Authenticate: Verify Assertion & Validate User
 */
app.post(
  "/authenticate/response",
  asyncHandler(async (req: Request, res: Response) => {
    const { username, assertion } = req.body as {
      username: string;
      assertion: {
        id: string;
        rawId: string;
        response: {
          clientDataJSON: string;
          authenticatorData: string;
          signature: string;
        };
      };
    };

    const user = getUser(username);
    if (!user || !user.challenge) {
      res.status(400).json({ error: "User oder Challenge nicht gefunden" });
      return;
    }

    const formattedAssertion: AssertionResult = {
      ...assertion,
      id: Buffer.from(assertion.id, "base64"),
      rawId: Buffer.from(assertion.rawId, "base64"),
      response: {
        clientDataJSON: Buffer.from(
          assertion.response.clientDataJSON,
          "base64"
        ).toString("utf8"),
        authenticatorData: Buffer.from(
          assertion.response.authenticatorData,
          "base64"
        ),
        signature: Buffer.from(assertion.response.signature, "base64").toString(
          "utf8"
        ),
      },
    };

    const verification = await verifyAuthentication(
      formattedAssertion,
      user.publicKey!,
      user.challenge
    );

    if (verification.success) {
      res.json({ success: true, message: "User authenticated!" });
    } else {
      res.status(400).json({ error: "Authentifizierung fehlgeschlagen" });
    }
  })
);

/**
 * Global Error Handler Middleware
 */
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error("🔥 Server Error:", err);
  res
    .status(500)
    .json({ error: "Interner Serverfehler", details: err.message });
});

app.listen(3000, () => console.log("✅ WebAuthn-Server läuft auf Port 3000"));
