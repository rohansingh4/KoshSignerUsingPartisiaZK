/**
 * Biometric Key Derivation for Kosh ZK Signer.
 *
 * Same finger → same 32-byte secret → same Ethereum wallet every time.
 *
 * Flow:
 *   1. registerBiometricPasskey() — create passkey with biometric + PRF
 *   2. deriveBiometricSecret() — authenticate with biometric → 32-byte secret
 *   3. derivePartySeeds() — HKDF expand secret → N party seeds for DKG
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

// Salt used for PRF evaluation. Changing this changes the derived wallet.
const PRF_SALT = new TextEncoder().encode("kosh-zk-signer-v1");


export async function isBiometricAvailable(): Promise<boolean> {
  if (
    typeof window === "undefined" ||
    !window.PublicKeyCredential ||
    !navigator.credentials
  ) {
    return false;
  }

  // Check platform authenticator (biometric) availability
  if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!available) return false;
  }

  return true;
}

/**
 * Register a new passkey protected by biometric authentication.
 * Returns the raw credential ID needed for future deriveBiometricSecret() calls.
 *
 * The passkey is synced by the OS (iCloud Keychain / Google Password Manager),
 * but the credentialId must be saved by the application (e.g. localStorage).
 */
export async function registerBiometricPasskey(userId: string): Promise<Uint8Array> {
  const userIdBytes = new TextEncoder().encode(userId);

  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { name: "Kosh ZK Signer" },
      user: {
        id: userIdBytes,
        name: userId,
        displayName: userId,
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [
        { alg: -7, type: "public-key" },   // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "required",
      },
      extensions: {
        prf: {},
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("Passkey registration failed or was cancelled");
  }

  // Verify PRF extension is supported
  const extResults = credential.getClientExtensionResults() as any;
  const prfResult = extResults?.prf;
  if (!prfResult?.enabled) {
    throw new Error(
      "PRF extension not supported by this authenticator. " +
      "Try a device with a newer platform authenticator (iOS 17+, Android 14+, macOS Sonoma+)."
    );
  }

  return new Uint8Array(credential.rawId);
}

/**
 * Authenticate with biometric and derive a deterministic 32-byte secret.
 *
 * Same passkey + same salt → same output every time.
 */
export async function deriveBiometricSecret(
  credentialId: Uint8Array,
  salt: string = "kosh-zk-signer-v1"
): Promise<Uint8Array> {
  const saltBytes = new TextEncoder().encode(salt);

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          id: credentialId as BufferSource,
          type: "public-key" as const,
          transports: ["internal" as AuthenticatorTransport],
        },
      ],
      userVerification: "required",
      extensions: {
        prf: {
          eval: {
            first: saltBytes,
          },
        },
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential;

  if (!assertion) {
    throw new Error("Biometric authentication failed or was cancelled");
  }

  const extResults = assertion.getClientExtensionResults() as any;
  const prfResult = extResults?.prf?.results;
  if (!prfResult?.first) {
    throw new Error(
      "PRF evaluation failed. The authenticator may not support the PRF extension."
    );
  }

  return new Uint8Array(prfResult.first);
}

/**
 * Derive N independent party seeds from a single 32-byte secret using HKDF.
 *
 * HKDF-SHA256(ikm=secret, salt=PRF_SALT, info="kosh-party-{i}") → 32 bytes per party.
 *
 * For single-user demo: one PRF output → multiple DKG party seeds.
 * For production multi-device: each party does their own PRF on their own device.
 */
export function derivePartySeeds(
  secret: Uint8Array,
  numParties: number
): Uint8Array[] {
  const seeds: Uint8Array[] = [];
  for (let i = 0; i < numParties; i++) {
    const info = `kosh-party-${i + 1}`;
    const seed = hkdf(sha256, secret, PRF_SALT, info, 32);
    seeds.push(seed);
  }
  return seeds;
}
