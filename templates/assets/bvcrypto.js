/*
 * BitVault client-side ("secret") encryption helpers.
 *
 * Format v2 (everything created from now on):
 *   key  = PBKDF2-HMAC-SHA256(password, salt, 600 000 iterations) -> AES-256 key
 *   data = AES-256-GCM(key, random 96-bit IV)            -> authenticated ciphertext
 *   strings: "v2.<salt b64>.<iv b64>.<ciphertext b64>"
 *   files:   "BVE2" + salt(16) + iv(12) + ciphertext      (raw bytes, no hex)
 *
 * One salt is used per upload so the (slow, deliberate) key derivation runs
 * once; every string/file still gets its own random IV.
 *
 * Legacy format v1 (uploads made before this file existed) was AES-128-CTR
 * with the password itself padded to 32 bytes as key, a fixed counter, and
 * hex output. It is only ever *decrypted* here, through aes.js, so that old
 * uploads keep working. It is never produced any more.
 *
 * Uses window.crypto.subtle, which browsers only expose in secure contexts
 * (HTTPS or localhost). available() tells the pages whether they can offer
 * secret mode at all.
 */
const BVCrypto = (() => {
  const PBKDF2_ITERATIONS = 600000;
  const STRING_PREFIX = "v2.";
  const FILE_MAGIC = [0x42, 0x56, 0x45, 0x32]; // "BVE2"
  const SALT_LEN = 16;
  const IV_LEN = 12;
  const LEGACY_MARKER = "!0K";

  const te = new TextEncoder();
  const td = new TextDecoder();
  const keyCache = new Map();

  function available() {
    return typeof crypto !== "undefined" && !!crypto.subtle && !!crypto.getRandomValues;
  }

  function requireSubtle() {
    if (!available()) {
      throw new Error(
        "Client-side encryption needs a secure context (HTTPS or localhost): " +
        "this browser does not expose window.crypto.subtle here."
      );
    }
  }

  function bytesToBase64(bytes) {
    let bin = "";
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomBytes(n) {
    requireSubtle();
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }

  function newSalt() {
    return randomBytes(SALT_LEN);
  }

  // Random per-upload key handed to the server for its own encryption layer.
  function randomKeyHex() {
    return Array.from(randomBytes(16), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function deriveKey(password, salt) {
    requireSubtle();
    const cacheId = bytesToBase64(salt) + "\u0000" + password;
    if (keyCache.has(cacheId)) return keyCache.get(cacheId);
    const baseKey = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    keyCache.set(cacheId, key);
    return key;
  }

  async function gcmEncrypt(password, salt, plaintextBytes) {
    const key = await deriveKey(password, salt);
    const iv = randomBytes(IV_LEN);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes));
    return { iv, ct };
  }

  // Returns null on wrong password / tampered data (GCM tag mismatch).
  async function gcmDecrypt(password, salt, iv, ct) {
    const key = await deriveKey(password, salt);
    try {
      return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
    } catch (_) {
      return null;
    }
  }

  // ---- strings -------------------------------------------------------------

  async function encryptString(password, plaintext, salt) {
    salt = salt || newSalt();
    const { iv, ct } = await gcmEncrypt(password, salt, te.encode(plaintext));
    return STRING_PREFIX + bytesToBase64(salt) + "." + bytesToBase64(iv) + "." + bytesToBase64(ct);
  }

  function isLegacyString(data) {
    return !data.startsWith(STRING_PREFIX);
  }

  async function decryptString(password, data) {
    if (isLegacyString(data)) return legacyDecryptString(password, data);
    const parts = data.split(".");
    if (parts.length !== 4) return null;
    let salt, iv, ct;
    try {
      salt = base64ToBytes(parts[1]);
      iv = base64ToBytes(parts[2]);
      ct = base64ToBytes(parts[3]);
    } catch (_) {
      return null;
    }
    const plain = await gcmDecrypt(password, salt, iv, ct);
    return plain === null ? null : td.decode(plain);
  }

  // ---- files ---------------------------------------------------------------

  async function encryptBytes(password, bytes, salt) {
    salt = salt || newSalt();
    const { iv, ct } = await gcmEncrypt(password, salt, bytes);
    const out = new Uint8Array(FILE_MAGIC.length + SALT_LEN + IV_LEN + ct.length);
    out.set(FILE_MAGIC, 0);
    out.set(salt, FILE_MAGIC.length);
    out.set(iv, FILE_MAGIC.length + SALT_LEN);
    out.set(ct, FILE_MAGIC.length + SALT_LEN + IV_LEN);
    return out;
  }

  function isLegacyBytes(bytes) {
    if (bytes.length < FILE_MAGIC.length) return true;
    return FILE_MAGIC.some((b, i) => bytes[i] !== b);
  }

  async function decryptBytes(password, bytes) {
    if (isLegacyBytes(bytes)) return legacyDecryptBytes(password, bytes);
    let off = FILE_MAGIC.length;
    const salt = bytes.subarray(off, off + SALT_LEN); off += SALT_LEN;
    const iv = bytes.subarray(off, off + IV_LEN); off += IV_LEN;
    return gcmDecrypt(password, salt, iv, bytes.subarray(off));
  }

  // ---- legacy v1 (decrypt only) -------------------------------------------

  function legacyCtr(password) {
    if (typeof aesjs === "undefined") throw new Error("aes.js is required to read legacy uploads");
    const passwordBytes = aesjs.utils.utf8.toBytes(password.padStart(32, "#"));
    return new aesjs.ModeOfOperation.ctr(passwordBytes);
  }

  function legacyDecryptString(password, encryptedHex) {
    try {
      const decrypted = legacyCtr(password).decrypt(aesjs.utils.hex.toBytes(encryptedHex));
      const res = aesjs.utils.utf8.fromBytes(decrypted);
      return res.endsWith(LEGACY_MARKER) ? res.slice(0, -LEGACY_MARKER.length) : null;
    } catch (_) {
      return null;
    }
  }

  // Legacy files were uploaded as hex *text*; the server hands them back as
  // the bytes of that text.
  function legacyDecryptBytes(password, bytes) {
    try {
      const hex = td.decode(bytes).trim();
      if (!/^[0-9a-fA-F]*$/.test(hex)) return null;
      return legacyCtr(password).decrypt(aesjs.utils.hex.toBytes(hex));
    } catch (_) {
      return null;
    }
  }

  return {
    available,
    newSalt,
    randomKeyHex,
    encryptString,
    decryptString,
    encryptBytes,
    decryptBytes,
    isLegacyString,
  };
})();
