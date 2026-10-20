// AES-256-GCM with a PBKDF2-SHA256 key. Same code runs in the browser and in Node (globalThis.crypto).
const enc = new TextEncoder();
const dec = new TextDecoder();
export const ITERATIONS = 600000;

const toB64 = buf => {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function deriveKey(passphrase, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function encryptJSON(value, passphrase, iterations = ITERATIONS) {
  if (!passphrase) throw new Error("encryptJSON: passphrase is required");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, iterations);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(value)));
  return { v: 1, kdf: "PBKDF2-SHA256", iterations, salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) };
}

export async function decryptJSON(payload, passphrase) {
  if (!payload || payload.v !== 1) throw new Error("decryptJSON: unsupported payload version");
  const key = await deriveKey(passphrase, fromB64(payload.salt), payload.iterations);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(payload.iv) }, key, fromB64(payload.ct));
  return JSON.parse(dec.decode(pt));
}
