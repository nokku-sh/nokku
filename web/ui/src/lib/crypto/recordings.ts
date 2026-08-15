import nacl from 'tweetnacl';

import { recordingPrivateKey } from '$lib/store.svelte';

// Workspace recording key helpers. The daemon seals chunks with NaCl box
// (X25519 + XSalsa20-Poly1305), tweetnacl is the browser-side equivalent of
// Go's golang.org/x/crypto/nacl/box. The private key lives in session
// storage and never leaves this device.

export type RecordingKeyPair = { publicKey: Uint8Array; secretKey: Uint8Array };

export function generateKeyPair(): RecordingKeyPair {
	return nacl.box.keyPair();
}

/** First 16 hex chars of SHA-256, matching the backend's fingerprint. */
export async function fingerprint(pub: Uint8Array): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(pub));
	return hex(new Uint8Array(digest).slice(0, 8));
}

// --- Key lifecycle -------------------------------------------------------

/** The private key stored in this browser session, or null. */
export function getPrivateKey(): Uint8Array | null {
	const stored = recordingPrivateKey.current;
	if (!stored) return null;
	try {
		const key = base64ToBytes(stored);
		return key.length === 32 ? key : null;
	} catch {
		return null;
	}
}

/** Store the private key for this browser session. */
export function setPrivateKey(secretKey: Uint8Array): void {
	if (secretKey.length !== 32) throw new Error('invalid private key length');
	recordingPrivateKey.current = bytesToBase64(secretKey);
}

export function clearPrivateKey(): void {
	recordingPrivateKey.current = '';
}

/** Derive the X25519 public key of a private key, for fingerprint checks. */
export function publicKeyOf(secretKey: Uint8Array): Uint8Array | null {
	try {
		return nacl.box.keyPair.fromSecretKey(secretKey).publicKey;
	} catch {
		return null;
	}
}

/** True when the private key in this browser matches the given fingerprint. */
export async function privateKeyMatches(expectedFingerprint: string): Promise<boolean> {
	return (await privateKeyFor(expectedFingerprint)) !== null;
}

/**
 * The stored private key when it matches the fingerprint, else null. This is
 * the single entry point for decryption, a stale key from an older key
 * generation never reaches unsealing.
 */
export async function privateKeyFor(expectedFingerprint: string): Promise<Uint8Array | null> {
	const key = getPrivateKey();
	if (!key) return null;
	const pub = publicKeyOf(key);
	if (!pub) return null;
	return (await fingerprint(pub)) === expectedFingerprint ? key : null;
}

// --- Sealing / unsealing ------------------------------------------------

// A sealed chunk is [ephemeralPub(32) || nonce(24) || ciphertext]. The
// ciphertext always carries a 16-byte Poly1305 tag, so no valid chunk is
// shorter than 72 bytes.
const SEALED_OVERHEAD = 32 + 24 + nacl.box.overheadLength;

/** Unseal one sealed chunk: [ephemeralPub(32) || nonce(24) || ciphertext]. */
export function unsealChunk(chunk: Uint8Array, secretKey: Uint8Array): Uint8Array | null {
	if (chunk.length < SEALED_OVERHEAD) return null;
	const ephemeralPub = chunk.slice(0, 32);
	const nonce = chunk.slice(32, 56);
	const ciphertext = chunk.slice(56);
	return nacl.box.open(ciphertext, nonce, ephemeralPub, secretKey);
}

/**
 * Unseal a recording stream. The daemon seals each flush batch separately
 * and the backend stores them back-to-back, so the bytes are a sequence of
 * [len(4 BE) || sealed chunk] frames, each opened independently with the
 * workspace private key.
 *
 * Decryption is fast per frame, but a very long recording could hold the
 * main thread for a while. Yield to the browser's event loop every ~2MB so
 * the UI stays responsive while decrypting.
 */
export async function unsealChunks(
	data: Uint8Array,
	secretKey: Uint8Array
): Promise<Uint8Array<ArrayBuffer> | null> {
	const plain: Uint8Array[] = [];
	let off = 0;
	let sinceYield = 0;
	while (off + 4 <= data.length) {
		const len = (data[off] << 24) | (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3];
		if (len < SEALED_OVERHEAD || off + 4 + len > data.length) return null;
		const opened = unsealChunk(data.subarray(off + 4, off + 4 + len), secretKey);
		if (!opened) return null;
		plain.push(opened);
		off += 4 + len;
		sinceYield += len;
		if (sinceYield >= 2 * 1024 * 1024) {
			await new Promise((resolve) => setTimeout(resolve, 0));
			sinceYield = 0;
		}
	}
	if (off !== data.length) return null;
	const total = plain.reduce((n, p) => n + p.length, 0);
	const out = new Uint8Array(total);
	let at = 0;
	for (const p of plain) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

export function hex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export function formatBytes(bytes: number): string {
	if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GiB`;
	if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`;
	if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KiB`;
	return `${bytes} B`;
}
