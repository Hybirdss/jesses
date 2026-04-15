// merkle.mjs
//
// RFC 6962 Merkle tree — byte-exact with Certificate Transparency.
// This is a straight transliteration of internal/merkle/tree.go;
// both implementations hash the same bytes with the same prefix
// bytes in the same order.
//
// Leaf  hash: SHA-256(0x00 || data)
// Node  hash: SHA-256(0x01 || left || right)
// Root:       MTH([]) = SHA-256(empty)
//             MTH([leaf_0 ... leaf_{n-1}]) uses split at largest
//             power of two less than n (see RFC 6962 section 2.1)

import { createHash } from "node:crypto";

export const LEAF_PREFIX = 0x00;
export const NODE_PREFIX = 0x01;

// hashLeaf returns SHA-256(0x00 || data) as a Buffer.
export function hashLeaf(data) {
	const h = createHash("sha256");
	h.update(Buffer.from([LEAF_PREFIX]));
	h.update(data);
	return h.digest();
}

// hashChildren returns SHA-256(0x01 || left || right) as a Buffer.
export function hashChildren(left, right) {
	const h = createHash("sha256");
	h.update(Buffer.from([NODE_PREFIX]));
	h.update(left);
	h.update(right);
	return h.digest();
}

// rootFromLeafHashes returns the MTH (Merkle Tree Hash) of a list of
// pre-hashed leaves. Mirrors Go's merkle.RootFromLeafHashes.
export function rootFromLeafHashes(leafHashes) {
	return mth(leafHashes);
}

function mth(hashes) {
	if (hashes.length === 0) {
		return createHash("sha256").digest();
	}
	if (hashes.length === 1) {
		return hashes[0];
	}
	const k = largestPow2Less(hashes.length);
	return hashChildren(mth(hashes.slice(0, k)), mth(hashes.slice(k)));
}

// largestPow2Less returns the largest power of two strictly less
// than n. For n=1 the function returns 1 (unused — MTH bottoms out
// at the single-leaf case before calling this).
export function largestPow2Less(n) {
	if (n <= 1) return 1;
	let k = 1;
	while (k * 2 < n) k *= 2;
	return k;
}
