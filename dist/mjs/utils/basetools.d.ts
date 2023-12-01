export declare const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/**
 * Encodes a Uint8Array of bytes using Base58 encoding (specifically designed for Bitcoin addresses).
 * @param {Uint8Array} bytes - The Uint8Array of bytes to encode.
 * @returns {string} The Base58-encoded string representation of the input bytes.
 */
export declare function encodeBase58BTC(bytes: Uint8Array): string;
/**
 * Decodes a Base58btc string into a Uint8Array.
 * @param str The Base58btc encoded string to decode.
 * @returns A Uint8Array containing the decoded bytes.
 * @throws Error if the input string is not a valid Base58btc string.
 */
export declare function decodeBase58BTC(str: string): Uint8Array;
export declare const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/**
 * Encodes data using the Base32 encoding scheme based on the RFC 4648 specification.
 * @param data - The input data to be encoded as a Uint8Array.
 * @returns The Base32 encoded string.
 */
export declare function encodeBase32RFC(data: Uint8Array): string;
/**
 * Decodes a string encoded in Base32 RFC 4648 format into a Uint8Array.
 * @param encoded The Base32 encoded string to decode.
 * @returns A Uint8Array containing the decoded bytes.
 */
export declare function decodeBase32RFC(encoded: string): Uint8Array;
/**
 * Encodes a Uint8Array into a Base64URL string.
 * @param input - The Uint8Array to be encoded.
 * @returns The Base64URL-encoded string.
 */
export declare function encodeBase64URL(input: Uint8Array): string;
/**
 * Decodes a Base64 URL-encoded string into a Uint8Array object.
 * @param input - The Base64 URL-encoded string to decode.
 * @returns A Uint8Array object containing the decoded binary data.
 */
export declare function decodeBase64URL(input: string): Uint8Array;
//# sourceMappingURL=basetools.d.ts.map