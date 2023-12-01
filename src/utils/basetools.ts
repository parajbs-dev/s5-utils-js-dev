// Define the Base58 alphabet used for Bitcoin addresses
export const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encodes a Uint8Array of bytes using Base58 encoding (specifically designed for Bitcoin addresses).
 * @param {Uint8Array} bytes - The Uint8Array of bytes to encode.
 * @returns {string} The Base58-encoded string representation of the input bytes.
 */
export function encodeBase58BTC(bytes: Uint8Array): string {
  const digits: number[] = [0];

  for (let i = 0; i < bytes.length; i++) {
    for (let j = 0; j < digits.length; j++) {
      digits[j] <<= 8;
    }
    digits[0] += bytes[i];

    let carry = 0;
    for (let j = 0; j < digits.length; ++j) {
      digits[j] += carry;
      carry = (digits[j] / 58) | 0;
      digits[j] %= 58;
    }

    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = "";
  while (digits[digits.length - 1] === 0) {
    digits.pop();
  }

  for (let i = digits.length - 1; i >= 0; i--) {
    result += ALPHABET[digits[i]];
  }

  return result;
}

/**
 * Decodes a Base58btc string into a Uint8Array.
 * @param str The Base58btc encoded string to decode.
 * @returns A Uint8Array containing the decoded bytes.
 * @throws Error if the input string is not a valid Base58btc string.
 */
export function decodeBase58BTC(str: string): Uint8Array {
  if (str[0] === "z") {
    str = str.substring(1);
  }

  const bytes: number[] = [];

  for (let i = 0; i < str.length; i++) {
    let value = ALPHABET.indexOf(str[i]);
    if (value === -1) {
      throw new Error("Invalid Base58Bitcoin string");
    }

    for (let j = 0; j < bytes.length; j++) {
      value += bytes[j] * 58;
      bytes[j] = value & 0xff;
      value >>= 8;
    }

    while (value > 0) {
      bytes.push(value & 0xff);
      value >>= 8;
    }
  }

  bytes.reverse();
  return new Uint8Array(bytes);
}

// Base32 RFC 4648 Alphabet
export const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Encodes data using the Base32 encoding scheme based on the RFC 4648 specification.
 * @param data - The input data to be encoded as a Uint8Array.
 * @returns The Base32 encoded string.
 */
export function encodeBase32RFC(data: Uint8Array): string {
  let result = "";
  let bits = 0;
  let value = 0;

  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i];
    bits += 8;

    while (bits >= 5) {
      const index = (value >>> (bits - 5)) & 31;
      result += BASE32_ALPHABET.charAt(index);
      bits -= 5;
    }
  }

  if (bits > 0) {
    const index = (value << (5 - bits)) & 31;
    result += BASE32_ALPHABET.charAt(index);
  }

  return result.toLowerCase();
}

/**
 * Decodes a string encoded in Base32 RFC 4648 format into a Uint8Array.
 * @param encoded The Base32 encoded string to decode.
 * @returns A Uint8Array containing the decoded bytes.
 */
export function decodeBase32RFC(encoded: string): Uint8Array {
  if (encoded[0] === "B" && /[A-Z]/.test(encoded)) {
    encoded = encoded.toLowerCase();
    encoded = encoded.substring(1);
  }

  if (encoded[0] === "b" && /[a-z]/.test(encoded)) {
    encoded = encoded.substring(1);
  }

  if (/[a-z]/.test(encoded)) {
    encoded = encoded.toUpperCase();
  }

  const result = new Uint8Array(Math.ceil((encoded.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < encoded.length; i++) {
    const c = encoded.charAt(i);
    const charIndex = BASE32_ALPHABET.indexOf(c);

    value = (value << 5) | charIndex;
    bits += 5;

    if (bits >= 8) {
      result[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  return result.subarray(0, index);
}

/**
 * Encodes a Uint8Array into a Base64URL string.
 * @param input - The Uint8Array to be encoded.
 * @returns The Base64URL-encoded string.
 */
export function encodeBase64URL(input: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...input));

  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Decodes a Base64 URL-encoded string into a Uint8Array object.
 * @param input - The Base64 URL-encoded string to decode.
 * @returns A Uint8Array object containing the decoded binary data.
 */
export function decodeBase64URL(input: string): Uint8Array {
  if (input[0] === "u") {
    input = input.substring(1);
  }

  input = input.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = input.length % 4;

  if (paddingLength > 0) {
    input += "=".repeat(4 - paddingLength);
  }

  const base64 = atob(input);
  const output = new Uint8Array(base64.length);

  for (let i = 0; i < base64.length; i++) {
    output[i] = base64.charCodeAt(i);
  }

  return output;
}

