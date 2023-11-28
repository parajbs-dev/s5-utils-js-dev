import { Buffer } from "buffer";
/**
 * Prepends the prefix to the given string only if the string does not already start with the prefix.
 * @param str - The string.
 * @param prefix - The prefix.
 * @returns - The prefixed string.
 */
export function ensurePrefix(str, prefix) {
    if (!str.startsWith(prefix)) {
        str = `${prefix}${str}`;
    }
    return str;
}
/**
 * Removes a prefix from the beginning of the string.
 * @param str - The string to process.
 * @param prefix - The prefix to remove.
 * @param [limit] - Maximum amount of times to trim. No limit by default.
 * @returns - The processed string.
 */
export function trimPrefix(str, prefix, limit) {
    while (str.startsWith(prefix)) {
        if (limit !== undefined && limit <= 0) {
            break;
        }
        str = str.slice(prefix.length);
        if (limit) {
            limit -= 1;
        }
    }
    return str;
}
/**
 * Removes a suffix from the end of the string.
 * @param str - The string to process.
 * @param suffix - The suffix to remove.
 * @param [limit] - Maximum amount of times to trim. No limit by default.
 * @returns - The processed string.
 */
export function trimSuffix(str, suffix, limit) {
    while (str.endsWith(suffix)) {
        if (limit !== undefined && limit <= 0) {
            break;
        }
        str = str.substring(0, str.length - suffix.length);
        if (limit) {
            limit -= 1;
        }
    }
    return str;
}
/**
 * Convert a byte array to a hex string.
 * @param byteArray - The byte array to convert.
 * @returns - The hex string.
 * @see {@link https://stackoverflow.com/a/44608819|Stack Overflow}
 */
export function toHexString(byteArray) {
    let s = "";
    byteArray.forEach(function (byte) {
        s += ("0" + (byte & 0xff).toString(16)).slice(-2);
    });
    return s;
}
/**
 * Converts a UTF-8 string to a uint8 array containing valid UTF-8 bytes.
 * @param str - The string to convert.
 * @returns - The uint8 array.
 */
export function stringToUint8ArrayUtf8(str) {
    return Uint8Array.from(Buffer.from(str));
}
/**
 * Converts a uint8 array containing valid utf-8 bytes to a string.
 * @param array - The uint8 array to convert.
 * @returns - The string.
 */
export function uint8ArrayToStringUtf8(array) {
    return Buffer.from(array).toString("utf-8");
}
/**
 * Encodes a Unicode string as UTF-8 and returns it as a Uint8Array.
 * @param inputString The string to encode.
 * @returns A Uint8Array containing the UTF-8 encoded bytes.
 */
export function encodeUtf8String(inputString) {
    const encoder = new TextEncoder();
    return encoder.encode(inputString);
}
/**
 * Generates a random string of the specified length.
 * @param length - The length of the random string to generate.
 * @returns The generated random string.
 */
export function generateRandomString(length) {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return typeof btoa === 'function'
        ? btoa(result)
        : Buffer.from(result).toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
}
