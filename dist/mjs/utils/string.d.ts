/**
 * Prepends the prefix to the given string only if the string does not already start with the prefix.
 * @param str - The string.
 * @param prefix - The prefix.
 * @returns - The prefixed string.
 */
export declare function ensurePrefix(str: string, prefix: string): string;
/**
 * Removes a prefix from the beginning of the string.
 * @param str - The string to process.
 * @param prefix - The prefix to remove.
 * @param [limit] - Maximum amount of times to trim. No limit by default.
 * @returns - The processed string.
 */
export declare function trimPrefix(str: string, prefix: string, limit?: number): string;
/**
 * Removes a suffix from the end of the string.
 * @param str - The string to process.
 * @param suffix - The suffix to remove.
 * @param [limit] - Maximum amount of times to trim. No limit by default.
 * @returns - The processed string.
 */
export declare function trimSuffix(str: string, suffix: string, limit?: number): string;
/**
 * Convert a byte array to a hex string.
 * @param byteArray - The byte array to convert.
 * @returns - The hex string.
 * @see {@link https://stackoverflow.com/a/44608819|Stack Overflow}
 */
export declare function toHexString(byteArray: Uint8Array): string;
/**
 * Converts a UTF-8 string to a uint8 array containing valid UTF-8 bytes.
 * @param str - The string to convert.
 * @returns - The uint8 array.
 */
export declare function stringToUint8ArrayUtf8(str: string): Uint8Array;
/**
 * Converts a uint8 array containing valid utf-8 bytes to a string.
 * @param array - The uint8 array to convert.
 * @returns - The string.
 */
export declare function uint8ArrayToStringUtf8(array: Uint8Array): string;
/**
 * Encodes a Unicode string as UTF-8 and returns it as a Uint8Array.
 * @param inputString The string to encode.
 * @returns A Uint8Array containing the UTF-8 encoded bytes.
 */
export declare function encodeUtf8String(inputString: string): Uint8Array;
/**
 * Generates a random string of the specified length.
 * @param length - The length of the random string to generate.
 * @returns The generated random string.
 */
export declare function generateRandomString(length: number): string;
//# sourceMappingURL=string.d.ts.map