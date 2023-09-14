/// <reference types="node" />
import { Buffer } from "buffer";
/**
 * Interface representing a decrypted blob object.
 */
export interface DecryptedBlobObject {
    blob?: Blob;
}
/**
 * Represents the metadata associated with encryption.
 */
export interface EncryptionMetadata {
    algorithm: number;
    chunkSize: number;
    hash: Buffer;
    key: Buffer;
    padding: number;
}
/**
 * Represents the response structure for an encrypted file URL.
 */
export interface EncryptedFileUrlResponse {
    url: string;
    ucid: string;
    hash: string;
    totalsize: number;
    encryptionMetadata?: EncryptionMetadata;
    bytes: Buffer;
}
/**
 * Decrypts a chunk of data using the XChaCha20-Poly1305 encryption scheme.
 * @param {Uint8Array} chunk - The encrypted chunk of data to be decrypted.
 * @param {Uint8Array} key - The encryption key used for decryption.
 * @param {number} chunkIndex - The index of the chunk for generating the nonce.
 * @returns {Promise<Uint8Array>} - The decrypted chunk of data.
 * @throws {Error} - If decryption fails or produces invalid output.
 */
export declare function decryptFileXchacha20(chunk: Uint8Array, key: Uint8Array, chunkIndex: number): Promise<Uint8Array>;
/**
 * Hashes the data from a ReadableStream using the BLAKE3 algorithm.
 * @param stream - The ReadableStream containing the data to be hashed.
 * @returns A Promise that resolves to the hash value as a Uint8Array.
 */
export declare function hashStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array>;
/**
 * Decrypts a stream of data using the XChaCha20 encryption algorithm and additional hashing and validation.
 * @param b3hashStream - The source stream containing the B3hash data.
 * @param clonedStream - The cloned stream for decryption.
 * @param durlEncryptionMetadataHash - The hash used for comparison.
 * @param key - The encryption key.
 * @param chunkSize - The size of data chunks for decryption.
 * @returns A promise that resolves when decryption is completed.
 */
export declare function decryptStream(b3hashStream: ReadableStream<Uint8Array>, clonedStream: ReadableStream<Uint8Array>, durlEncryptionMetadataHash: Buffer, key: Uint8Array, chunkSize: number): Promise<{
    blob: Blob;
}>;
/**
 * Decrypts a file from a response stream and saves it to a specified file path.
 * @param response - The HTTP response containing the encrypted file data.
 * @param durlEncryptionMetadataHash - The hash used for DURL encryption metadata.
 * @param decryptedFilePath - The path where the decrypted file should be saved.
 * @param decryptionKey - The decryption key used to decrypt the file.
 * @param chunkIndex - (Optional) The index of the chunk being decrypted.
 * @returns A Promise that resolves once the file is successfully decrypted and saved.
 */
export declare function decryptFile(response: Response, durlEncryptionMetadataHash: Buffer, decryptedFilePath: string, decryptionKey: Uint8Array, chunkIndex?: number): Promise<{
    blob: Blob;
} | undefined>;
/**
 * Compare two B3 hashes and return the result of the comparison.
 * @param {Buffer} b3hash1 - The first B3 hash to compare.
 * @param {Buffer} b3hash2 - The second B3 hash to compare.
 * @returns {number} - A number indicating the comparison result. Negative value if b3hash1 comes before b3hash2, positive value if b3hash1 comes after b3hash2, and zero if they are equal.
 */
export declare function compareB3hash(b3hash1: Buffer, b3hash2: Buffer): number;
/**
 * Retrieves an encrypted file URL and associated metadata based on the provided encrypted CID.
 * @param encryptedCid The encrypted CID for the file.
 * @param locationsHost The host for fetching streaming locations.
 * @returns A promise that resolves to an `EncryptedFileUrlResponse` containing metadata and the file URL.
 * @throws Error if the CID format is invalid or if the encryption algorithm is not supported.
 */
export declare function getEncryptedFileUrl(encryptedCid: string, locationsHost: string): Promise<EncryptedFileUrlResponse>;
/**
 * Decodes a URL-safe Base64 encoded string into its original data format.
 * @param {string} input - The URL-safe Base64 encoded string to decode.
 * @returns {Buffer} - The decoded data as a Buffer object.
 */
export declare function decodeBase64URL2(input: string): Buffer;
/**
 * Decodes a byte array in little-endian format into a single numeric value.
 * @param {Array} bytes - The byte array to decode, represented as an array of integers.
 * @returns {number} - The decoded numeric value.
 */
export declare function decodeEndian(bytes: Buffer): number;
/**
 * Converts a byte array to a Base64 URL-encoded string without padding characters.
 * @param {Array} hashBytes - The byte array to convert.
 * @returns {string} - The Base64 URL-encoded string without padding.
 */
export declare function hashToBase64UrlNoPadding(hashBytes: Uint8Array | Buffer): string;
/**
 * Convert a Base64 string to a Uint8Array.
 * @param {string} base64 - The Base64 string to decode.
 * @returns {Uint8Array} - The decoded Uint8Array.
 */
export declare function _base64ToUint8Array(base64: string): Uint8Array;
export declare const streamingUrlCache: Record<string, string[]>;
/**
 * Retrieves streaming locations based on the provided hash and types.
 * @param {string} hash - The hash used to identify the streaming location.
 * @param {string} types - The types of streaming locations to retrieve.
 * @param {string} locationsHost - The host URL for retrieving locations.
 * @returns {Promise<string[]>} A promise that resolves to an array of streaming locations.
 */
export declare function getStreamingLocation(hash: string, types: string, locationsHost: string): Promise<string[]>;
/**
 * Retrieves the appropriate API host for S5 locations based on the provided portal URL.
 * @param {string} portalUrl - The portal URL.
 * @returns {Promise<string>} The API host for S5 locations.
 */
export declare function getS5LocationsApiHost(portalUrl: string): Promise<string | undefined>;
/**
 * Check options for the Locations API.
 * @param {object} opts - The options object.
 * @param {string} opts.locationAPI - The Locations API host.
 * @param {string} opts.portalUrl - The portal URL.
 * @returns {Promise<string>} The resolved Locations API host.
 */
export declare function checkOptsLocationsAPI(opts: any): Promise<string>;
//# sourceMappingURL=decrypt.d.ts.map