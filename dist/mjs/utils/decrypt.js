import { Buffer } from "buffer";
import sodium from "libsodium-wrappers";
import { blake3 } from "@noble/hashes/blake3";
import { convertMHashToB64url } from "./blake3tools";
import { decodeBase64URL } from "./basetools";
/**
 * Decrypts a chunk of data using the XChaCha20-Poly1305 encryption scheme.
 * @param {Uint8Array} chunk - The encrypted chunk of data to be decrypted.
 * @param {Uint8Array} key - The encryption key used for decryption.
 * @param {number} chunkIndex - The index of the chunk for generating the nonce.
 * @returns {Promise<Uint8Array>} - The decrypted chunk of data.
 * @throws {Error} - If decryption fails or produces invalid output.
 */
export async function decryptFileXchacha20(chunk, key, chunkIndex) {
    await sodium.ready;
    const nonce = new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const indexBytes = new Uint8Array(4);
    indexBytes.set(new Uint8Array(new Uint32Array([chunkIndex]).buffer), 0);
    nonce.set(indexBytes, 0);
    const decryptedChunk = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, chunk, null, nonce, key);
    if (!decryptedChunk) {
        throw new Error('Decryption error.');
    }
    return decryptedChunk;
}
/**
 * Hashes the data from a ReadableStream using the BLAKE3 algorithm.
 * @param stream - The ReadableStream containing the data to be hashed.
 * @returns A Promise that resolves to the hash value as a Uint8Array.
 */
export async function hashStream(stream) {
    const hasher = await blake3.create({});
    const reader = stream.getReader();
    try {
        let chunkIndex = 0;
        const isTrue = true;
        while (isTrue === true) {
            const { done, value } = await reader.read();
            if (done) {
                console.debug('B3Hash Chunk:', chunkIndex);
                chunkIndex++;
                return hasher.digest();
            }
            hasher.update(value);
            console.debug('B3Hash Chunk:', chunkIndex);
            chunkIndex++;
        }
    }
    catch (error) {
        reader.releaseLock();
        throw error;
    }
    return hasher.digest();
}
/**
 * Decrypts a stream of data using the XChaCha20 encryption algorithm and additional hashing and validation.
 * @param b3hashStream - The source stream containing the B3hash data.
 * @param clonedStream - The cloned stream for decryption.
 * @param durlEncryptionMetadataHash - The hash used for comparison.
 * @param key - The encryption key.
 * @param chunkSize - The size of data chunks for decryption.
 * @returns A promise that resolves when decryption is completed.
 */
export async function decryptStream(b3hashStream, clonedStream, durlEncryptionMetadataHash, key, chunkSize) {
    await sodium.ready;
    let decryptedBlob;
    const reader = clonedStream.getReader();
    const clonedStreamForHashing = b3hashStream;
    try {
        const hash = await hashStream(clonedStreamForHashing);
        const compareB3hashes = await compareB3hash(durlEncryptionMetadataHash, Buffer.from(hash));
        if (compareB3hashes === 0) {
            console.debug('\nCalculate B3hash completed.\n\n');
            let chunkIndex = 0;
            let currentChunk = new Uint8Array(0);
            let chunks = [];
            const isTrue = true;
            while (isTrue === true) {
                const { done, value } = await reader.read();
                if (done) {
                    if (currentChunk.length !== 0) {
                        const chunkToDecrypt = currentChunk.slice(0, chunkSize);
                        const decryptedChunk = await decryptFileXchacha20(chunkToDecrypt, key, chunkIndex);
                        chunks.push(decryptedChunk.slice(0, decryptedChunk.length));
                        console.debug('Decrypted Chunk:', chunkIndex);
                        chunkIndex++;
                    }
                    decryptedBlob = {
                        blob: new Blob(chunks, { type: 'application/octet-stream' })
                    };
                    return decryptedBlob;
                }
                currentChunk = new Uint8Array([...currentChunk, ...value]);
                while (currentChunk.length >= chunkSize) {
                    const chunkToDecrypt = currentChunk.slice(0, chunkSize);
                    const decryptedChunk = await decryptFileXchacha20(chunkToDecrypt, key, chunkIndex);
                    chunks.push(decryptedChunk.slice(0, decryptedChunk.length));
                    console.debug('Decrypted Chunk:', chunkIndex);
                    chunkIndex++;
                    currentChunk = currentChunk.slice(chunkSize);
                }
            }
            decryptedBlob = {
                blob: new Blob(chunks, { type: 'application/octet-stream' })
            };
            sodium.memzero(currentChunk);
            sodium.memzero(key);
            sodium.memzero(durlEncryptionMetadataHash);
            chunkIndex = 0;
            chunks = [];
            return decryptedBlob;
        }
        else {
            throw new Error('Invalid B3hash.');
        }
    }
    catch (error) {
        reader.releaseLock();
        throw error;
    }
}
/**
 * Decrypts a file from a response stream and saves it to a specified file path.
 * @param response - The HTTP response containing the encrypted file data.
 * @param durlEncryptionMetadataHash - The hash used for DURL encryption metadata.
 * @param decryptedFilePath - The path where the decrypted file should be saved.
 * @param decryptionKey - The decryption key used to decrypt the file.
 * @param chunkIndex - (Optional) The index of the chunk being decrypted.
 * @returns A Promise that resolves once the file is successfully decrypted and saved.
 */
export async function decryptFile(response, durlEncryptionMetadataHash, decryptedFilePath, decryptionKey, chunkIndex) {
    try {
        await sodium.ready;
        if (chunkIndex) {
            console.debug(chunkIndex);
        }
        const b3hashFileStream = response.clone().body;
        const encryptedFileStream = response.clone().body;
        if (b3hashFileStream && encryptedFileStream) {
            try {
                const decryptedBlob = await decryptStream(b3hashFileStream, encryptedFileStream, durlEncryptionMetadataHash, decryptionKey, 262160);
                console.debug('\nDecryption end');
                if (decryptedBlob.blob) {
                    return { blob: decryptedBlob.blob };
                }
            }
            catch (error) {
                console.error("Error decrypting stream:", error);
            }
        }
    }
    catch (error) {
        if (error instanceof Error) {
            console.error('Error:', error.message);
        }
        else {
            console.error('An unknown error occurred:', error);
        }
    }
}
/**
 * Compare two B3 hashes and return the result of the comparison.
 * @param {Buffer} b3hash1 - The first B3 hash to compare.
 * @param {Buffer} b3hash2 - The second B3 hash to compare.
 * @returns {number} - A number indicating the comparison result. Negative value if b3hash1 comes before b3hash2, positive value if b3hash1 comes after b3hash2, and zero if they are equal.
 */
export function compareB3hash(b3hash1, b3hash2) {
    // Convert b3hash1 to a buffer
    const buffer1 = b3hash1;
    // Create buffer2 by concatenating [31] with b3hash2
    const buffer2 = Buffer.concat([Buffer.from([31]), Buffer.from(b3hash2)]);
    // Compare buffer1 with buffer2 and store the result
    const compareB3hashes = Buffer.compare(buffer1, buffer2);
    // Return the comparison result
    return compareB3hashes;
}
/**
 * Retrieves an encrypted file URL and associated metadata based on the provided encrypted CID.
 * @param encryptedCid The encrypted CID for the file.
 * @param locationsHost The host for fetching streaming locations.
 * @returns A promise that resolves to an `EncryptedFileUrlResponse` containing metadata and the file URL.
 * @throws Error if the CID format is invalid or if the encryption algorithm is not supported.
 */
export async function getEncryptedFileUrl(encryptedCid, locationsHost) {
    let uCid;
    let bytes;
    let url0;
    let hash_b64;
    let hashBytes;
    let totalSize;
    let encryptionMetadata;
    let encryptionMetadataIntern;
    if (encryptedCid[0] === 'u') {
        const fullCID = encryptedCid;
        const cid = fullCID.split('.')[0];
        if (!cid.startsWith('u')) {
            throw new Error('Invalid CID format');
        }
        bytes = decodeBase64URL(cid.substr(1));
        if (bytes[0] == 0xae) {
            if (bytes[1] != 0xa6) {
                throw new Error('Encryption algorithm not supported');
            }
            encryptionMetadata = {
                algorithm: bytes[1],
                chunkSize: Math.pow(2, bytes[2]),
                hash: bytes.subarray(3, 36),
                key: bytes.subarray(36, 68),
                padding: decodeEndian(bytes.subarray(68, 72)),
            };
            //encryptedKey = bytes.subarray(36, 68);
            bytes = bytes.subarray(72);
            uCid = 'u' + convertMHashToB64url(bytes);
            totalSize = decodeEndian(bytes.subarray(34));
            const isEncrypted = encryptionMetadata !== undefined;
            hashBytes = _base64ToUint8Array(uCid.substring(1).replace(/-/g, '+').replace(/_/g, '/')).slice(1, 34);
            hash_b64 = hashToBase64UrlNoPadding(isEncrypted ? encryptionMetadata.hash : hashBytes);
            const parts = await getStreamingLocation(hash_b64, '3,5', locationsHost);
            const url = parts[0];
            url0 = new URL(url);
        }
        encryptionMetadataIntern = {
            url: url0 ? url0.toString() : '',
            ucid: uCid ? uCid : '',
            hash: hash_b64 ? hash_b64 : '',
            totalsize: totalSize ? totalSize : 0,
            encryptionMetadata,
            bytes,
        };
        bytes = [];
        return encryptionMetadataIntern;
    }
    throw new Error('Invalid encryptedCid');
}
/**
 * Decodes a URL-safe Base64 encoded string into its original data format.
 * @param {string} input - The URL-safe Base64 encoded string to decode.
 * @returns {Buffer} - The decoded data as a Buffer object.
 */
export function decodeBase64URL2(input) {
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const paddingLength = (4 - (base64.length % 4)) % 4;
    const paddedBase64 = base64 + '==='.slice(0, paddingLength);
    return Buffer.from(paddedBase64, 'base64');
}
/**
 * Decodes a byte array in little-endian format into a single numeric value.
 * @param {Array} bytes - The byte array to decode, represented as an array of integers.
 * @returns {number} - The decoded numeric value.
 */
export function decodeEndian(bytes) {
    let value = 0;
    for (let i = bytes.length - 1; i >= 0; i--) {
        value = (value << 8) + bytes[i];
    }
    return value;
}
/**
 * Converts a byte array to a Base64 URL-encoded string without padding characters.
 * @param {Array} hashBytes - The byte array to convert.
 * @returns {string} - The Base64 URL-encoded string without padding.
 */
export function hashToBase64UrlNoPadding(hashBytes) {
    // Convert byte array to Base64 string
    const base64 = Buffer.from(hashBytes).toString('base64');
    // Replace characters for URL compatibility and remove padding
    const base64Url = base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    return base64Url;
}
/**
 * Convert a Base64 string to a Uint8Array.
 * @param {string} base64 - The Base64 string to decode.
 * @returns {Uint8Array} - The decoded Uint8Array.
 */
export function _base64ToUint8Array(base64) {
    try {
        // Convert Base64 string to binary string
        const binaryString = Buffer.from(base64, 'base64').toString('binary');
        // Get the length of the binary string
        const length = binaryString.length;
        // Create a new Uint8Array with the specified length
        const bytes = new Uint8Array(length);
        // Iterate over each character in the binary string
        for (let i = 0; i < length; i++) {
            // Get the character code at the current index
            bytes[i] = binaryString.charCodeAt(i);
        }
        // Return the resulting Uint8Array
        return bytes;
    }
    catch (error) {
        // Handle the error here
        console.error('Error decoding Base64 string:', error);
        // Return an empty Uint8Array or null, depending on your use case
        return new Uint8Array(0);
    }
}
export const streamingUrlCache = {};
/**
 * Retrieves streaming locations based on the provided hash and types.
 * @param {string} hash - The hash used to identify the streaming location.
 * @param {string} types - The types of streaming locations to retrieve.
 * @param {string} locationsHost - The host URL for retrieving locations.
 * @returns {Promise<string[]>} A promise that resolves to an array of streaming locations.
 */
export async function getStreamingLocation(hash, types, locationsHost) {
    // Check if the streaming locations are already cached
    const val = streamingUrlCache[hash];
    if (val !== undefined) {
        return val; // Return the cached value
    }
    console.debug('\nfetch', locationsHost + hash + '?types=' + types);
    const res = await fetch(locationsHost + hash + '?types=' + types);
    // Extract the parts from the response JSON
    const { parts } = (await res.json())['locations'][0];
    // Cache the streaming locations
    streamingUrlCache[hash] = parts;
    return parts;
}
/**
 * Retrieves the appropriate API host for S5 locations based on the provided portal URL.
 * @param {string} portalUrl - The portal URL.
 * @returns {Promise<string>} The API host for S5 locations.
 */
export async function getS5LocationsApiHost(portalUrl) {
    let localtionCheckUrl;
    if (portalUrl.startsWith("http://")) {
        localtionCheckUrl = portalUrl + "/s5/debug/storage_locations/";
    }
    if (portalUrl.startsWith("https://localhost")) {
        localtionCheckUrl = portalUrl + "/s5/debug/storage_locations/";
    }
    else {
        if (portalUrl.startsWith("https://")) {
            localtionCheckUrl = "https://s5.cx/api/locations/";
        }
    }
    return localtionCheckUrl;
}
/**
 * Check options for the Locations API.
 * @param {object} opts - The options object.
 * @param {string} opts.locationAPI - The Locations API host.
 * @param {string} opts.portalUrl - The portal URL.
 * @returns {Promise<string>} The resolved Locations API host.
 */
// eslint-disable-next-line  @typescript-eslint/no-explicit-any
export async function checkOptsLocationsAPI(opts) {
    let locationsAPIHost;
    if (!opts.locationAPI) {
        locationsAPIHost = await getS5LocationsApiHost(opts.portalUrl);
    }
    else {
        locationsAPIHost = opts.locationAPI;
    }
    return locationsAPIHost;
}
