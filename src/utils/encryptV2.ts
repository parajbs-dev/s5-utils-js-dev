import { Buffer } from "buffer";
import { blake3 } from "@noble/hashes/blake3";
import * as sodium from "libsodium-wrappers";

import {
  convertMHashToB64url,
  calculateB3hashFromFile,
} from "./blake3tools";

import {
  cidTypeEncrypted,
  mhashBlake3Default,
  encryptionAlgorithmXChaCha20Poly1305,
} from "./constants";

export const chunkSizeAsPowerOf2 = 18;
export const CID_TYPE_ENCRYPTED_LENGTH = 1;
export const ENCRYPTION_ALGORITHM_LENGTH = 1;
export const CHUNK_LENGTH_AS_POWEROF2_LENGTH = 1;
export const ENCRYPTED_BLOB_HASH_LENGTH = 33;
export const KEY_LENGTH = 32;

/**
 * Generates a key using the XChaCha20-Poly1305 encryption algorithm.
 * @returns A Promise that resolves to a Uint8Array representing the generated key.
 */
export async function generate_key(): Promise<Uint8Array> {
  await sodium.ready;

  const encryptKey = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  return encryptKey;
}

/**
 * Generates a key from a seed string using the XChaCha20-Poly1305 encryption algorithm.
 * @param seedString - The seed string used to derive the key.
 * @returns A Promise that resolves to a Uint8Array representing the generated key.
 */
export async function generate_key_From_Seed(seedString: string): Promise<Uint8Array> {
  await sodium.ready;

  // Ensure the seed string is encoded as UTF-8 before generating the key.
  const seedBytes = sodium.from_string(seedString);

  // Use the seed bytes to generate the key.
  const encryptKey = sodium.crypto_generichash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    seedBytes
  );

  return encryptKey;
}

/**
 * Encrypts a file using the XChaCha20-Poly1305 algorithm.
 * @param inputFile The input file to be encrypted as a Uint8Array.
 * @param key The encryption key as a Uint8Array.
 * @param padding The padding value as a number.
 * @param chunkIndex Optional. The index of the current chunk as a number.
 * @returns A promise that resolves to the encrypted file as a Uint8Array.
 */
export async function encrypt_file_xchacha20(
  inputFile: Uint8Array,
  key: Uint8Array,
  padding: number,
  chunkIndex?: number | undefined
): Promise<Uint8Array> {
  await sodium.ready;

  const chunkSize = 262144; // 256 KB
  const encryptedFile: Uint8Array[] = [];
  let chunkIndexIntern = chunkIndex || 0;

  for (let i = 0; i < inputFile.length; i += chunkSize) {
    const chunk = inputFile.slice(i, i + chunkSize);

    const nonce = new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const indexBytes = new Uint8Array(4);
    indexBytes.set(new Uint8Array(new Uint32Array([chunkIndexIntern]).buffer), 0);
    nonce.set(indexBytes, 0);

    const ciphertext = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      chunk,
      null,
      null,
      nonce,
      key
    );

    encryptedFile.push(ciphertext);
    chunkIndexIntern++;
  }

  return concatUint8Arrays(encryptedFile);
}

/**
 * Concatenates multiple Uint8Array objects into a single Uint8Array.
 * @param arrays An array of Uint8Array objects to be concatenated.
 * @returns A new Uint8Array that contains the concatenated values.
 */
export function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  // Calculate the total length of the concatenated array
  const totalLength = arrays.reduce((acc, array) => acc + array.length, 0);

  // Create a new Uint8Array with the calculated total length
  const result = new Uint8Array(totalLength);

  // Initialize the offset to keep track of the position within the result array
  let offset = 0;

  // Iterate over each Uint8Array in the input array
  for (const array of arrays) {
    // Set the current Uint8Array at the corresponding position in the result array
    result.set(array, offset);

    // Update the offset by adding the length of the current Uint8Array
    offset += array.length;
  }

  // Return the concatenated Uint8Array
  return result;
}

/**
 * Calculates the BLAKE3 hash of a file after encrypting it with a given key.
 * @param {File} file - The file to hash.
 * @param {Uint8Array} encryptedKey - The key to use for encryption.
 * @returns {Promise<{ b3hash: Buffer; encryptedFileSize: number }>} A Promise that resolves to an object containing the hash value and the size of the encrypted file.
 */
export async function calculateB3hashFromFileEncrypt(
  file: File,
  encryptedKey: Uint8Array
): Promise<{ b3hash: Buffer; encryptedFileSize: number }> {
  // Create a hash object
  const hasher = await blake3.create({});

  // Define the chunk size (1 MB)
  const chunkSize = 262144; // 256 KB;
  // Initialize the position to 0
  let position = 0;
  let encryptedFileSize = 0;
  let chunkIndex = 0;

  // Process the file in chunks
  while (position <= file.size) {
    // Slice the file to extract a chunk
    const chunk = file.slice(position, position + chunkSize);

    // Convert chunk's ArrayBuffer to hex string and log it
    const chunkArrayBuffer = await chunk.arrayBuffer();
    const chunkUint8Array = new Uint8Array(chunkArrayBuffer);
    const encryptedChunkUint8Array = await encrypt_file_xchacha20(chunkUint8Array, encryptedKey, 0x0, chunkIndex);
    encryptedFileSize += encryptedChunkUint8Array.length;

    // Update the hash with the chunk's data
    hasher.update(encryptedChunkUint8Array);

    // Move to the next position
    position += chunkSize;
    chunkIndex++;
  }

  // Obtain the final hash value
  const b3hash = hasher.digest();
  // Return the hash value as a Promise resolved to a Buffer
  return { b3hash: Buffer.from(b3hash), encryptedFileSize };
}

/**
 * Extracts the encryption key from an encrypted CID.
 * @param {string} encryptedCid - The encrypted CID to get the key from.
 * @returns {string} The encryption key from the CID.
 */
export function getKeyFromEncryptedCid(encryptedCid: string): string {
  const extensionIndex = encryptedCid.lastIndexOf(".");

  let cidWithoutExtension;
  if (extensionIndex !== -1) {
    cidWithoutExtension = encryptedCid.slice(0, extensionIndex);
  } else {
    cidWithoutExtension = encryptedCid;
  }
  console.log("getKeyFromEncryptedCid: encryptedCid = ", encryptedCid);
  console.log("getKeyFromEncryptedCid: cidWithoutExtension = ", cidWithoutExtension);

  cidWithoutExtension = cidWithoutExtension.slice(1);
  const cidBytes = convertBase64urlToBytes(cidWithoutExtension);
  const startIndex =
    CID_TYPE_ENCRYPTED_LENGTH +
    ENCRYPTION_ALGORITHM_LENGTH +
    CHUNK_LENGTH_AS_POWEROF2_LENGTH +
    ENCRYPTED_BLOB_HASH_LENGTH;

  const endIndex = startIndex + KEY_LENGTH;

  const selectedBytes = cidBytes.slice(startIndex, endIndex);

  const key = convertBytesToBase64url(selectedBytes);
  return key;
}

/**
 * Removes the encryption key from an encrypted CID.
 * @param {string} encryptedCid - The encrypted CID to remove the key from.
 * @returns {string} The CID with the encryption key removed.
 */
export function removeKeyFromEncryptedCid(encryptedCid: string): string {
  const extensionIndex = encryptedCid.lastIndexOf(".");
  const cidWithoutExtension = extensionIndex === -1 ? encryptedCid : encryptedCid.slice(0, extensionIndex);

  // remove 'u' prefix as well
  const cidWithoutExtensionBytes = convertBase64urlToBytes(cidWithoutExtension.slice(1));

  const part1 = cidWithoutExtensionBytes.slice(
    0,
    CID_TYPE_ENCRYPTED_LENGTH +
      ENCRYPTION_ALGORITHM_LENGTH +
      CHUNK_LENGTH_AS_POWEROF2_LENGTH +
      ENCRYPTED_BLOB_HASH_LENGTH
  );
  const part2 = cidWithoutExtensionBytes.slice(part1.length + KEY_LENGTH);

  const combinedBytes = new Uint8Array(cidWithoutExtensionBytes.length - KEY_LENGTH);
  combinedBytes.set(part1);
  combinedBytes.set(part2, part1.length);

  const cidWithoutKey = "u" + convertBytesToBase64url(combinedBytes);
  return cidWithoutKey;
}

/**
 * Combines an encryption key with an encrypted CID.
 * @param {string} key - The encryption key to combine with the encrypted CID.
 * @param {string} encryptedCidWithoutKey - The encrypted CID without the encryption key.
 * @returns {string} The encrypted CID with the encryption key combined.
 */
export function combineKeytoEncryptedCid(key: string, encryptedCidWithoutKey: string): string {
  const extensionIndex = encryptedCidWithoutKey.lastIndexOf(".");
  const cidWithoutKeyAndExtension =
    extensionIndex === -1 ? encryptedCidWithoutKey : encryptedCidWithoutKey.slice(0, extensionIndex);

  const encryptedCidWithoutKeyBytes = convertBase64urlToBytes(cidWithoutKeyAndExtension.slice(1));

  const keyBytes = convertBase64urlToBytes(key);

  const combinedBytes = new Uint8Array(encryptedCidWithoutKeyBytes.length + keyBytes.length);

  const part1 = encryptedCidWithoutKeyBytes.slice(
    0,
    CID_TYPE_ENCRYPTED_LENGTH +
      ENCRYPTION_ALGORITHM_LENGTH +
      CHUNK_LENGTH_AS_POWEROF2_LENGTH +
      ENCRYPTED_BLOB_HASH_LENGTH
  );
  const part2 = encryptedCidWithoutKeyBytes.slice(part1.length);

  combinedBytes.set(part1);
  combinedBytes.set(keyBytes, part1.length);
  combinedBytes.set(part2, part1.length + keyBytes.length);

  const encryptedCid = `u` + convertBytesToBase64url(combinedBytes);
  return encryptedCid;
}

/**
 * Converts an array of bytes to a Base64URL-encoded string.
 * @param {Uint8Array} hashBytes - The array of bytes to be converted.
 * @returns {string} The Base64URL-encoded string.
 */
export function convertBytesToBase64url(hashBytes: Uint8Array): string {
  const mHash = Buffer.from(hashBytes);

  // Convert the hash Buffer to a Base64 string
  const hashBase64 = mHash.toString("base64");

  // Make the Base64 string URL-safe
  const hashBase64url = hashBase64.replace(/\+/g, "-").replace(/\//g, "_").replace("=", "");

  return hashBase64url;
}

/**
 * Converts a URL-safe Base64 string to a Uint8Array of bytes.
 * @param {string} b64url - The URL-safe Base64 string to convert.
 * @returns {Uint8Array} - The Uint8Array containing the bytes.
 */
export function convertBase64urlToBytes(b64url: string): Uint8Array {
  // Convert the URL-safe Base64 string to a regular Base64 string
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");

  // Add missing padding
  while (b64.length % 4) {
    b64 += "=";
  }

  // Convert Base64 string to Buffer
  const buffer = Buffer.from(b64, "base64");

  // Convert Buffer to Uint8Array
  const mHash = Uint8Array.from(buffer);

  return mHash;
}

/**
 * Creates an encrypted Content Identifier (CID) from the provided parameters.
 * @param cidTypeEncrypted - The encrypted type of the CID.
 * @param encryptionAlgorithm - The encryption algorithm used.
 * @param chunkSizeAsPowerOf2 - The chunk size as a power of 2.
 * @param encryptedBlobHash - The encrypted hash of the blob.
 * @param encryptionKey - The encryption key used.
 * @param padding - Additional padding to be used.
 * @param originalCid - The original CID before encryption.
 * @returns A Uint8Array representing the encrypted CID.
 */
export function createEncryptedCid(
  cidTypeEncrypted: number,
  encryptionAlgorithm: number,
  chunkSizeAsPowerOf2: number,
  encryptedBlobHash: Uint8Array,
  encryptionKey: Uint8Array,
  padding: number,
  originalCid: Uint8Array
): Uint8Array {
  const result: number[] = [];
  result.push(cidTypeEncrypted);
  result.push(encryptionAlgorithm);
  result.push(chunkSizeAsPowerOf2);
  result.push(...Array.from(encryptedBlobHash));
  result.push(...Array.from(encryptionKey));
  result.push(...Array.from(new Uint8Array(new Uint32Array([padding]).buffer))); // convert padding to big-endian
  result.push(...Array.from(originalCid));

  return new Uint8Array(result);
}

/**
 * Encrypts a file using a specified encryption key and CID. This function
 * first reads the input file and converts it into a Uint8Array format.
 * It then initializes a WebAssembly (WASM) module and calls an encryption
 * function to encrypt the file content. The encrypted file content is then
 * converted back into a Blob and then into a File object.
 * It also computes the encrypted blob hash, constructs the encrypted CID,
 * and returns the encrypted file along with the encrypted CID.
 * @param {File} file - The file to be encrypted.
 * @param {string} filename - The name of the file.
 * @param {Uint8Array} encryptedKey - The encryption key to be used.
 * @param {string} cid - The Content Identifier of the file.
 * @returns {Promise<{ encryptedFile: File; encryptedCid: string }>} A promise that resolves with an object containing the encrypted file and the encrypted CID.
 */
export async function encryptFile(
  file: File,
  filename: string,
  encryptedKey: Uint8Array,
  cid: Buffer
): Promise<{
  encryptedFile: File;
  encryptedCid: string;
  //  encryptedBlobMHashBase64url: string;
}> {
  // Convert the File object to a Uint8Array
  const reader = new FileReader();
  reader.readAsArrayBuffer(file);
  await new Promise((resolve) => {
    reader.onload = (event) => {
      resolve(event);
    };
  });
  const fileContents = new Uint8Array(reader.result as ArrayBuffer);

  // Call the function to encrypt the file
  const encryptedFileBytes = await encrypt_file_xchacha20(fileContents, encryptedKey, 0x0);

  // Convert Uint8Array to Blob
  const blob = new Blob([encryptedFileBytes], { type: "application/octet-stream" });

  // Convert Blob to File
  const encryptedFile = new File([blob], filename, { type: "application/octet-stream", lastModified: Date.now() });

  const b3hash = await calculateB3hashFromFile(encryptedFile);
  const encryptedBlobHash = Buffer.concat([Buffer.alloc(1, mhashBlake3Default), b3hash]);

  const padding = 0;

  const encryptedCidBytes = createEncryptedCid(
    cidTypeEncrypted,
    encryptionAlgorithmXChaCha20Poly1305,
    chunkSizeAsPowerOf2,
    encryptedBlobHash,
    encryptedKey,
    padding,
    cid
  );

  const encryptedCid = "u" + convertMHashToB64url(Buffer.from(encryptedCidBytes));

  return {
    encryptedFile,
    encryptedCid,
  };
}

/**
 * Returns a ReadableStreamDefaultReader for a ReadableStream of encrypted data from the provided File object.
 * The data is encrypted using the XChaCha20-Poly1305 algorithm with the provided encryption key.
 * The encryption is done on-the-fly using a transformer function.
 * The input data is split into chunks of size 262144 bytes (256 KB) and each chunk is encrypted separately.
 * @param file The File object to read from.
 * @param encryptedKey The encryption key to use, as a Uint8Array.
 * @returns A ReadableStreamDefaultReader for a ReadableStream of encrypted data from the provided File object.
 */
export function getEncryptedStreamReader(
  file: File,
  encryptedKey: Uint8Array
): ReadableStreamDefaultReader<Uint8Array> {
  // Creates a ReadableStream from a File object, encrypts the stream using a transformer,
  // and returns a ReadableStreamDefaultReader for the encrypted stream.

  const fileStream = file.stream();
  const transformerEncrypt = getTransformerEncrypt(encryptedKey);
  const encryptedFileStream = fileStream.pipeThrough(transformerEncrypt);
  const reader = encryptedFileStream.getReader();

  return reader;
}

/**
 * Returns a transformer function that encrypts the input data using the provided key.
 * The encryption is done using the XChaCha20-Poly1305 algorithm.
 * The input data is split into chunks of size 262144 bytes (256 KB) and each chunk is encrypted separately.
 * @param key The encryption key to use, as a Uint8Array.
 * @returns A TransformStream object that takes in Uint8Array chunks and outputs encrypted Uint8Array chunks.
 */
export function getTransformerEncrypt(key: Uint8Array): TransformStream<Uint8Array, Uint8Array> {
  let buffer = new Uint8Array(0);
  let chunkIndex = 0;
  const chunkSize = 262144; // Chunk size in bytes

  return new TransformStream({
    async transform(chunk, controller) {
      const newBuffer = new Uint8Array(buffer.length + chunk.length);
      newBuffer.set(buffer);
      newBuffer.set(chunk, buffer.length);
      buffer = newBuffer;

      while (buffer.length >= chunkSize) {
        const chunk = buffer.slice(0, chunkSize);
        const encryptedChunkUint8Array = Promise.resolve(await encrypt_file_xchacha20(chunk, key, 0x0, chunkIndex));
        controller.enqueue(await encryptedChunkUint8Array);

        buffer = buffer.slice(chunkSize);
        console.log("encrypt: chunkIndex = ", chunkIndex);
        chunkIndex++;
      }
    },
    async flush(controller) {
      // Process remaining data in the buffer, if any
      while (buffer.length > 0) {
        const chunk = buffer.slice(0, Math.min(chunkSize, buffer.length));
        const encryptedChunkUint8Array = Promise.resolve(await encrypt_file_xchacha20(chunk, key, 0x0, chunkIndex));
        controller.enqueue(await encryptedChunkUint8Array);

        buffer = buffer.slice(Math.min(chunkSize, buffer.length));
        console.log("encrypt: chunkIndex = ", chunkIndex);
        chunkIndex++;
      }
    },
  });
}
