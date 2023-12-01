/* eslint-disable @typescript-eslint/no-explicit-any */
import { MAX_REVISION } from "./constants";

/**
 * Check if the provided data is not an empty string, not null, not undefined,
 * and not a Uint8Array with a length of 0.
 * @param {*} data - The data to be checked.
 * @returns {boolean} - True if the data is valid, false otherwise.
 */
export function isValidData(data: any): boolean {
  return (
    data !== "" &&
    data !== null &&
    data !== undefined &&
    !(data instanceof Uint8Array && data.length === 0)
  );
}

/**
 * Check and decode response data from a JSON response.
 * @param jsonResponseData - The data to be checked and decoded, represented as a Uint8Array or undefined.
 * @returns The decoded data as a string, Uint8Array, or undefined if the input data is undefined.
 */
export function checkResponseData(jsonResponseData: Uint8Array | undefined): string | Uint8Array | undefined {
  let dataCheck;

  if (jsonResponseData === undefined) {
    dataCheck = jsonResponseData;
  } else {
    if (jsonResponseData instanceof Uint8Array) {
      dataCheck = new TextDecoder().decode(jsonResponseData);
    }
  }
  return dataCheck;
}

/**
 * Asynchronously increments the revision number and checks if it exceeds a maximum value.
 * @param jsonResponse The JSON response object containing the current revision.
 * @param maxRevision Optional parameter specifying the maximum allowed revision.
 * @returns A Promise that resolves to the updated revision if it's within the allowed range,
 *          or rejects with an error message if the revision exceeds the maximum.
 */
export async function incrementAndCheckRevision(jsonResponse: any, maxRevision?: number): Promise<number> {
  const MAXREVISION = maxRevision !== undefined ? maxRevision : MAX_REVISION;
  const revision = jsonResponse ? jsonResponse.revision + 1 : 0;
  return revision <= MAXREVISION
    ? revision
    : (console.error("Revision exceeds the maximum allowed value."), undefined);
}

