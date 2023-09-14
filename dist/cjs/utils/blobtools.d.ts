/**
 * Create an HTML video element from a Blob.
 * @param {Blob} blob - The Blob object representing the video data.
 * @returns {HTMLVideoElement} - The created HTML video element.
 */
export declare function createVideoElementFromBlob(blob: Blob): HTMLVideoElement;
/**
 * Creates a new browser tab to display a video from a Blob.
 * @param {Blob} blob - The Blob containing the video data.
 */
export declare function createVideoPageInNewTab(blob: Blob): void;
/**
 * Creates a download link for a Blob and triggers the download.
 * @param blob - The Blob data to be downloaded.
 * @param decryptedFilePath - The name to be used for the downloaded file.
 */
export declare function createDownloadFromBlob(blob: Blob, decryptedFilePath: string): void;
//# sourceMappingURL=blobtools.d.ts.map