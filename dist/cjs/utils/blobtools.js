"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDownloadFromBlob = exports.createVideoPageInNewTab = exports.createVideoElementFromBlob = void 0;
/**
 * Create an HTML video element from a Blob.
 * @param {Blob} blob - The Blob object representing the video data.
 * @returns {HTMLVideoElement} - The created HTML video element.
 */
function createVideoElementFromBlob(blob) {
    // Create a video element
    const videoElement = document.createElement('video');
    // Set attributes for the video element
    videoElement.controls = true; // Add controls
    videoElement.autoplay = true; // Autoplay
    videoElement.muted = true; // Muted (optional)
    // Apply custom CSS styles
    videoElement.style.width = '100%';
    videoElement.style.height = '100vh';
    videoElement.style.objectFit = 'fill';
    // Create a URL from the Blob
    const blobUrl = URL.createObjectURL(blob);
    // Set the Blob URL as the source for the video element
    videoElement.src = blobUrl;
    // Create a button to remove the video element and the button itself
    const removeButton = document.createElement('button');
    removeButton.textContent = 'Remove Video';
    removeButton.addEventListener('click', () => {
        // Remove the video element
        document.body.removeChild(videoElement);
        // Remove the remove button
        document.body.removeChild(removeButton);
    });
    // Append the video element to the document body
    document.body.appendChild(videoElement);
    // Append the remove button to the document body
    document.body.appendChild(removeButton);
    return videoElement;
}
exports.createVideoElementFromBlob = createVideoElementFromBlob;
/**
 * Creates a new browser tab to display a video from a Blob.
 * @param {Blob} blob - The Blob containing the video data.
 */
function createVideoPageInNewTab(blob) {
    // Create a Blob URL for the video
    const blobUrl = URL.createObjectURL(blob);
    // Create the HTML content for the new page
    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Video Page</title>
    </head>
    <body>
        <video controls autoplay src="${blobUrl}" style="width: 100%; height: 100vh; object-fit: fill;"></video>
    </body>
    </html>
  `;
    // Create a Blob with the HTML content
    const pageBlob = new Blob([htmlContent], { type: 'text/html' });
    // Create a Blob URL for the new page
    const pageBlobUrl = URL.createObjectURL(pageBlob);
    // Open the new page in a new tab
    const newTab = window.open(pageBlobUrl, '_blank');
    // Release resources when the page is closed (optional)
    newTab?.addEventListener('beforeunload', () => {
        URL.revokeObjectURL(blobUrl);
        URL.revokeObjectURL(pageBlobUrl);
    });
}
exports.createVideoPageInNewTab = createVideoPageInNewTab;
/**
 * Creates a download link for a Blob and triggers the download.
 * @param blob - The Blob data to be downloaded.
 * @param decryptedFilePath - The name to be used for the downloaded file.
 */
function createDownloadFromBlob(blob, decryptedFilePath) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = decryptedFilePath;
    a.click();
    URL.revokeObjectURL(url);
}
exports.createDownloadFromBlob = createDownloadFromBlob;
