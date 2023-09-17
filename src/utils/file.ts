import mime from "mime/lite";

import { trimPrefix } from "./string";

/**
 * Get the file mime type. In case the type is not provided, try to guess the
 * file type based on the extension.
 * @param file - The file.
 * @returns - The mime type.
 */
export function getFileMimeType(file: File): string {
  if (file.type) return file.type;
  let ext = file.name.split(".").pop();
  if (ext) {
    ext = trimPrefix(ext, ".");
    const mimeType = mime.getType(ext);
    if (mimeType) {
      return mimeType;
    }
  }
  return "";
}
