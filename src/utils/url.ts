import { trimSuffix } from "./string";
import { throwValidationError } from "./validation";

export const DEFAULT_S5_PORTAL_URL = "http://localhost:5050";

/**
 * @deprecated please use DEFAULT_S5_PORTAL_URL.
 */
export const defaultS5PortalUrl = DEFAULT_S5_PORTAL_URL;

export const URI_S5_PREFIX = "s5://";

/**
 * @deprecated please use URI_S5_PREFIX.
 */
export const uriS5Prefix = URI_S5_PREFIX;

/**
 * Returns the default portal URL.
 * @returns - The portal URL.
 */
export function defaultPortalUrl(): string {
  /* istanbul ignore next */
  if (typeof window === "undefined") return "/"; // default to path root on ssr
  return window.location.origin;
}

/**
 * Adds a subdomain to the given URL.
 * @param url - The URL.
 * @param subdomain - The subdomain to add.
 * @returns - The final URL.
 */
export function addUrlSubdomain(url: string, subdomain: string): string {
  const urlObj = new URL(url);
  urlObj.hostname = `${subdomain}.${urlObj.hostname}`;
  const str = urlObj.toString();
  return trimSuffix(str, "/");
}

/**
 * Returns the first subdomain of the given URL.
 * If the URL does not contain a subdomain, returns null.
 * @param url The URL to extract the subdomain from.
 * @returns The first subdomain of the URL, or null if there is no subdomain.
 */
export function getSubdomainFromUrl(url: string): string | null {
  const subdomain = url.match(/^(?:https?:\/\/)?([^./]+)\./i);
  return subdomain ? subdomain[1] : null;
}

/**
 * Adds or updates query parameters in a URL without using url-parse.
 * @param url - The original URL.
 * @param query - The query parameters to add or update.
 * @returns The modified URL with the updated query parameters.
 */
export function addUrlQuery(url: string, query: { [key: string]: string | undefined }): string {
  const urlObj = new URL(url);
  for (const key in query) {
    if (Object.prototype.hasOwnProperty.call(query, key)) {
      const value = query[key];
      if (value !== undefined) {
        urlObj.searchParams.set(key, value);
      } else {
        urlObj.searchParams.delete(key);
      }
    }
  }
  return urlObj.toString();
}

/**
 * Prepends the prefix to the given string only if the string does not already start with the prefix.
 * @param str - The string.
 * @param prefix - The prefix.
 * @returns - The prefixed string.
 */
export function ensurePrefix(str: string, prefix: string): string {
  if (!str.startsWith(prefix)) {
    str = `${prefix}${str}`;
  }
  return str;
}

/**
 * Ensures that the given string is a URL.
 * @param url - The given string.
 * @returns - The URL.
 */
export function ensureUrl(url: string): string {
  if (url.startsWith("http://")) {
    return url;
  }
  return ensurePrefix(url, "https://");
}

/**
 * Ensures that the given string is a URL with a protocol prefix.
 * @param url - The given string.
 * @returns - The URL.
 */
export function ensureUrlPrefix(url: string): string {
  if (url === "localhost") {
    return "http://localhost/";
  }
  if (!/^https?:(\/\/)?/i.test(url)) {
    return `https://${url}`;
  }
  return url;
}

/**
 * Create a URL by joining multiple path segments.
 * @param args - An array of string path segments to join.
 * @returns The joined URL as a string.
 */
export function makeUrl(...args: string[]): string {
  if (args.length === 0) {
    throwValidationError("args", args, "parameter", "non-empty");
  }
  return ensureUrl(args.reduce((acc, cur) => joinPathSegments(acc, cur)));
}

/**
 * Join two path segments, ensuring there is a single '/' between them.
 * @param segment1 - The first path segment.
 * @param segment2 - The second path segment.
 * @returns The joined path.
 */
function joinPathSegments(segment1: string, segment2: string): string {
  // Remove trailing '/' from segment1 and leading '/' from segment2 to ensure a single '/' separator
  const cleanedSegment1 = segment1.replace(/\/+$/, '');
  const cleanedSegment2 = segment2.replace(/^\/+/, '');
  return `${cleanedSegment1}/${cleanedSegment2}`;
}

