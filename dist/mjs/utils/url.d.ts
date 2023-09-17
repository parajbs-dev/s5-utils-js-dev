export declare const DEFAULT_S5_PORTAL_URL = "http://localhost:5050";
/**
 * @deprecated please use DEFAULT_S5_PORTAL_URL.
 */
export declare const defaultS5PortalUrl = "http://localhost:5050";
export declare const URI_S5_PREFIX = "s5://";
/**
 * @deprecated please use URI_S5_PREFIX.
 */
export declare const uriS5Prefix = "s5://";
/**
 * Returns the default portal URL.
 * @returns - The portal URL.
 */
export declare function defaultPortalUrl(): string;
/**
 * Adds a subdomain to the given URL.
 * @param url - The URL.
 * @param subdomain - The subdomain to add.
 * @returns - The final URL.
 */
export declare function addUrlSubdomain(url: string, subdomain: string): string;
/**
 * Returns the first subdomain of the given URL.
 * If the URL does not contain a subdomain, returns null.
 * @param url The URL to extract the subdomain from.
 * @returns The first subdomain of the URL, or null if there is no subdomain.
 */
export declare function getSubdomainFromUrl(url: string): string | null;
/**
 * Adds or updates query parameters in a URL without using url-parse.
 * @param url - The original URL.
 * @param query - The query parameters to add or update.
 * @returns The modified URL with the updated query parameters.
 */
export declare function addUrlQuery(url: string, query: {
    [key: string]: string | undefined;
}): string;
/**
 * Prepends the prefix to the given string only if the string does not already start with the prefix.
 * @param str - The string.
 * @param prefix - The prefix.
 * @returns - The prefixed string.
 */
export declare function ensurePrefix(str: string, prefix: string): string;
/**
 * Ensures that the given string is a URL.
 * @param url - The given string.
 * @returns - The URL.
 */
export declare function ensureUrl(url: string): string;
/**
 * Ensures that the given string is a URL with a protocol prefix.
 * @param url - The given string.
 * @returns - The URL.
 */
export declare function ensureUrlPrefix(url: string): string;
/**
 * Create a URL by joining multiple path segments.
 * @param args - An array of string path segments to join.
 * @returns The joined URL as a string.
 */
export declare function makeUrl(...args: string[]): string;
//# sourceMappingURL=url.d.ts.map