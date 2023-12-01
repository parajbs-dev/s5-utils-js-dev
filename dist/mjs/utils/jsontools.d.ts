/**
 * Parses a JSON string and revives functions if found.
 * @param jsonString - The JSON string to parse.
 * @returns Parsed object with revived functions if present.
 */
export declare function JSONparse(jsonString: string): object;
/**
 * Converts an object to a JSON string, including function string representations.
 * @param obj - The object to be converted.
 * @returns A JSON string representation of the object.
 */
export declare function JSONstringify(obj: {
    [key: string]: any;
}): string;
/**
 * Checks if the given data is a valid JSON and returns a stringified version of it.
 * @param data - The data to be checked and stringified.
 * @returns A Promise that resolves to the stringified JSON or undefined if the data is not valid.
 */
export declare function isJson(data: string | object): Promise<string | undefined>;
//# sourceMappingURL=jsontools.d.ts.map