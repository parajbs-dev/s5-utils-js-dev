/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Recursively replaces double quotes with single quotes in strings and function bodies within an object.
 * @param obj - The input object to process.
 * @returns The modified object with replaced quotes.
 */
function replaceQuotes(obj) {
    if (typeof obj !== 'object' || obj === null)
        return obj;
    for (const [key, value] of Object.entries(obj)) {
        if (!Object.prototype.hasOwnProperty.call(obj, key))
            continue;
        if (typeof value === 'string') {
            obj[key] = value.replace(/"/g, "'");
        }
        else if (typeof value === 'function') {
            const functionString = value.toString().includes('function')
                ? value.toString().replace(/"/g, "'")
                : ("function " + value).replace(/"/g, "'");
            obj[key] = functionString;
        }
        else if (typeof value === 'object') {
            obj[key] = replaceQuotes(value);
        }
    }
    return obj;
}
/**
 * Parses a JSON string and revives functions if found.
 * @param jsonString - The JSON string to parse.
 * @returns Parsed object with revived functions if present.
 */
export function JSONparse(jsonString) {
    const obj = JSON.parse(jsonString);
    if (Object.values(obj).some(value => typeof value === 'string' && (/\b\w+\s*\(.*\)\s*{/).test(value))) {
        const reviveFunctions = (key, value) => typeof value === 'string' && (/\b\w+\s*\(.*\)\s*{/).test(value) ? new Function('return ' + value)() : value;
        return JSON.parse(jsonString, reviveFunctions);
    }
    return obj;
}
/**
 * Converts an object to a JSON string, including function string representations.
 * @param obj - The object to be converted.
 * @returns A JSON string representation of the object.
 */
export function JSONstringify(obj) {
    if (Object.values(obj).some((value) => (/\b\w+\s*\(.*\)\s*{/).test(value))) {
        for (const key in obj)
            if (typeof obj[key] === 'function')
                obj[key] = obj[key].toString();
        return JSON.stringify(obj);
    }
    return JSON.stringify(obj);
}
/**
 * Checks if a given string is a valid JSON string.
 * @param data - The input string to be validated.
 * @returns `true` if the input is a valid JSON string, `false` otherwise.
 */
function isValidJSONString(data) {
    try {
        return !!JSON.parse(data);
    }
    catch {
        return false;
    }
}
/**
 * Check if data is a valid JSON object
 * @param data - The data to be checked
 * @returns True if the data is a valid JSON object, false otherwise
 */
function isValidJSONObject(data) {
    return typeof data === 'object' && data !== null;
}
/**
 * Validates if the provided array is a valid JSON array.
 * @param arr - The array to be validated.
 * @returns True if the array is a valid JSON array, false otherwise.
 */
function isValidJSONArray(arr) {
    return areAllValidJSON(arr);
}
/**
 * Checks if all elements in the array are valid JSON strings or objects.
 * @param arr An array containing strings or objects to be validated.
 * @returns True if all elements are valid JSON, false otherwise.
 */
function areAllValidJSON(arr) {
    try {
        for (const element of arr) {
            if (typeof element === 'string')
                JSON.parse(element);
            else if (typeof element === 'object') {
                if (element instanceof Array && !isValidJSONArray(element))
                    return false;
                else if (!(element instanceof Object))
                    return false;
            }
            else
                return false;
        }
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Converts an array of JSON strings into an array of objects.
 * @param jsonArray - The input array containing JSON strings.
 * @returns An array of objects obtained by parsing valid JSON strings or keeping non-parsable strings.
 */
function convertJsonStringsToObject(jsonArray) {
    return jsonArray.map(item => {
        if (typeof item === 'string') {
            try {
                return JSON.parse(item);
            }
            catch (error) {
                return item;
            }
        }
        else if (Array.isArray(item)) {
            return convertJsonStringsToObject(item);
        }
        else {
            return item;
        }
    });
}
/**
 * Checks if the given data is a valid JSON and returns a stringified version of it.
 * @param data - The data to be checked and stringified.
 * @returns A Promise that resolves to the stringified JSON or undefined if the data is not valid.
 */
export async function isJson(data) {
    try {
        if (!data)
            throw new Error("Invalid JSON data.");
        if (typeof data === "string" && isValidJSONString(data))
            return JSON.stringify(JSON.parse(data));
        if (data instanceof Array && isValidJSONArray(data))
            return JSON.stringify(convertJsonStringsToObject(data));
        if (data instanceof Uint8Array)
            throw new Error("Invalid JSON data.");
        if (data instanceof Object && isValidJSONObject(data))
            return JSON.stringify(replaceQuotes(data));
        throw new Error("Invalid JSON data.");
    }
    catch (error) {
        throw new Error(typeof error === "string" ? error : "Unexpected error");
    }
}
