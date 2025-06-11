// Add these helper functions to your server.js file

/**
 * Safely checks if a value is a string
 * @param {any} value - The value to check
 * @return {boolean} - True if the value is a string
 */
function isString(value) {
  return typeof value === 'string' || value instanceof String;
}

/**
 * Safely checks if a path starts with a prefix
 * @param {any} path - The path to check
 * @param {string} prefix - The prefix to check for
 * @return {boolean} - True if path starts with prefix
 */
function safePathStartsWith(path, prefix) {
  if (!isString(path)) {
    console.log(`Warning: path is not a string: ${typeof path}`, path);
    return false;
  }
  return path.startsWith(prefix);
}

/**
 * Safely gets a string path or returns a default
 * @param {any} path - The path to check
 * @param {string} defaultPath - Default path to return if input is not a string
 * @return {string} - A valid string path
 */
function getValidPath(path, defaultPath = '/') {
  return isString(path) ? path : defaultPath;
}
