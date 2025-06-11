// Add this helper function at the top of your server.js file
function safeStringCheck(value) {
  return typeof value === 'string' || value instanceof String;
}

// Add this helper function to safely check if a path starts with a prefix
function safePathStartsWith(path, prefix) {
  // Check if path is a string before calling startsWith
  if (!safeStringCheck(path)) {
    console.log(`Warning: path is not a string: ${typeof path}`, path);
    return false;
  }
  return path.startsWith(prefix);
}

// Add this function to safely check if a path is a system path
function isSystemPath(path) {
  // Check if path is a string first
  if (!safeStringCheck(path)) {
    console.log(`Warning: path is not a string: ${typeof path}`, path);
    return false;
  }
  
  // Now safely check if it starts with various prefixes
  return path.startsWith('/js') || 
         path.startsWith('/img') || 
         path.startsWith('/css') ||
         path.startsWith('/favicon');
}

// Modified parseUserAgent function to safely handle paths
function parseUserAgent(userAgent, path) {
  // Add safety check for path parameter
  const safePath = safeStringCheck(path) ? path : '/';
  
  // Rest of your parseUserAgent function...
  // When you need to check path, use safePath instead
  
  // Example:
  // if (safePath.startsWith('/js') || safePath.startsWith('/img')) {
  //   // Do something
  // }
}

// Modified detectMiddleware function to safely handle paths
function detectMiddleware(req, res, next) {
  // Get accurate client IP with fallbacks
  const clientIp = getAccurateClientIp(req);
  
  // Add safety check for req.path
  const path = safeStringCheck(req.path) ? req.path : '/';
  
  // Skip tracking for non-target routes or local IPs
  if (!REAL_ROUTES.includes(path) || isLocalIP(clientIp) || isSystemPath(path)) {
    return next();
  }
  
  // Rest of your middleware function...
}
