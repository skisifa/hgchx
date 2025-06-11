/**
 * Redirect Handler Script
 * Simple handler for redirecting visitors from dashboard
 */

/**
 * Performs a safe redirect to the specified URL with aggressive modal cleanup
 * - Aggressively removes all modal backdrops
 * - Resets all body styles
 * - Performs the redirect with a delay to ensure cleanup completes
 * @param {string} url - The URL to redirect to
 * @returns {boolean} - Whether the redirect was initiated
 */
function safeRedirect(url) {
  console.log('Redirect handler: Redirecting to:', url);
  
  // Force close any open modals first
  if (typeof $ !== 'undefined') {
    try {
      if ($.fn && $.fn.modal) {
        $('.modal').modal('hide');
      }
    } catch (e) {
      console.log('Bootstrap modal not available:', e);
    }
    // Remove modal backdrops with jQuery
    $('.modal-backdrop').remove();
  }
  
  // Aggressive cleanup of modal backdrops with multiple methods
  function cleanupModals() {
    // Method 1: Direct removal
    const modalBackdrops = document.querySelectorAll('.modal-backdrop');
    modalBackdrops.forEach(backdrop => {
      backdrop.classList.remove('show');
      backdrop.remove();
    });
    
    // Method 2: Remove via jQuery if available
    if (typeof $ !== 'undefined') {
      $('.modal-backdrop').remove();
    }
    
    // Method 3: Remove via direct DOM manipulation
    document.querySelectorAll('.modal-backdrop').forEach(el => el.parentNode.removeChild(el));
    
    // Reset all body styles
    document.body.classList.remove('modal-open');
    document.body.style.overflow = '';
    document.body.style.paddingRight = '';
    document.body.style.position = '';
    document.body.style.height = '';
    document.body.style.width = '';
  }
  
  // Clean up immediately
  cleanupModals();
  
  // Clean up again after a short delay
  setTimeout(cleanupModals, 50);
  
  // Perform the redirect with a longer delay to ensure cleanup completes
  setTimeout(() => {
    // Final cleanup before navigation
    cleanupModals();
    window.location.href = url;
  }, 200);
  
  return true;
}

// Make the function available globally
window.safeRedirect = safeRedirect;
