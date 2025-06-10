/**
 * Global redirect handler to ensure proper cleanup before navigation
 * This prevents modal backdrop issues when redirecting
 */

// Global function to forcefully clean up modal artifacts
window.forceCleanModals = function() {
  console.log('Forcing modal cleanup');
  
  // 1. Use jQuery if available (more reliable for Bootstrap modals)
  if (typeof $ !== 'undefined') {
    try {
      // Hide all modals properly
      $('.modal').modal('hide');
      
      // Force remove all modal backdrops
      $('.modal-backdrop').remove();
      
      // Reset body classes and styles
      $('body').removeClass('modal-open');
      $('body').css({
        'overflow': '',
        'padding-right': ''
      });
      
      console.log('jQuery modal cleanup complete');
    } catch (e) {
      console.error('jQuery modal cleanup error:', e);
    }
  }
  
  // 2. Always do vanilla JS cleanup as well (as a backup)
  try {
    // Force remove all modal backdrops
    document.querySelectorAll('.modal-backdrop').forEach(function(el) {
      document.body.removeChild(el);
    });
    
    // Reset all modals
    document.querySelectorAll('.modal').forEach(function(el) {
      el.classList.remove('show');
      el.style.display = 'none';
      el.setAttribute('aria-hidden', 'true');
    });
    
    // Reset body
    document.body.classList.remove('modal-open');
    document.body.style.overflow = '';
    document.body.style.paddingRight = '';
    
    // Create a style tag to forcefully hide modal backdrops
    const style = document.createElement('style');
    style.innerHTML = '.modal-backdrop { display: none !important; }';
    document.head.appendChild(style);
    
    console.log('Vanilla JS modal cleanup complete');
  } catch (e) {
    console.error('Vanilla JS modal cleanup error:', e);
  }
};

// Global function to safely navigate to a new URL with proper cleanup
window.safeRedirect = function(url) {
  if (!url) return;
  
  console.log('Safe redirect initiated to:', url);
  
  // Force clean all modal artifacts
  window.forceCleanModals();
  
  // Redirect after a short delay to ensure cleanup completes
  setTimeout(function() {
    // Clean one more time right before redirecting
    window.forceCleanModals();
    console.log('Executing redirect to:', url);
    window.location.href = url;
  }, 200);
};
