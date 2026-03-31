// HTMX — server-driven interactivity
import htmx from 'htmx.org'

// Configure HTMX defaults
htmx.config.defaultSwapStyle = 'innerHTML'
htmx.config.historyCacheSize = 0
htmx.config.defaultSettleDelay = 100

// Auto-inject CSRF token into HTMX requests
document.body.addEventListener('htmx:configRequest', function(event) {
  const csrfCookie = document.cookie.split('; ')
    .find(c => c.startsWith('zentryc_csrf='))
  if (csrfCookie) {
    event.detail.headers['X-CSRF-Token'] = csrfCookie.split('=')[1]
  }
})

window.htmx = htmx
