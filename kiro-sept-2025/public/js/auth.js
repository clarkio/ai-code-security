/**
 * Common authentication utilities and security functions
 * Shared across login and registration pages
 */

class AuthUtils {
    constructor() {
        this.csrfToken = null;
        this.rateLimitInfo = null;
        this.init();
    }

    async init() {
        await this.fetchCsrfToken();
        this.setupGlobalErrorHandling();
    }

    /**
     * Fetch CSRF token from server
     */
    async fetchCsrfToken() {
        try {
            const response = await fetch('/api/csrf-token', {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.csrfToken = data.csrfToken;
                
                // Update all CSRF token inputs
                const csrfInputs = document.querySelectorAll('input[name="_csrf"]');
                csrfInputs.forEach(input => {
                    input.value = this.csrfToken;
                });
            } else {
                console.error('Failed to fetch CSRF token');
                this.showError('Security token could not be loaded. Please refresh the page.');
            }
        } catch (error) {
            console.error('Error fetching CSRF token:', error);
            this.showError('Network error. Please check your connection and try again.');
        }
    }

    /**
     * Make secure API request with CSRF protection
     */
    async secureRequest(url, options = {}) {
        const defaultOptions = {
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };

        // Merge options
        const requestOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        // Add CSRF token to POST requests
        if (options.method === 'POST' && this.csrfToken) {
            if (requestOptions.body && typeof requestOptions.body === 'string') {
                try {
                    const bodyData = JSON.parse(requestOptions.body);
                    bodyData._csrf = this.csrfToken;
                    requestOptions.body = JSON.stringify(bodyData);
                } catch (e) {
                    // If body is not JSON, add CSRF as form data
                    const formData = new FormData();
                    formData.append('_csrf', this.csrfToken);
                    requestOptions.body = formData;
                }
            }
        }

        try {
            const response = await fetch(url, requestOptions);
            
            // Handle rate limiting
            if (response.status === 429) {
                const retryAfter = response.headers.get('Retry-After');
                this.handleRateLimit(retryAfter);
                throw new Error('Rate limit exceeded');
            }

            return response;
        } catch (error) {
            if (error.message !== 'Rate limit exceeded') {
                console.error('Request failed:', error);
            }
            throw error;
        }
    }

    /**
     * Handle rate limiting display
     */
    handleRateLimit(retryAfter) {
        const warningElement = document.getElementById('rate-limit-warning');
        const countdownElement = document.getElementById('rate-limit-countdown');
        
        if (warningElement && countdownElement) {
            warningElement.style.display = 'block';
            
            let remainingTime = parseInt(retryAfter) || 60;
            
            const updateCountdown = () => {
                const minutes = Math.floor(remainingTime / 60);
                const seconds = remainingTime % 60;
                countdownElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                
                if (remainingTime > 0) {
                    remainingTime--;
                    setTimeout(updateCountdown, 1000);
                } else {
                    warningElement.style.display = 'none';
                }
            };
            
            updateCountdown();
        }
    }

    /**
     * Sanitize user input to prevent XSS
     */
    sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        
        // Basic HTML entity encoding
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }

    /**
     * Validate email format
     */
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email) && email.length <= 254;
    }

    /**
     * Validate password strength
     */
    validatePassword(password) {
        const requirements = {
            length: password.length >= 12,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
        };

        const score = Object.values(requirements).filter(Boolean).length;
        let strength = 'weak';
        
        if (score >= 5) strength = 'strong';
        else if (score >= 4) strength = 'good';
        else if (score >= 3) strength = 'fair';

        return {
            isValid: Object.values(requirements).every(Boolean),
            requirements,
            strength,
            score
        };
    }

    /**
     * Show error message
     */
    showError(message, elementId = 'error-message') {
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = this.sanitizeInput(message);
            errorElement.style.display = 'block';
            
            // Hide after 10 seconds
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 10000);
        }
    }

    /**
     * Show success message
     */
    showSuccess(message, elementId = 'success-message') {
        const successElement = document.getElementById(elementId);
        if (successElement) {
            successElement.textContent = this.sanitizeInput(message);
            successElement.style.display = 'block';
            
            // Hide after 5 seconds
            setTimeout(() => {
                successElement.style.display = 'none';
            }, 5000);
        }
    }

    /**
     * Hide all messages
     */
    hideMessages() {
        const messages = document.querySelectorAll('.alert');
        messages.forEach(msg => {
            msg.style.display = 'none';
        });
    }

    /**
     * Show field error
     */
    showFieldError(fieldName, message) {
        const errorElement = document.getElementById(`${fieldName}-error`);
        if (errorElement) {
            errorElement.textContent = this.sanitizeInput(message);
            errorElement.style.display = 'block';
        }
    }

    /**
     * Hide field error
     */
    hideFieldError(fieldName) {
        const errorElement = document.getElementById(`${fieldName}-error`);
        if (errorElement) {
            errorElement.style.display = 'none';
        }
    }

    /**
     * Set button loading state
     */
    setButtonLoading(buttonId, loading = true) {
        const button = document.getElementById(buttonId);
        if (button) {
            if (loading) {
                button.classList.add('loading');
                button.disabled = true;
            } else {
                button.classList.remove('loading');
                button.disabled = false;
            }
        }
    }

    /**
     * Setup global error handling
     */
    setupGlobalErrorHandling() {
        window.addEventListener('error', (event) => {
            console.error('Global error:', event.error);
            // Don't show technical errors to users
        });

        window.addEventListener('unhandledrejection', (event) => {
            console.error('Unhandled promise rejection:', event.reason);
            // Don't show technical errors to users
        });
    }

    /**
     * Redirect to dashboard or specified URL
     */
    redirectTo(url = '/dashboard') {
        // Use replace to prevent back button issues
        window.location.replace(url);
    }

    /**
     * Check if user is authenticated (basic check)
     */
    async checkAuthStatus() {
        try {
            const response = await this.secureRequest('/api/auth/status', {
                method: 'GET'
            });
            
            return response.ok;
        } catch (error) {
            return false;
        }
    }
}

// Initialize auth utils when DOM is loaded
let authUtils;
document.addEventListener('DOMContentLoaded', () => {
    authUtils = new AuthUtils();
});

// Export for use in other scripts
window.AuthUtils = AuthUtils;