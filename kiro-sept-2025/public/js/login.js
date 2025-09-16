/**
 * Login page functionality with security features
 */

class LoginManager {
    constructor() {
        this.form = null;
        this.emailField = null;
        this.passwordField = null;
        this.submitButton = null;
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupElements();
            this.setupEventListeners();
            this.setupValidation();
        });
    }

    setupElements() {
        this.form = document.getElementById('login-form');
        this.emailField = document.getElementById('email');
        this.passwordField = document.getElementById('password');
        this.submitButton = document.getElementById('login-btn');
    }

    setupEventListeners() {
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        }

        // Real-time validation
        if (this.emailField) {
            this.emailField.addEventListener('blur', () => this.validateEmail());
            this.emailField.addEventListener('input', () => this.clearFieldError('email'));
        }

        if (this.passwordField) {
            this.passwordField.addEventListener('blur', () => this.validatePassword());
            this.passwordField.addEventListener('input', () => this.clearFieldError('password'));
        }

        // Prevent form submission on Enter if validation fails
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.target.tagName === 'INPUT') {
                if (!this.isFormValid()) {
                    e.preventDefault();
                }
            }
        });
    }

    setupValidation() {
        // Set up HTML5 validation attributes
        if (this.emailField) {
            this.emailField.setAttribute('pattern', '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$');
            this.emailField.setAttribute('title', 'Please enter a valid email address');
        }

        if (this.passwordField) {
            this.passwordField.setAttribute('minlength', '12');
            this.passwordField.setAttribute('title', 'Password must be at least 12 characters long');
        }
    }

    async handleSubmit(event) {
        event.preventDefault();
        
        // Clear previous messages
        authUtils.hideMessages();
        this.clearAllFieldErrors();

        // Validate form
        if (!this.isFormValid()) {
            return;
        }

        // Set loading state
        authUtils.setButtonLoading('login-btn', true);

        try {
            const formData = new FormData(this.form);
            const loginData = {
                email: authUtils.sanitizeInput(formData.get('email')),
                password: formData.get('password'), // Don't sanitize password
                _csrf: formData.get('_csrf')
            };

            const response = await authUtils.secureRequest('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify(loginData)
            });

            const result = await response.json();

            if (response.ok) {
                // Success
                authUtils.showSuccess('Login successful! Redirecting...');
                
                // Redirect after short delay
                setTimeout(() => {
                    authUtils.redirectTo('/dashboard');
                }, 1500);
            } else {
                // Handle different error types
                this.handleLoginError(response.status, result);
            }
        } catch (error) {
            console.error('Login error:', error);
            
            if (error.message === 'Rate limit exceeded') {
                // Rate limit error is already handled by authUtils
                return;
            }
            
            authUtils.showError('Network error. Please check your connection and try again.');
        } finally {
            authUtils.setButtonLoading('login-btn', false);
        }
    }

    handleLoginError(status, result) {
        switch (status) {
            case 400:
                // Validation errors
                if (result.errors && Array.isArray(result.errors)) {
                    result.errors.forEach(error => {
                        if (error.field) {
                            authUtils.showFieldError(error.field, error.message);
                        } else {
                            authUtils.showError(error.message);
                        }
                    });
                } else {
                    authUtils.showError(result.error?.message || 'Invalid input. Please check your information.');
                }
                break;
                
            case 401:
                // Authentication failed
                authUtils.showError('Invalid email or password. Please try again.');
                // Clear password field for security
                if (this.passwordField) {
                    this.passwordField.value = '';
                }
                break;
                
            case 423:
                // Account locked
                authUtils.showError('Account temporarily locked due to too many failed attempts. Please try again later.');
                break;
                
            case 429:
                // Rate limited (handled by authUtils)
                break;
                
            case 500:
                authUtils.showError('Server error. Please try again later.');
                break;
                
            default:
                authUtils.showError(result.error?.message || 'Login failed. Please try again.');
        }
    }

    validateEmail() {
        const email = this.emailField.value.trim();
        
        if (!email) {
            authUtils.showFieldError('email', 'Email is required');
            return false;
        }
        
        if (!authUtils.validateEmail(email)) {
            authUtils.showFieldError('email', 'Please enter a valid email address');
            return false;
        }
        
        authUtils.hideFieldError('email');
        return true;
    }

    validatePassword() {
        const password = this.passwordField.value;
        
        if (!password) {
            authUtils.showFieldError('password', 'Password is required');
            return false;
        }
        
        if (password.length < 12) {
            authUtils.showFieldError('password', 'Password must be at least 12 characters long');
            return false;
        }
        
        authUtils.hideFieldError('password');
        return true;
    }

    isFormValid() {
        const emailValid = this.validateEmail();
        const passwordValid = this.validatePassword();
        
        return emailValid && passwordValid;
    }

    clearFieldError(fieldName) {
        authUtils.hideFieldError(fieldName);
    }

    clearAllFieldErrors() {
        ['email', 'password'].forEach(field => {
            authUtils.hideFieldError(field);
        });
    }
}

// Initialize login manager
const loginManager = new LoginManager();