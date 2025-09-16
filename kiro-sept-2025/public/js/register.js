/**
 * Registration page functionality with security features and password validation
 */

class RegisterManager {
    constructor() {
        this.form = null;
        this.emailField = null;
        this.passwordField = null;
        this.confirmPasswordField = null;
        this.submitButton = null;
        this.passwordRequirements = {};
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupElements();
            this.setupEventListeners();
            this.setupValidation();
            this.setupPasswordStrengthIndicator();
        });
    }

    setupElements() {
        this.form = document.getElementById('register-form');
        this.emailField = document.getElementById('email');
        this.passwordField = document.getElementById('password');
        this.confirmPasswordField = document.getElementById('confirmPassword');
        this.submitButton = document.getElementById('register-btn');
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
            this.passwordField.addEventListener('input', () => {
                this.validatePassword();
                this.updatePasswordStrength();
                this.validateConfirmPassword();
                this.updateSubmitButton();
            });
            this.passwordField.addEventListener('blur', () => this.validatePassword());
        }

        if (this.confirmPasswordField) {
            this.confirmPasswordField.addEventListener('input', () => {
                this.validateConfirmPassword();
                this.updateSubmitButton();
            });
            this.confirmPasswordField.addEventListener('blur', () => this.validateConfirmPassword());
        }

        // Update submit button state on any input change
        this.form?.addEventListener('input', () => {
            setTimeout(() => this.updateSubmitButton(), 100);
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
            this.passwordField.setAttribute('title', 'Password must meet all requirements');
        }

        if (this.confirmPasswordField) {
            this.confirmPasswordField.setAttribute('minlength', '12');
            this.confirmPasswordField.setAttribute('title', 'Passwords must match');
        }
    }

    setupPasswordStrengthIndicator() {
        // Initialize password requirements display
        this.passwordRequirements = {
            length: document.getElementById('req-length'),
            uppercase: document.getElementById('req-uppercase'),
            lowercase: document.getElementById('req-lowercase'),
            number: document.getElementById('req-number'),
            special: document.getElementById('req-special')
        };
    }

    async handleSubmit(event) {
        event.preventDefault();
        
        // Clear previous messages
        authUtils.hideMessages();
        this.clearAllFieldErrors();

        // Validate form
        if (!this.isFormValid()) {
            authUtils.showError('Please fix the errors below before submitting.');
            return;
        }

        // Set loading state
        authUtils.setButtonLoading('register-btn', true);

        try {
            const formData = new FormData(this.form);
            const registerData = {
                email: authUtils.sanitizeInput(formData.get('email')),
                password: formData.get('password'), // Don't sanitize password
                confirmPassword: formData.get('confirmPassword'), // Don't sanitize password
                _csrf: formData.get('_csrf')
            };

            const response = await authUtils.secureRequest('/api/auth/register', {
                method: 'POST',
                body: JSON.stringify(registerData)
            });

            const result = await response.json();

            if (response.ok) {
                // Success
                authUtils.showSuccess('Account created successfully! You can now sign in.');
                
                // Clear form
                this.form.reset();
                this.updatePasswordStrength();
                this.updateSubmitButton();
                
                // Redirect to login after delay
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            } else {
                // Handle different error types
                this.handleRegistrationError(response.status, result);
            }
        } catch (error) {
            console.error('Registration error:', error);
            
            if (error.message === 'Rate limit exceeded') {
                // Rate limit error is already handled by authUtils
                return;
            }
            
            authUtils.showError('Network error. Please check your connection and try again.');
        } finally {
            authUtils.setButtonLoading('register-btn', false);
        }
    }

    handleRegistrationError(status, result) {
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
                
            case 409:
                // Email already exists
                authUtils.showFieldError('email', 'An account with this email already exists.');
                break;
                
            case 429:
                // Rate limited (handled by authUtils)
                break;
                
            case 500:
                authUtils.showError('Server error. Please try again later.');
                break;
                
            default:
                authUtils.showError(result.error?.message || 'Registration failed. Please try again.');
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
        
        const validation = authUtils.validatePassword(password);
        
        if (!validation.isValid) {
            const missingRequirements = [];
            if (!validation.requirements.length) missingRequirements.push('at least 12 characters');
            if (!validation.requirements.uppercase) missingRequirements.push('one uppercase letter');
            if (!validation.requirements.lowercase) missingRequirements.push('one lowercase letter');
            if (!validation.requirements.number) missingRequirements.push('one number');
            if (!validation.requirements.special) missingRequirements.push('one special character');
            
            authUtils.showFieldError('password', `Password must include: ${missingRequirements.join(', ')}`);
            return false;
        }
        
        authUtils.hideFieldError('password');
        return true;
    }

    validateConfirmPassword() {
        const password = this.passwordField.value;
        const confirmPassword = this.confirmPasswordField.value;
        
        if (!confirmPassword) {
            authUtils.showFieldError('confirm-password', 'Please confirm your password');
            return false;
        }
        
        if (password !== confirmPassword) {
            authUtils.showFieldError('confirm-password', 'Passwords do not match');
            return false;
        }
        
        authUtils.hideFieldError('confirm-password');
        return true;
    }

    updatePasswordStrength() {
        const password = this.passwordField.value;
        const validation = authUtils.validatePassword(password);
        
        // Update requirement indicators
        Object.keys(this.passwordRequirements).forEach(req => {
            const element = this.passwordRequirements[req];
            if (element) {
                if (validation.requirements[req]) {
                    element.classList.add('valid');
                } else {
                    element.classList.remove('valid');
                }
            }
        });
        
        // Update strength bar
        const strengthFill = document.getElementById('strength-fill');
        const strengthText = document.getElementById('strength-text');
        
        if (strengthFill && strengthText) {
            // Remove all strength classes
            strengthFill.className = 'strength-fill';
            strengthText.className = 'strength-text';
            
            if (password.length > 0) {
                // Add current strength class
                strengthFill.classList.add(validation.strength);
                strengthText.classList.add(validation.strength);
                
                // Update text
                const strengthLabels = {
                    weak: 'Weak',
                    fair: 'Fair',
                    good: 'Good',
                    strong: 'Strong'
                };
                
                strengthText.textContent = `Password strength: ${strengthLabels[validation.strength]}`;
            } else {
                strengthText.textContent = 'Password strength: Weak';
            }
        }
    }

    updateSubmitButton() {
        if (this.submitButton) {
            const isValid = this.isFormValid();
            this.submitButton.disabled = !isValid;
        }
    }

    isFormValid() {
        const emailValid = this.emailField.value.trim() && this.validateEmail();
        const passwordValid = this.passwordField.value && this.validatePassword();
        const confirmPasswordValid = this.confirmPasswordField.value && this.validateConfirmPassword();
        
        return emailValid && passwordValid && confirmPasswordValid;
    }

    clearFieldError(fieldName) {
        authUtils.hideFieldError(fieldName);
    }

    clearAllFieldErrors() {
        ['email', 'password', 'confirm-password'].forEach(field => {
            authUtils.hideFieldError(field);
        });
    }
}

// Initialize register manager
const registerManager = new RegisterManager();