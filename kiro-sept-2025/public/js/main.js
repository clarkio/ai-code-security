/**
 * Main application JavaScript for home page and general functionality
 */

class MainApp {
    constructor() {
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupNavigation();
            this.setupAccessibility();
            this.checkAuthStatus();
        });
    }

    setupNavigation() {
        // Highlight current page in navigation
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.nav-link');
        
        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            if (href === currentPath || (currentPath === '/' && href === '/')) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });

        // Add smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    setupAccessibility() {
        // Add keyboard navigation support
        document.addEventListener('keydown', (e) => {
            // Skip to main content with Alt+M
            if (e.altKey && e.key === 'm') {
                e.preventDefault();
                const main = document.querySelector('main');
                if (main) {
                    main.focus();
                    main.scrollIntoView();
                }
            }
        });

        // Add focus indicators for keyboard navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                document.body.classList.add('keyboard-navigation');
            }
        });

        document.addEventListener('mousedown', () => {
            document.body.classList.remove('keyboard-navigation');
        });
    }

    async checkAuthStatus() {
        // Only check auth status if authUtils is available
        if (typeof authUtils !== 'undefined') {
            try {
                const isAuthenticated = await authUtils.checkAuthStatus();
                if (isAuthenticated) {
                    this.updateUIForAuthenticatedUser();
                }
            } catch (error) {
                // Silently handle auth check errors
                console.debug('Auth status check failed:', error);
            }
        }
    }

    updateUIForAuthenticatedUser() {
        // Update navigation for authenticated users
        const nav = document.querySelector('.nav');
        if (nav) {
            // Add dashboard link
            const dashboardLink = document.createElement('a');
            dashboardLink.href = '/dashboard';
            dashboardLink.className = 'nav-link';
            dashboardLink.textContent = 'Dashboard';
            
            // Add logout link
            const logoutLink = document.createElement('a');
            logoutLink.href = '#';
            logoutLink.className = 'nav-link';
            logoutLink.textContent = 'Logout';
            logoutLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogout();
            });
            
            // Replace login/register links
            const loginLink = nav.querySelector('a[href="/login"]');
            const registerLink = nav.querySelector('a[href="/register"]');
            
            if (loginLink) loginLink.replaceWith(dashboardLink);
            if (registerLink) registerLink.replaceWith(logoutLink);
        }

        // Update CTA buttons
        const ctaButtons = document.querySelector('.cta-buttons');
        if (ctaButtons) {
            ctaButtons.innerHTML = `
                <a href="/dashboard" class="btn btn-primary">Go to Dashboard</a>
                <a href="/notes" class="btn btn-secondary">My Notes</a>
            `;
        }
    }

    async handleLogout() {
        if (typeof authUtils !== 'undefined') {
            try {
                const response = await authUtils.secureRequest('/api/auth/logout', {
                    method: 'POST'
                });
                
                if (response.ok) {
                    // Redirect to home page
                    window.location.href = '/';
                } else {
                    console.error('Logout failed');
                }
            } catch (error) {
                console.error('Logout error:', error);
                // Force redirect anyway
                window.location.href = '/';
            }
        }
    }
}

// Initialize main app
const mainApp = new MainApp();

// Add CSS for keyboard navigation
const style = document.createElement('style');
style.textContent = `
    .keyboard-navigation *:focus {
        outline: 2px solid #007bff !important;
        outline-offset: 2px !important;
    }
`;
document.head.appendChild(style);