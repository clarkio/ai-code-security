/**
 * Dashboard functionality with secure data handling
 */

class DashboardManager {
    constructor() {
        this.stats = {
            totalNotes: 0,
            recentNotes: 0,
            lastLogin: null
        };
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.setupEventListeners();
            this.loadDashboardData();
            this.checkAuthentication();
        });
    }

    setupEventListeners() {
        // Logout functionality
        const logoutLink = document.getElementById('logout-link');
        if (logoutLink) {
            logoutLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogout();
            });
        }
    }

    async checkAuthentication() {
        if (typeof authUtils !== 'undefined') {
            try {
                const isAuthenticated = await authUtils.checkAuthStatus();
                if (!isAuthenticated) {
                    // Redirect to login if not authenticated
                    window.location.href = '/login';
                    return;
                }
            } catch (error) {
                console.error('Authentication check failed:', error);
                window.location.href = '/login';
                return;
            }
        }
    }

    async loadDashboardData() {
        try {
            // Load user stats
            await this.loadUserStats();
            
            // Load recent notes
            await this.loadRecentNotes();
            
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            authUtils.showError('Failed to load dashboard data. Please refresh the page.');
        }
    }

    async loadUserStats() {
        try {
            const response = await authUtils.secureRequest('/api/user/stats', {
                method: 'GET'
            });

            if (response.ok) {
                const stats = await response.json();
                this.updateStatsDisplay(stats);
            } else {
                // Handle error gracefully - show default values
                this.updateStatsDisplay({
                    totalNotes: 0,
                    recentNotes: 0,
                    lastLogin: null
                });
            }
        } catch (error) {
            console.error('Failed to load user stats:', error);
            // Show default values on error
            this.updateStatsDisplay({
                totalNotes: 0,
                recentNotes: 0,
                lastLogin: null
            });
        }
    }

    async loadRecentNotes() {
        const recentNotesList = document.getElementById('recent-notes-list');
        const loadingSpinner = document.getElementById('loading-spinner');
        
        if (!recentNotesList) return;

        try {
            const response = await authUtils.secureRequest('/api/notes?limit=5&sort=recent', {
                method: 'GET'
            });

            if (response.ok) {
                const data = await response.json();
                this.displayRecentNotes(data.notes || []);
            } else {
                this.displayRecentNotes([]);
            }
        } catch (error) {
            console.error('Failed to load recent notes:', error);
            this.displayRecentNotes([]);
        } finally {
            if (loadingSpinner) {
                loadingSpinner.style.display = 'none';
            }
        }
    }

    updateStatsDisplay(stats) {
        // Update total notes
        const totalNotesElement = document.getElementById('total-notes');
        if (totalNotesElement) {
            totalNotesElement.textContent = stats.totalNotes || 0;
        }

        // Update recent notes count
        const recentNotesElement = document.getElementById('recent-notes');
        if (recentNotesElement) {
            recentNotesElement.textContent = stats.recentNotes || 0;
        }

        // Update last login
        const lastLoginElement = document.getElementById('last-login');
        if (lastLoginElement) {
            if (stats.lastLogin) {
                const lastLoginDate = new Date(stats.lastLogin);
                lastLoginElement.textContent = this.formatDate(lastLoginDate);
            } else {
                lastLoginElement.textContent = 'Never';
            }
        }
    }

    displayRecentNotes(notes) {
        const recentNotesList = document.getElementById('recent-notes-list');
        if (!recentNotesList) return;

        if (notes.length === 0) {
            recentNotesList.innerHTML = `
                <div class="empty-state">
                    <p>No notes yet. <a href="/notes/new">Create your first note</a></p>
                </div>
            `;
            return;
        }

        const notesHtml = notes.map(note => this.createNotePreviewHtml(note)).join('');
        recentNotesList.innerHTML = notesHtml;
    }

    createNotePreviewHtml(note) {
        // Sanitize note data
        const title = authUtils.sanitizeInput(note.title || 'Untitled');
        const preview = authUtils.sanitizeInput(this.truncateText(note.content || '', 150));
        const createdAt = this.formatDate(new Date(note.createdAt));
        const updatedAt = this.formatDate(new Date(note.updatedAt));

        return `
            <div class="note-item">
                <div class="note-header">
                    <h4 class="note-title">${title}</h4>
                    <div class="note-actions">
                        <a href="/notes/edit/${note.id}" class="btn btn-secondary">Edit</a>
                    </div>
                </div>
                <div class="note-preview">${preview}</div>
                <div class="note-meta">
                    <span class="note-date">Created: ${createdAt}</span>
                    <span class="note-date">Updated: ${updatedAt}</span>
                </div>
            </div>
        `;
    }

    truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    formatDate(date) {
        if (!date || isNaN(date.getTime())) return 'Unknown';
        
        const now = new Date();
        const diffTime = Math.abs(now - date);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays === 1) {
            return 'Today';
        } else if (diffDays === 2) {
            return 'Yesterday';
        } else if (diffDays <= 7) {
            return `${diffDays - 1} days ago`;
        } else {
            return date.toLocaleDateString();
        }
    }

    async handleLogout() {
        if (typeof authUtils !== 'undefined') {
            try {
                const response = await authUtils.secureRequest('/api/auth/logout', {
                    method: 'POST'
                });
                
                if (response.ok) {
                    authUtils.showSuccess('Logged out successfully. Redirecting...');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    console.error('Logout failed');
                    // Force redirect anyway for security
                    window.location.href = '/';
                }
            } catch (error) {
                console.error('Logout error:', error);
                // Force redirect anyway for security
                window.location.href = '/';
            }
        }
    }
}

// Initialize dashboard manager
const dashboardManager = new DashboardManager();