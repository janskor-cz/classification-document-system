/**
 * Classification Document System - Main JavaScript
 * Handles common functionality across the application
 */

// ============================================================================
// GLOBAL CONFIGURATION
// ============================================================================

const App = {
    config: {
        apiBase: '/api',
        refreshInterval: 30000, // 30 seconds
        toastDuration: 5000,    // 5 seconds
        maxRetries: 3,
        retryDelay: 1000
    },
    
    state: {
        isOnline: true,
        identusStatus: null,
        currentUser: null,
        notifications: []
    }
};

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Classification Document System - Initializing...');
    
    // Initialize core functionality
    initializeApp();
    initializeToastContainer();
    initializeStatusMonitoring();
    initializeEventListeners();
    
    console.log('✅ Application initialized successfully');
});

function initializeApp() {
    // Check if user is authenticated
    checkAuthentication();
    
    // Load initial system status
    updateSystemStatus();
    
    // Setup periodic updates
    setInterval(updateSystemStatus, App.config.refreshInterval);
    
    // Setup online/offline detection
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

async function checkAuthentication() {
    try {
        const response = await apiCall('/auth/status');
        if (response.authenticated) {
            App.state.currentUser = response.user;
            updateUserInterface();
        }
    } catch (error) {
        console.log('User not authenticated');
    }
}

function updateUserInterface() {
    const user = App.state.currentUser;
    if (!user) return;
    
    // Update user-specific UI elements
    const userElements = document.querySelectorAll('[data-user-name]');
    userElements.forEach(el => {
        el.textContent = user.name || 'Unknown User';
    });
    
    const credentialElements = document.querySelectorAll('[data-user-credentials]');
    credentialElements.forEach(el => {
        el.textContent = user.credentials_count || 0;
    });
}

// ============================================================================
// API UTILITIES
// ============================================================================

async function apiCall(endpoint, options = {}) {
    const url = `${App.config.apiBase}${endpoint}`;
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include'
    };
    
    const config = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, config);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        } else {
            return await response.text();
        }
        
    } catch (error) {
        console.error(`API call failed: ${endpoint}`, error);
        throw error;
    }
}

// ============================================================================
// SYSTEM STATUS MONITORING
// ============================================================================

function initializeStatusMonitoring() {
    // Initial status check
    updateSystemStatus();
    
    // Periodic status updates
    setInterval(updateSystemStatus, App.config.refreshInterval);
}

async function updateSystemStatus() {
    try {
        const response = await apiCall('/identus/status');
        App.state.identusStatus = response;
        
        updateStatusIndicators(response);
        
    } catch (error) {
        console.error('Failed to update system status:', error);
        showOfflineStatus();
    }
}

function updateStatusIndicators(status) {
    const systemStatus = document.getElementById('system-status');
    const identusStatus = document.getElementById('identus-status');
    
    if (systemStatus) {
        if (status.agents_healthy) {
            systemStatus.className = 'badge bg-success me-2';
            systemStatus.innerHTML = '<i class="fas fa-check-circle me-1"></i>System Online';
        } else {
            systemStatus.className = 'badge bg-danger me-2';
            systemStatus.innerHTML = '<i class="fas fa-exclamation-circle me-1"></i>System Issues';
        }
    }
    
    if (identusStatus) {
        if (status.agents_healthy) {
            identusStatus.className = 'badge bg-info me-2';
            identusStatus.innerHTML = '<i class="fas fa-cloud me-1"></i>Identus Ready';
        } else {
            identusStatus.className = 'badge bg-warning me-2';
            identusStatus.innerHTML = '<i class="fas fa-cloud-exclamation me-1"></i>Identus Issues';
        }
    }
}

function showOfflineStatus() {
    const systemStatus = document.getElementById('system-status');
    const identusStatus = document.getElementById('identus-status');
    
    if (systemStatus) {
        systemStatus.className = 'badge bg-secondary me-2';
        systemStatus.innerHTML = '<i class="fas fa-wifi me-1"></i>Offline';
    }
    
    if (identusStatus) {
        identusStatus.className = 'badge bg-secondary me-2';
        identusStatus.innerHTML = '<i class="fas fa-cloud-off me-1"></i>Offline';
    }
}

// ============================================================================
// NOTIFICATION SYSTEM
// ============================================================================

function initializeToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '1055';
        document.body.appendChild(container);
    }
}

function showToast(message, type = 'info', duration = App.config.toastDuration) {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        initializeToastContainer();
        return showToast(message, type, duration);
    }
    
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `toast align-items-center text-white bg-${type === 'error' ? 'danger' : type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${getToastIcon(type)} ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: duration
    });
    
    bsToast.show();
    
    // Remove after hiding
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
    
    return toastId;
}

function getToastIcon(type) {
    const icons = {
        success: '<i class="fas fa-check-circle me-2"></i>',
        error: '<i class="fas fa-exclamation-circle me-2"></i>',
        warning: '<i class="fas fa-exclamation-triangle me-2"></i>',
        info: '<i class="fas fa-info-circle me-2"></i>'
    };
    return icons[type] || icons.info;
}

function showSuccess(message) {
    showToast(message, 'success');
}

function showError(message) {
    showToast(message, 'error');
}

function showWarning(message) {
    showToast(message, 'warning');
}

function showInfo(message) {
    showToast(message, 'info');
}

// ============================================================================
// FORM UTILITIES
// ============================================================================

function initializeEventListeners() {
    // Classification selectors
    document.querySelectorAll('.classification-selector').forEach(selector => {
        selector.addEventListener('click', handleClassificationSelect);
    });
    
    // File inputs
    document.querySelectorAll('input[type="file"]').forEach(input => {
        input.addEventListener('change', handleFileSelect);
    });
}

function handleClassificationSelect(event) {
    const selector = event.currentTarget;
    const radio = selector.querySelector('input[type="radio"]');
    
    // Remove selected class from all selectors
    document.querySelectorAll('.classification-selector').forEach(s => {
        s.classList.remove('selected');
    });
    
    // Add selected class to clicked selector
    selector.classList.add('selected');
    
    // Check the radio button
    if (radio) {
        radio.checked = true;
        radio.dispatchEvent(new Event('change'));
    }
}

function handleFileSelect(event) {
    const input = event.target;
    const file = input.files[0];
    
    if (!file) return;
    
    // Auto-fill title if available
    autoFillTitle(file);
}

function autoFillTitle(file) {
    const titleInput = document.getElementById('title');
    if (titleInput && !titleInput.value.trim()) {
        const fileName = file.name.replace(/\.[^/.]+$/, '');
        titleInput.value = fileName;
        titleInput.dispatchEvent(new Event('input'));
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// NETWORK STATUS
// ============================================================================

function handleOnline() {
    App.state.isOnline = true;
    showSuccess('Connection restored');
    updateSystemStatus();
}

function handleOffline() {
    App.state.isOnline = false;
    showWarning('Connection lost. Some features may not work.');
    showOfflineStatus();
}

// ============================================================================
// DASHBOARD UTILITIES
// ============================================================================

async function refreshDashboard() {
    try {
        showInfo('Refreshing dashboard...');
        
        // Update system status
        await updateSystemStatus();
        
        showSuccess('Dashboard refreshed successfully');
        
    } catch (error) {
        console.error('Dashboard refresh failed:', error);
        showError('Failed to refresh dashboard');
    }
}

// ============================================================================
// EXPORT GLOBAL FUNCTIONS
// ============================================================================

// Make functions available globally
window.App = App;
window.showToast = showToast;
window.showSuccess = showSuccess;
window.showError = showError;
window.showWarning = showWarning;
window.showInfo = showInfo;
window.apiCall = apiCall;
window.refreshDashboard = refreshDashboard;
window.formatFileSize = formatFileSize;

console.log('📦 Main JavaScript loaded successfully');
