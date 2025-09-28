// BountyBud Main JavaScript

// Copy to clipboard functionality
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent || element.innerText;
    
    navigator.clipboard.writeText(text).then(function() {
        // Show success feedback
        const copyBtn = element.parentElement.querySelector('.copy-btn');
        const originalContent = copyBtn.innerHTML;
        copyBtn.innerHTML = '<i class="bi bi-check"></i>';
        copyBtn.classList.add('btn-success');
        
        setTimeout(() => {
            copyBtn.innerHTML = originalContent;
            copyBtn.classList.remove('btn-success');
        }, 2000);
        
        // Show toast notification
        showToast('Copied to clipboard!', 'success');
    }).catch(function() {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        showToast('Copied to clipboard!', 'success');
    });
}

// Toast notification system
function showToast(message, type = 'info') {
    // Remove existing toasts
    const existingToasts = document.querySelectorAll('.toast-notification');
    existingToasts.forEach(toast => toast.remove());
    
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast-notification alert alert-${type} position-fixed`;
    toast.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 250px;
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.3s ease;
    `;
    toast.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="bi bi-${type === 'success' ? 'check-circle' : 'info-circle'} me-2"></i>
            ${message}
        </div>
    `;
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto remove
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Form validation
function validateDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(domain);
}

// Smooth scrolling for anchor links
document.addEventListener('DOMContentLoaded', function() {
    const links = document.querySelectorAll('a[href^="#"]:not([href="#"])');
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const href = this.getAttribute('href');
            if (href && href !== '#') {
                const target = document.querySelector(href);
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            }
        });
    });
});

// Loading state management
function setLoadingState(button, loading = true) {
    if (loading) {
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Generating...';
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalText || 'Generate';
    }
}

// API request helper
async function makeAPIRequest(url, data) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        showToast('Request failed. Please try again.', 'danger');
        throw error;
    }
}

// Initialize tooltips and popovers if Bootstrap is available
document.addEventListener('DOMContentLoaded', function() {
    if (typeof bootstrap !== 'undefined') {
        // Initialize tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // Initialize popovers
        const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        popoverTriggerList.map(function (popoverTriggerEl) {
            return new bootstrap.Popover(popoverTriggerEl);
        });
    }
});

// Search functionality
function filterItems(searchTerm, itemSelector, searchProperties) {
    const items = document.querySelectorAll(itemSelector);
    const term = searchTerm.toLowerCase();
    
    items.forEach(item => {
        let shouldShow = false;
        
        searchProperties.forEach(prop => {
            const element = item.querySelector(prop);
            if (element && element.textContent.toLowerCase().includes(term)) {
                shouldShow = true;
            }
        });
        
        item.style.display = shouldShow ? 'block' : 'none';
    });
}

// Category filtering
function filterByCategory(category, itemSelector, categoryAttribute) {
    const items = document.querySelectorAll(itemSelector);
    
    items.forEach(item => {
        const itemCategory = item.getAttribute(categoryAttribute);
        const shouldShow = category === 'all' || itemCategory === category;
        item.style.display = shouldShow ? 'block' : 'none';
    });
}

// Theme toggle functionality
function toggleTheme() {
    const html = document.documentElement;
    const themeIcon = document.getElementById('themeIcon');
    
    if (html.getAttribute('data-theme') === 'light') {
        html.setAttribute('data-theme', 'dark');
        themeIcon.className = 'bi bi-moon';
        showToast('Switched to dark theme', 'info');
    } else {
        html.setAttribute('data-theme', 'light');
        themeIcon.className = 'bi bi-sun';
        showToast('Switched to light theme', 'info');
    }
}