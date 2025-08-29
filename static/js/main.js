// Main JavaScript for Political Event Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initAnimations();
    initFormHandlers();
    initEventCards();
    initFileUploads();
    initRealTimeUpdates();
    initQRCodeScanner();
});

// Smooth Animations
function initAnimations() {
    // Add animation classes to elements
    const animatedElements = document.querySelectorAll('.card, .event-card, .stat-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in-up');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });
    
    animatedElements.forEach(el => observer.observe(el));
    
    // Navbar scroll effect
    window.addEventListener('scroll', () => {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(255, 255, 255, 0.98)';
            navbar.style.boxShadow = '0 2px 30px rgba(0, 0, 0, 0.15)';
        } else {
            navbar.style.background = 'rgba(255, 255, 255, 0.95)';
            navbar.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.1)';
        }
    });
}

// Form Handlers
function initFormHandlers() {
    // Form validation and enhancement
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;
            
            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    isValid = false;
                    showFieldError(field, 'This field is required');
                } else {
                    clearFieldError(field);
                }
            });
            
            if (!isValid) {
                e.preventDefault();
                showNotification('Please fill in all required fields', 'error');
            }
        });
        
        // Real-time validation
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('blur', validateField);
            input.addEventListener('input', clearFieldError);
        });
    });
}

// Field validation
function validateField(e) {
    const field = e.target;
    const value = field.value.trim();
    
    // Email validation
    if (field.type === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            showFieldError(field, 'Please enter a valid email address');
        }
    }
    
    // Phone validation
    if (field.name === 'phone' && value) {
        const phoneRegex = /^[0-9]{10}$/;
        if (!phoneRegex.test(value)) {
            showFieldError(field, 'Please enter a valid 10-digit phone number');
        }
    }
    
    // Password validation
    if (field.type === 'password' && value) {
        if (value.length < 6) {
            showFieldError(field, 'Password must be at least 6 characters long');
        }
    }
}

function showFieldError(field, message) {
    clearFieldError(field);
    field.style.borderColor = '#ff416c';
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error';
    errorDiv.style.color = '#ff416c';
    errorDiv.style.fontSize = '0.875rem';
    errorDiv.style.marginTop = '5px';
    errorDiv.textContent = message;
    field.parentNode.appendChild(errorDiv);
}

function clearFieldError(field) {
    field.style.borderColor = '#e9ecef';
    const errorDiv = field.parentNode.querySelector('.field-error');
    if (errorDiv) {
        errorDiv.remove();
    }
}

// Event Cards Enhancement
function initEventCards() {
    const eventCards = document.querySelectorAll('.event-card');
    
    eventCards.forEach(card => {
        // Add click effect
        card.addEventListener('click', function(e) {
            if (!e.target.classList.contains('btn')) {
                this.style.transform = 'scale(0.98)';
                setTimeout(() => {
                    this.style.transform = '';
                }, 150);
            }
        });
        
        // Add hover sound effect (optional)
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-10px) scale(1.02)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
    });
}

// File Upload Enhancement
function initFileUploads() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Show file name
                const label = this.parentNode.querySelector('.file-upload-label');
                if (label) {
                    label.textContent = `Selected: ${file.name}`;
                    label.style.color = '#56ab2f';
                }
                
                // Preview image if it's an image file
                if (file.type.startsWith('image/')) {
                    showImagePreview(file, this);
                }
            }
        });
    });
}

function showImagePreview(file, input) {
    const reader = new FileReader();
    reader.onload = function(e) {
        const previewContainer = input.parentNode.parentNode.querySelector('.image-preview');
        if (!previewContainer) {
            const container = document.createElement('div');
            container.className = 'image-preview mt-2';
            container.style.textAlign = 'center';
            input.parentNode.parentNode.appendChild(container);
        }
        
        const img = document.createElement('img');
        img.src = e.target.result;
        img.style.maxWidth = '200px';
        img.style.maxHeight = '200px';
        img.style.borderRadius = '10px';
        img.style.boxShadow = '0 5px 15px rgba(0,0,0,0.1)';
        
        const container = input.parentNode.parentNode.querySelector('.image-preview');
        container.innerHTML = '';
        container.appendChild(img);
    };
    reader.readAsDataURL(file);
}

// Real-time Updates
function initRealTimeUpdates() {
    // Update event stats every 30 seconds for admin
    if (document.querySelector('.admin-dashboard')) {
        setInterval(updateEventStats, 30000);
    }
    
    // Auto-refresh pending users list
    if (document.querySelector('.pending-users')) {
        setInterval(refreshPendingUsers, 60000);
    }
}

function updateEventStats() {
    const eventCards = document.querySelectorAll('[data-event-id]');
    
    eventCards.forEach(card => {
        const eventId = card.dataset.eventId;
        fetch(`/api/event_stats/${eventId}`)
            .then(response => response.json())
            .then(data => {
                if (data.total_registered !== undefined) {
                    const statsElement = card.querySelector('.event-stats');
                    if (statsElement) {
                        statsElement.innerHTML = `
                            <div class="stat-item">
                                <span class="stat-number">${data.total_registered}</span>
                                <span class="stat-label">Registered</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-number">${data.checked_in}</span>
                                <span class="stat-label">Checked In</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-number">${data.not_attended}</span>
                                <span class="stat-label">Not Attended</span>
                            </div>
                        `;
                    }
                }
            })
            .catch(error => console.error('Error updating stats:', error));
    });
}

function refreshPendingUsers() {
    // This would typically make an AJAX call to refresh the pending users list
    // For now, we'll just show a notification
    showNotification('Checking for new user registrations...', 'info');
}

// QR Code Scanner (Basic Implementation)
function initQRCodeScanner() {
    const scanButtons = document.querySelectorAll('.scan-qr-btn');
    
    scanButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Show scanning animation
            const originalText = this.textContent;
            this.innerHTML = '<span class="loading"></span> Scanning...';
            this.disabled = true;
            
            // Simulate scanning process
            setTimeout(() => {
                this.textContent = originalText;
                this.disabled = false;
                
                // Redirect to scan page
                const eventId = this.dataset.eventId;
                window.location.href = `/scan_qr/${eventId}`;
            }, 2000);
        });
    });
}

// Notification System
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 10px;
        color: white;
        font-weight: 600;
        z-index: 10000;
        transform: translateX(100%);
        transition: transform 0.3s ease;
        max-width: 300px;
    `;
    
    // Set background based on type
    switch(type) {
        case 'success':
            notification.style.background = 'linear-gradient(135deg, #56ab2f, #a8e6cf)';
            break;
        case 'error':
            notification.style.background = 'linear-gradient(135deg, #ff416c, #ff4b2b)';
            break;
        case 'warning':
            notification.style.background = 'linear-gradient(135deg, #f39c12, #f1c40f)';
            break;
        default:
            notification.style.background = 'linear-gradient(135deg, #667eea, #764ba2)';
    }
    
    notification.textContent = message;
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 5000);
}

// Search and Filter Functionality
function initSearchAndFilter() {
    const searchInput = document.querySelector('#search-events');
    const filterSelect = document.querySelector('#filter-party');
    
    if (searchInput) {
        searchInput.addEventListener('input', filterEvents);
    }
    
    if (filterSelect) {
        filterSelect.addEventListener('change', filterEvents);
    }
}

function filterEvents() {
    const searchTerm = document.querySelector('#search-events')?.value.toLowerCase();
    const filterParty = document.querySelector('#filter-party')?.value;
    const eventCards = document.querySelectorAll('.event-card');
    
    eventCards.forEach(card => {
        const title = card.querySelector('.event-title')?.textContent.toLowerCase();
        const party = card.querySelector('.event-party')?.textContent;
        const description = card.querySelector('.event-description')?.textContent.toLowerCase();
        
        let showCard = true;
        
        // Search filter
        if (searchTerm) {
            showCard = title.includes(searchTerm) || description.includes(searchTerm);
        }
        
        // Party filter
        if (filterParty && filterParty !== 'all') {
            showCard = showCard && party === filterParty;
        }
        
        // Show/hide card with animation
        if (showCard) {
            card.style.display = 'block';
            setTimeout(() => {
                card.style.opacity = '1';
                card.style.transform = 'scale(1)';
            }, 50);
        } else {
            card.style.opacity = '0';
            card.style.transform = 'scale(0.8)';
            setTimeout(() => {
                card.style.display = 'none';
            }, 300);
        }
    });
}

// Smooth Scrolling
function initSmoothScrolling() {
    const links = document.querySelectorAll('a[href^="#"]');
    
    links.forEach(link => {
        link.addEventListener('click', function(e) {
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

// Initialize additional features
document.addEventListener('DOMContentLoaded', function() {
    initSearchAndFilter();
    initSmoothScrolling();
    
    // Add loading states to buttons
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            if (!this.disabled) {
                this.style.opacity = '0.7';
                setTimeout(() => {
                    this.style.opacity = '1';
                }, 1000);
            }
        });
    });
});

// Export functions for global use
window.PoliticalEvents = {
    showNotification,
    updateEventStats,
    filterEvents
};

