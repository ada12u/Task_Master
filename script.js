// Modal Functions
function hideAddTaskModal() {
    const modal = document.getElementById('add-task-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function showAddTaskModal() {
    const modal = document.getElementById('add-task-modal');
    if (modal) {
        modal.style.display = 'block';
    }
}

// Make functions available globally
window.hideAddTaskModal = hideAddTaskModal;
window.showAddTaskModal = showAddTaskModal;

// API Configuration
const API_BASE_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:8080'
    : 'https://task-master-u3ss.onrender.com';

// State Management
let authToken = localStorage.getItem('authToken');
let currentUser = JSON.parse(localStorage.getItem('USER_STORAGE_KEY') || 'null');
let tasks = [];

// Helper Functions
function showLoader(message = 'Loading...') {
    const loader = document.createElement('div');
    loader.className = 'loader-container';
    loader.innerHTML = `
        <div class="loader">
            <div class="spinner"></div>
            <p>${message}</p>
        </div>
    `;
    document.body.appendChild(loader);
}

function hideLoader() {
    const loader = document.querySelector('.loader-container');
    if (loader) {
        loader.remove();
    }
}

function showError(message) {
    showNotification(message, 'error');
}

function showSuccess(message) {
    showNotification(message, 'success');
}

function getToken() {
    return localStorage.getItem('authToken');
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <p>${message}</p>
            <button class="close-btn">&times;</button>
        </div>
    `;
    document.body.appendChild(notification);

    // Add close button functionality
    const closeBtn = notification.querySelector('.close-btn');
    closeBtn.addEventListener('click', () => {
        notification.remove();
    });

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification && notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

// API Service
const api = {
    async request(endpoint, options = {}, retries = 3) {
        try {
            const headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            };

            if (!endpoint.includes('/api/users/login') && !endpoint.includes('/api/users/register')) {
                const token = getToken();
                if (!token) {
                    throw new Error('No authentication token found');
                }
                headers.Authorization = `Bearer ${token}`;
            }

            const url = `${API_BASE_URL}${endpoint}`;
            console.log('Making request to:', url);
            
            const requestOptions = {
                method: options.method || 'GET',
                headers,
                credentials: 'include',
                mode: 'cors',
                ...(options.body && { body: typeof options.body === 'string' ? options.body : JSON.stringify(options.body) })
            };
            
            console.log('Request options:', requestOptions);

            try {
                const response = await fetch(url, requestOptions);
                
                // First check if the server is responding
                if (!response) {
                    throw new Error('No response from server');
                }

                // Try to parse JSON response
                let data;
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    data = await response.json();
                } else {
                    throw new Error(`Invalid response type: ${contentType}`);
                }

                // Check if response was successful
                if (!response.ok) {
                    throw new Error(data.message || `Server error: ${response.status}`);
                }

                return data;
            } catch (fetchError) {
                console.error('Fetch error:', fetchError);
                if (retries > 0) {
                    console.log(`Retrying request... (${retries} attempts left)`);
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    return this.request(endpoint, options, retries - 1);
                }
                throw new Error(`Network error: ${fetchError.message}`);
            }
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    },

    async login(email, password) {
        try {
            const response = await this.request('/api/users/login', {
                method: 'POST',
                body: { email, password }
            });

            if (response.token) {
                localStorage.setItem('authToken', response.token);
                localStorage.setItem('USER_STORAGE_KEY', JSON.stringify(response.user));
                authToken = response.token;
                currentUser = response.user;
            }

            return response;
        } catch (error) {
            console.error('Login failed:', error);
            throw error;
        }
    },

    async requestPasswordReset(email) {
        try {
            showLoader('Requesting password reset...');
            const response = await this.request('/api/users/forgot-password', {
                method: 'POST',
                body: { email }
            });
            hideLoader();
            showSuccess('Password reset instructions have been sent to your email.');
            showLoginForm();
            return response;
        } catch (error) {
            hideLoader();
            showError(error.message);
            throw error;
        }
    },

    async resetPassword(token, password) {
        try {
            showLoader('Resetting password...');
            const response = await this.request('/api/users/reset-password', {
                method: 'POST',
                body: { token, password }
            });
            hideLoader();
            showSuccess('Password reset successful. Please login with your new password.');
            showLoginForm();
            return response;
        } catch (error) {
            hideLoader();
            showError(error.message);
            throw error;
        }
    }
};

// Form Handling Functions
window.showPasswordResetForm = function() {
    try {
        const authForms = document.querySelectorAll('.auth-form');
        authForms.forEach(form => form.classList.add('hidden'));

        let resetForm = document.getElementById('password-reset-form');
        if (!resetForm) {
            resetForm = document.createElement('form');
            resetForm.id = 'password-reset-form';
            resetForm.className = 'auth-form';
            resetForm.innerHTML = `
                <h3>Reset Password</h3>
                <p>Enter your email address to receive a password reset link.</p>
                <input type="email" name="email" placeholder="Email" required>
                <button type="submit" class="btn-primary">Reset Password</button>
                <button type="button" class="btn-secondary" onclick="showLoginForm()">Back to Login</button>
            `;
            
            const authContainer = document.querySelector('.auth-container');
            if (authContainer) {
                authContainer.appendChild(resetForm);
            }
        }
        
        resetForm.classList.remove('hidden');
        resetForm.addEventListener('submit', handlePasswordResetRequest);
    } catch (error) {
        console.error('Error showing password reset form:', error);
        showError('Failed to show password reset form. Please try again.');
    }
};

async function handlePasswordResetRequest(event) {
    event.preventDefault();
    const email = event.target.email.value;
    try {
        await api.requestPasswordReset(email);
    } catch (error) {
        showError(error.message);
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    // Add event listeners for modals
    window.onclick = function(event) {
        const modal = document.getElementById('add-task-modal');
        if (event.target === modal) {
            hideAddTaskModal();
        }
    };
});

// Global form functions
window.showLoginForm = function() {
    const loginForm = document.querySelector('#login-form');
    const registerForm = document.querySelector('#register-form');
    const loginTab = document.querySelector('.auth-tab:nth-child(1)');
    const registerTab = document.querySelector('.auth-tab:nth-child(2)');

    if (loginForm && registerForm && loginTab && registerTab) {
        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');
        loginTab.classList.add('active');
        registerTab.classList.remove('active');
    }
};

window.showRegisterForm = function() {
    const loginForm = document.querySelector('#login-form');
    const registerForm = document.querySelector('#register-form');
    const loginTab = document.querySelector('.auth-tab:nth-child(1)');
    const registerTab = document.querySelector('.auth-tab:nth-child(2)');

    if (loginForm && registerForm && loginTab && registerTab) {
        registerForm.classList.remove('hidden');
        loginForm.classList.add('hidden');
        loginTab.classList.remove('active');
        registerTab.classList.add('active');
    }
};

// Logout function
function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('USER_STORAGE_KEY');
    authToken = null;
    currentUser = null;
    showAuth();
    showSuccess('Logged out successfully');
}

// Utility Functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Toggle task completion status
window.toggleTaskComplete = async function(taskId) {
    try {
        const token = getToken();
        if (!token) {
            throw new Error('No authentication token found');
        }

        const response = await fetch(`${API_BASE_URL}/api/tasks/${taskId}/toggle`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || `HTTP error! status: ${response.status}`);
        }

        await loadTasks(); // Refresh the task list
    } catch (error) {
        console.error('Error toggling task:', error);
        showError('Failed to update task status');
    }
};

// Search tasks
window.searchTasks = async function(criteria) {
    try {
        const token = getToken();
        if (!token) {
            throw new Error('No authentication token found');
        }

        const queryParams = new URLSearchParams(criteria).toString();
        const response = await fetch(`${API_BASE_URL}/api/tasks/search?${queryParams}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || `HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error searching tasks:', error);
        showError('Failed to search tasks');
        return [];
    }
};

// Delete task
window.deleteTask = async function(taskId) {
    if (!confirm('Are you sure you want to delete this task?')) {
        return;
    }

    try {
        const token = getToken();
        if (!token) {
            throw new Error('No authentication token found');
        }

        const response = await fetch(`${API_BASE_URL}/api/tasks/${taskId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || `HTTP error! status: ${response.status}`);
        }

        await loadTasks(); // Refresh the task list
    } catch (error) {
        console.error('Error deleting task:', error);
        showError('Failed to delete task');
    }
};

// DOM Elements
const authSection = document.getElementById('auth-section');
const appSection = document.getElementById('app-section');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const addTaskModal = document.getElementById('add-task-modal');
const addTaskForm = document.getElementById('add-task-form');
const tasksContainer = document.getElementById('tasks-container');
const searchInput = document.getElementById('search-input');
const sortSelect = document.getElementById('sort-tasks');

// Authentication Functions

// UI Functions
function showApp() {
    authSection.classList.add('hidden');
    appSection.classList.remove('hidden');
    document.getElementById('user-name').textContent = currentUser.name;
}

function showAuth() {
    authSection.classList.remove('hidden');
    appSection.classList.add('hidden');
}

async function loadTasks() {
    try {
        showLoader('Loading tasks...');
        const tasks = await api.request('/api/tasks');
        hideLoader();
        renderTasks(tasks);
    } catch (error) {
        hideLoader();
        showError('Failed to load tasks: ' + error.message);
    }
}

function renderTasks(tasks) {
    const container = document.querySelector('#tasks-container');
    const template = document.querySelector('#task-template');
    
    container.innerHTML = '';
    
    if (tasks.length === 0) {
        container.innerHTML = '<p class="no-tasks">No tasks found</p>';
        return;
    }

    tasks.forEach(task => {
        const taskElement = template.content.cloneNode(true);
        
        taskElement.querySelector('.task-title').textContent = task.title;
        taskElement.querySelector('.task-description').textContent = task.description;
        taskElement.querySelector('.deadline').textContent = new Date(task.deadline).toLocaleString();
        taskElement.querySelector('.priority').textContent = task.priority;
        
        const taskCard = taskElement.querySelector('.task-card');
        taskCard.dataset.taskId = task._id;
        taskCard.classList.add(`priority-${task.priority}`);
        if (task.completed) {
            taskCard.classList.add('completed');
        }

        container.appendChild(taskElement);
    });
}

// Initial page load
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Initialize UI elements
        const loginForm = document.querySelector('#login-form');
        const registerForm = document.querySelector('#register-form');
        const passwordResetForm = document.querySelector('#password-reset-form');
        const passwordResetTokenForm = document.querySelector('#password-reset-token-form');
        const addTaskForm = document.querySelector('#add-task-form');
        const searchInput = document.querySelector('#search-input');
        const sortSelect = document.querySelector('#sort-tasks');
        const showCompletedCheckbox = document.querySelector('#show-completed');

        // Check authentication status
        const token = getToken();
        const user = JSON.parse(localStorage.getItem('USER_STORAGE_KEY'));
        
        if (!token || !user) {
            // Clear any stale data
            localStorage.removeItem('authToken');
            localStorage.removeItem('USER_STORAGE_KEY');
            showAuth();
        } else {
            // Verify token with server
            try {
                const response = await api.request('/api/users/verify-token');
                if (response.valid) {
                    currentUser = user;
                    showApp();
                    await loadTasks();
                } else {
                    throw new Error('Invalid token');
                }
            } catch (error) {
                console.error('Token verification failed:', error);
                localStorage.removeItem('authToken');
                localStorage.removeItem('USER_STORAGE_KEY');
                showAuth();
            }
        }

        // Auth form listeners
        if (loginForm) loginForm.addEventListener('submit', handleLogin);
        if (registerForm) registerForm.addEventListener('submit', handleRegister);
        if (passwordResetForm) passwordResetForm.addEventListener('submit', handlePasswordResetRequest);
        if (passwordResetTokenForm) passwordResetTokenForm.addEventListener('submit', handlePasswordReset);

        // Task form listeners
        if (addTaskForm) addTaskForm.addEventListener('submit', handleAddTask);
        
        // Search and filter listeners
        if (searchInput) searchInput.addEventListener('input', debouncedSearch);
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                const currentFilters = {
                    sortBy: e.target.value,
                    priority: document.querySelector('.priority-filters .active')?.dataset.priority,
                    completed: showCompletedCheckbox?.checked
                };
                filterTasks(currentFilters);
            });
        }

        // Priority filter listeners
        document.querySelectorAll('.priority-badge').forEach(badge => {
            if (badge) {
                badge.dataset.priority = badge.classList.contains('high') ? 'high' : 
                                       badge.classList.contains('medium') ? 'medium' : 'low';
                
                badge.addEventListener('click', (e) => {
                    document.querySelectorAll('.priority-badge').forEach(b => b.classList.remove('active'));
                    e.target.classList.toggle('active');

                    const currentFilters = {
                        sortBy: sortSelect?.value || 'deadline',
                        priority: e.target.classList.contains('active') ? e.target.dataset.priority : null,
                        completed: showCompletedCheckbox?.checked
                    };
                    filterTasks(currentFilters);
                });
            }
        });

        // Add "Forgot Password" link
        const forgotPasswordLink = document.createElement('a');
        forgotPasswordLink.href = '#';
        forgotPasswordLink.textContent = 'Forgot Password?';
        forgotPasswordLink.className = 'forgot-password-link';
        forgotPasswordLink.onclick = showPasswordResetForm;
        
        if (loginForm) {
            loginForm.appendChild(forgotPasswordLink);
        }
    } catch (error) {
        console.error('Initialization error:', error);
        showAuth();
    }
});

async function handleLogin(event) {
    event.preventDefault();
    try {
        showLoader('Logging in...');
        const formData = new FormData(event.target);
        const email = formData.get('email');
        const password = formData.get('password');

        const data = await api.login(email, password);
        hideLoader();
        showSuccess(`Welcome back, ${data.user.name}!`);
        showApp();
        await loadTasks();
    } catch (error) {
        hideLoader();
        showError(error.message || 'Login failed. Please check your credentials.');
    }
}

async function handleRegister(event) {
    event.preventDefault();
    try {
        const formData = new FormData(event.target);
        const name = formData.get('name');
        const email = formData.get('email');
        const password = formData.get('password');
        const confirmPassword = formData.get('confirmPassword');

        // Validate form data
        if (!name || !email || !password || !confirmPassword) {
            throw new Error('All fields are required');
        }

        if (password !== confirmPassword) {
            throw new Error('Passwords do not match');
        }

        showLoader('Creating your account...');
        const data = await api.request('/api/users/register', {
            method: 'POST',
            body: JSON.stringify({ name, email, password })
        });
        hideLoader();
        showSuccess('Registration successful! Please check your email to verify your account.');
        showLoginForm();
    } catch (error) {
        hideLoader();
        showError(error.message || 'Registration failed. Please try again.');
    }
}

async function handleAddTask(event) {
    event.preventDefault();
    const form = event.target;
    const taskData = {
        title: form.querySelector('#task-title').value,
        description: form.querySelector('#task-description').value,
        deadline: form.querySelector('#task-deadline').value,
        priority: form.querySelector('#task-priority').value
    };

    try {
        showLoader('Creating task...');
        const task = await api.request('/api/tasks', {
            method: 'POST',
            body: JSON.stringify(taskData)
        });
        hideLoader();
        window.hideAddTaskModal();
        await loadTasks();
        showSuccess('Task created successfully!');
    } catch (error) {
        hideLoader();
        showError('Failed to create task: ' + error.message);
    }
}

async function handleUpdateTask(taskId, updates) {
    try {
        showLoader('Updating task...');
        await api.request(`/api/tasks/${taskId}`, {
            method: 'PUT',
            body: JSON.stringify(updates)
        });
        hideLoader();
        await loadTasks();
        showSuccess('Task updated successfully!');
    } catch (error) {
        hideLoader();
        showError('Failed to update task: ' + error.message);
    }
}

async function handleDeleteTask(taskId) {
    if (!confirm('Are you sure you want to delete this task?')) {
        return;
    }

    try {
        showLoader('Deleting task...');
        await api.request(`/api/tasks/${taskId}`, {
            method: 'DELETE'
        });
        hideLoader();
        await loadTasks();
        showSuccess('Task deleted successfully!');
    } catch (error) {
        hideLoader();
        showError('Failed to delete task: ' + error.message);
    }
}

async function handleSearch(event) {
    try {
        const searchInput = document.querySelector('#search-input');
        const priorityFilter = document.querySelector('#priority-filter');
        const sortBy = document.querySelector('#sort-tasks');

        // Create filters object with null checks
        const filters = {
            search: searchInput?.value || '',
            priority: priorityFilter?.value || '',
            sortBy: sortBy?.value || 'deadline'
        };

        // Use the existing filterTasks function which already has proper error handling
        await filterTasks(filters);
    } catch (error) {
        console.error('Search error:', error);
        showError('Search failed: ' + error.message);
    }
}

// Add debounced search handler
const debouncedSearch = debounce(handleSearch, 300);

// Add event listeners for search inputs
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.querySelector('#search-input');
    const priorityFilter = document.querySelector('#priority-filter');
    const sortBy = document.querySelector('#sort-tasks');

    if (searchInput) {
        searchInput.addEventListener('input', debouncedSearch);
    }
    if (priorityFilter) {
        priorityFilter.addEventListener('change', handleSearch);
    }
    if (sortBy) {
        sortBy.addEventListener('change', handleSearch);
    }
});

// Task Filtering and Sorting
async function filterTasks(filters = {}) {
    try {
        showLoader('Filtering tasks...');
        
        const queryParams = new URLSearchParams();
        if (filters.priority) queryParams.append('priority', filters.priority);
        if (filters.completed !== undefined) queryParams.append('completed', filters.completed);
        if (filters.startDate) queryParams.append('startDate', filters.startDate);
        if (filters.endDate) queryParams.append('endDate', filters.endDate);
        if (filters.search) queryParams.append('query', filters.search);

        const tasks = await api.request(`/api/tasks/search?${queryParams.toString()}`);
        renderTasks(sortTasks(tasks, filters.sortBy));
        hideLoader();
    } catch (error) {
        hideLoader();
        showError('Failed to filter tasks: ' + error.message);
    }
}

function sortTasks(tasks, sortBy = 'deadline') {
    return [...tasks].sort((a, b) => {
        switch (sortBy) {
            case 'deadline':
                return new Date(a.deadline) - new Date(b.deadline);
            case 'priority':
                const priorityOrder = { high: 0, medium: 1, low: 2 };
                return priorityOrder[a.priority] - priorityOrder[b.priority];
            case 'created':
                return new Date(b.createdAt) - new Date(a.createdAt);
            default:
                return 0;
        }
    });
}
