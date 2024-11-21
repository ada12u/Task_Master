// API Configuration
const API_BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8080'
    : 'https://task-masters.onrender.com';

// State Management
let authToken = localStorage.getItem('authToken');
let currentUser = JSON.parse(localStorage.getItem('USER_STORAGE_KEY') || 'null');
let tasks = [];

// API Service
const api = {
    async request(endpoint, options = {}) {
        try {
            const headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {})
            };

            console.log('Making request to:', `${API_BASE_URL}${endpoint}`);
            console.log('Request options:', { ...options, headers });

            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                ...options,
                headers,
                mode: 'cors'
            });

            console.log('Response status:', response.status);
            
            try {
                const data = await response.json();
                console.log('Response data:', data);

                if (!response.ok) {
                    throw new Error(data.error || 'Something went wrong');
                }

                return data;
            } catch (jsonError) {
                console.error('JSON parsing error:', jsonError);
                const textResponse = await response.text();
                console.error('Raw response:', textResponse);
                throw new Error('Server response was not in the expected format');
            }
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    },

    // Auth endpoints
    async login(email, password) {
        const data = await this.request('/api/users/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        authToken = data.token;
        currentUser = data.user;
        localStorage.setItem('authToken', authToken);
        localStorage.setItem('USER_STORAGE_KEY', JSON.stringify(currentUser));
        return data;
    },

    async register(name, email, password) {
        const data = await this.request('/api/users/register', {
            method: 'POST',
            body: JSON.stringify({ name, email, password })
        });
        console.log('Registration response:', data);
        return data;
    },

    // Task endpoints
    async getTasks() {
        return await this.request('/api/tasks');
    },

    async getTask(id) {
        return await this.request(`/api/tasks/${id}`);
    },

    async createTask(taskData) {
        return await this.request('/api/tasks', {
            method: 'POST',
            body: JSON.stringify(taskData)
        });
    },

    async updateTask(id, updates) {
        return await this.request(`/api/tasks/${id}`, {
            method: 'PUT',
            body: JSON.stringify(updates)
        });
    },

    async deleteTask(id) {
        return await this.request(`/api/tasks/${id}`, {
            method: 'DELETE'
        });
    },

    async searchTasks(params) {
        const queryString = new URLSearchParams(params).toString();
        return await this.request(`/api/tasks/search?${queryString}`);
    }
};

// UI Utilities
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

function showError(message) {
    showNotification(message, 'error');
}

function showSuccess(message) {
    showNotification(message, 'success');
}

// UI Event Handlers
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
        showError(error.message || 'Login failed. Please try again.');
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
        const data = await api.register(name, email, password);
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
        const task = await api.createTask(taskData);
        hideLoader();
        hideAddTaskModal();
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
        await api.updateTask(taskId, updates);
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
        await api.deleteTask(taskId);
        hideLoader();
        await loadTasks();
        showSuccess('Task deleted successfully!');
    } catch (error) {
        hideLoader();
        showError('Failed to delete task: ' + error.message);
    }
}

async function handleSearch(event) {
    const searchInput = document.querySelector('#search-input');
    const priorityFilter = document.querySelector('#priority-filter');
    const sortBy = document.querySelector('#sort-tasks');

    const params = {
        query: searchInput.value,
        priority: priorityFilter.value,
        sortBy: sortBy.value
    };

    try {
        showLoader('Searching tasks...');
        const searchResults = await api.searchTasks(params);
        hideLoader();
        renderTasks(searchResults);
    } catch (error) {
        hideLoader();
        showError('Search failed: ' + error.message);
    }
}

// Task Rendering
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
    // Auth form listeners
    document.querySelector('#login-form').addEventListener('submit', handleLogin);
    document.querySelector('#register-form').addEventListener('submit', handleRegister);
    
    // Auth tab listeners
    document.querySelector('.auth-tab:nth-child(1)').addEventListener('click', showLoginForm);
    document.querySelector('.auth-tab:nth-child(2)').addEventListener('click', showRegisterForm);
    
    // Task form listeners
    document.querySelector('#add-task-form').addEventListener('submit', handleAddTask);
    
    // Search listeners
    document.querySelector('#search-input').addEventListener('input', debounce(handleSearch, 500));

    // Check authentication status
    const token = localStorage.getItem('authToken');
    const user = JSON.parse(localStorage.getItem('USER_STORAGE_KEY'));

    if (token && user) {
        try {
            // Verify token is still valid
            const response = await fetch(`${API_BASE_URL}/api/users/verify-token`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                showApp();
                await loadTasks();
            } else {
                // Token is invalid, clear storage and show login
                localStorage.removeItem('authToken');
                localStorage.removeItem('USER_STORAGE_KEY');
                showAuth();
            }
        } catch (error) {
            console.error('Token verification failed:', error);
            localStorage.removeItem('authToken');
            localStorage.removeItem('USER_STORAGE_KEY');
            showAuth();
        }
    } else {
        // No token found, show login
        showAuth();
    }
});

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

function showLoginForm() {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginTab = document.querySelector('.auth-tab:nth-child(1)');
    const registerTab = document.querySelector('.auth-tab:nth-child(2)');

    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
    loginTab.classList.add('active');
    registerTab.classList.remove('active');
}

function showRegisterForm() {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginTab = document.querySelector('.auth-tab:nth-child(1)');
    const registerTab = document.querySelector('.auth-tab:nth-child(2)');

    loginForm.classList.add('hidden');
    registerForm.classList.remove('hidden');
    loginTab.classList.remove('active');
    registerTab.classList.add('active');
}

function showAddTaskModal() {
    addTaskModal.classList.remove('hidden');
}

function hideAddTaskModal() {
    addTaskModal.classList.add('hidden');
}

async function loadTasks() {
    try {
        showLoader('Loading tasks...');
        const tasks = await api.getTasks();
        hideLoader();
        renderTasks(tasks);
    } catch (error) {
        hideLoader();
        showError('Failed to load tasks: ' + error.message);
    }
}
