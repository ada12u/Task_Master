require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const rateLimit = require('express-rate-limit');

// Import models
const User = require('./models/User');
const Task = require('./models/Task');

const app = express();
const PORT = process.env.PORT || 8080;

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files with proper MIME types
app.use(express.static(path.join(__dirname), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.js')) {
            res.set('Content-Type', 'application/javascript');
        } else if (filePath.endsWith('.css')) {
            res.set('Content-Type', 'text/css');
        } else if (filePath.endsWith('.html')) {
            res.set('Content-Type', 'text/html');
        }
    }
}));

// Serve index.html for all routes except /api
app.get('*', (req, res, next) => {
    if (req.url.startsWith('/api')) {
        next();
    } else {
        res.sendFile(path.join(__dirname, 'index.html'));
    }
});

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// CORS configuration
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'https://task-master-u3ss.onrender.com'
];

// CORS middleware with detailed logging
app.use(cors({
    origin: function(origin, callback) {
        console.log('Request Origin:', origin);
        
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) {
            console.log('Allowing request with no origin');
            return callback(null, true);
        }
        
        if (allowedOrigins.includes(origin)) {
            console.log('Allowed origin:', origin);
            callback(null, origin);
        } else {
            console.log('Blocked origin:', origin);
            callback(new Error(`Origin ${origin} not allowed by CORS`));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie'],
    credentials: true,
    maxAge: 86400 // 24 hours
}));

// Additional security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// Request logging middleware
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${res.statusCode} (${duration}ms)`);
        
        // Log additional details for errors
        if (res.statusCode >= 400) {
            console.log('Request Headers:', req.headers);
            console.log('Request Body:', req.body);
            console.log('Query Parameters:', req.query);
        }
    });
    next();
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// API Routes
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'API is healthy', timestamp: new Date().toISOString() });
});

// User Routes
app.post('/api/users/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Create new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        // Create token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Error creating user' });
    }
});

// Add content-type middleware for API routes
app.use('/api', (req, res, next) => {
    res.header('Content-Type', 'application/json');
    next();
});

// Logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);

    // MongoDB errors
    if (err.name === 'MongoError' || err.name === 'MongoServerError') {
        return res.status(500).json({
            success: false,
            message: 'Database error occurred',
            error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
        });
    }

    // Validation errors
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: 'Validation error',
            errors: Object.values(err.errors).map(e => e.message)
        });
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }

    // Default error
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err : {}
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// Updated rate limiting configuration
const rateLimitConfig = {
    standard: rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: {
            status: 'error',
            message: 'Too many requests',
            details: 'Please try again after 15 minutes'
        }
    }),
    auth: rateLimit({
        windowMs: 60 * 60 * 1000, // 1 hour
        max: 5, // limit each IP to 5 failed login attempts per hour
        message: {
            status: 'error',
            message: 'Too many login attempts',
            details: 'Please try again after 1 hour'
        }
    })
};

// Apply rate limiting
app.use('/api/', rateLimitConfig.standard);
app.use('/api/users/login', rateLimitConfig.auth);
app.use('/api/users/register', rateLimitConfig.auth);

// Authentication Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            throw new Error('No authentication token found');
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decoded.userId });

        if (!user) {
            throw new Error('User not found');
        }

        req.token = token;
        req.user = user;
        next();
    } catch (error) {
        res.status(401).send({ error: 'Please authenticate.' });
    }
};

// User Login
app.post('/api/users/login', async (req, res) => {
    try {
        console.log('\n=== Login Attempt ===');
        console.log('Request Origin:', req.headers.origin);
        console.log('Request Headers:', req.headers);
        
        const { email, password } = req.body;
        
        if (!email || !password) {
            console.log('Missing credentials');
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            console.log('User not found:', email);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Invalid password for user:', email);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log('Login successful for user:', email);
        
        res.status(200).json({
            success: true,
            token,
            user: {
                _id: user._id,
                email: user.email,
                name: user.name
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login' 
        });
    }
});

// User Registration
app.post('/api/users/register', async (req, res) => {
    try {
        console.log('\n=== Registration Attempt ===');
        console.log('Request body:', req.body);

        const { name, email, password } = req.body;

        // Validate required fields
        if (!name || !email || !password) {
            console.log('Missing required fields');
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        console.log('User exists:', existingUser ? 'Yes' : 'No');

        if (existingUser) {
            console.log('User already exists');
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Create new user
        const user = new User({
            name,
            email,
            password // Password will be hashed by the User model pre-save middleware
        });

        // Save user to database
        const savedUser = await user.save();
        console.log('User saved successfully:', savedUser._id);

        // Generate JWT token
        const token = jwt.sign(
            { userId: savedUser._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        console.log('\n--- Registration Response ---');
        console.log('Status: 201');
        console.log('Response:', { 
            message: 'Registration successful',
            user: {
                id: savedUser._id,
                name: savedUser.name,
                email: savedUser.email
            }
        });

        res.status(201).json({
            message: 'Registration successful',
            user: {
                id: savedUser._id,
                name: savedUser.name,
                email: savedUser.email
            },
            token
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed: ' + error.message });
    }
});

// Password Reset Routes
app.post('/api/users/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        console.log('Password reset requested for:', email);

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate reset token
        const resetToken = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Save reset token to user
        user.resetToken = resetToken;
        user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
        await user.save();

        // In a real application, you would send an email here
        console.log('Reset token generated:', resetToken);
        
        res.json({ 
            message: 'Password reset instructions sent to email',
            // Only in development - remove in production
            resetToken: resetToken 
        });
    } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({ 
            error: 'Failed to process password reset request',
            details: error.message 
        });
    }
});

app.post('/api/users/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        console.log('Password reset attempt with token');

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Find user
        const user = await User.findOne({ 
            _id: decoded.userId,
            resetToken: token,
            resetTokenExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Update user password and clear reset token
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ 
            error: 'Failed to reset password',
            details: error.message 
        });
    }
});

// Email Configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Test email configuration
transporter.verify(function(error, success) {
    if (error) {
        console.log('Email configuration error:', error);
    } else {
        console.log('Email server is ready to send messages');
    }
});

// Password validation function
const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) return 'Password must be at least 8 characters long';
    if (!hasUpperCase) return 'Password must contain at least one uppercase letter';
    if (!hasLowerCase) return 'Password must contain at least one lowercase letter';
    if (!hasNumbers) return 'Password must contain at least one number';
    if (!hasSpecialChar) return 'Password must contain at least one special character';

    return null;
};

// Task Routes with RESTful principles
// GET /api/tasks - Get all tasks for a user
app.get('/api/tasks', auth, async (req, res) => {
    try {
        console.log('\n=== Fetching Tasks ===');
        const tasks = await Task.find({ userId: req.user._id })
            .sort({ deadline: 1 });
        console.log('Tasks fetched successfully');
        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ 
            error: 'Failed to fetch tasks',
            details: error.message 
        });
    }
});

// Task filtering route - MUST come before /:id route
app.get('/api/tasks/search', auth, async (req, res) => {
    try {
        console.log('\n=== Filtering Tasks ===');
        console.log('Filter criteria:', req.query);
        console.log('User:', req.user);

        const { priority, completed, startDate, endDate, query } = req.query;
        const searchCriteria = { userId: req.user._id.toString() };

        if (priority) {
            searchCriteria.priority = priority;
        }

        if (completed !== undefined) {
            searchCriteria.completed = completed === 'true';
        }

        if (startDate || endDate) {
            searchCriteria.deadline = {};
            if (startDate) {
                searchCriteria.deadline.$gte = new Date(startDate);
            }
            if (endDate) {
                searchCriteria.deadline.$lte = new Date(endDate);
            }
        }

        if (query) {
            searchCriteria.$or = [
                { title: new RegExp(query, 'i') },
                { description: new RegExp(query, 'i') }
            ];
        }

        console.log('Final search criteria:', JSON.stringify(searchCriteria, null, 2));

        const tasks = await Task.find(searchCriteria).sort({ deadline: 1 });
        console.log(`Found ${tasks.length} tasks`);

        res.json(tasks);
    } catch (error) {
        console.error('Filter tasks error:', error);
        res.status(500).json({ 
            error: 'Failed to filter tasks',
            details: error.message,
            stack: error.stack
        });
    }
});

// GET /api/tasks/:id - Get a specific task
app.get('/api/tasks/:id', auth, async (req, res) => {
    try {
        console.log('\n=== Fetching Task ===');
        const task = await Task.findOne({ 
            _id: req.params.id,
            userId: req.user._id 
        });
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        res.json(task);
    } catch (error) {
        console.error('Error fetching task:', error);
        res.status(500).json({ 
            error: 'Failed to fetch task',
            details: error.message 
        });
    }
});

// POST /api/tasks - Create a new task
app.post('/api/tasks', auth, async (req, res) => {
    try {
        console.log('\n=== Creating Task ===');
        const { title, description, deadline, priority } = req.body;

        // Validate required fields
        if (!title || !deadline || !priority) {
            console.log('Missing required fields');
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['title', 'deadline', 'priority']
            });
        }

        // Validate priority
        const validPriorities = ['low', 'medium', 'high'];
        if (!validPriorities.includes(priority)) {
            console.log('Invalid priority level');
            return res.status(400).json({ 
                error: 'Invalid priority level',
                validOptions: validPriorities 
            });
        }

        const task = new Task({
            userId: req.user._id,
            title,
            description,
            deadline: new Date(deadline),
            priority
        });

        await task.save();

        // Send email notification for task creation
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.user.email,
            subject: 'New Task Created - TaskMaster',
            html: `
                <h1>New Task Created</h1>
                <p><strong>Title:</strong> ${title}</p>
                <p><strong>Deadline:</strong> ${new Date(deadline).toLocaleString()}</p>
                <p><strong>Priority:</strong> ${priority}</p>
                <p>Login to TaskMaster to view more details.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        console.log('Task created successfully');
        res.status(201).json(task);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ 
            error: 'Failed to create task',
            details: error.message 
        });
    }
});

// PUT /api/tasks/:id - Update a task
app.put('/api/tasks/:id', auth, async (req, res) => {
    try {
        console.log('\n=== Updating Task ===');
        const updates = req.body;
        const allowedUpdates = ['title', 'description', 'deadline', 'priority', 'completed'];
        
        // Validate update fields
        const updateFields = Object.keys(updates);
        const isValidOperation = updateFields.every(field => allowedUpdates.includes(field));
        
        if (!isValidOperation) {
            console.log('Invalid updates');
            return res.status(400).json({ 
                error: 'Invalid updates',
                allowedUpdates 
            });
        }

        const task = await Task.findOne({ 
            _id: req.params.id,
            userId: req.user._id 
        });

        if (!task) {
            console.log('Task not found');
            return res.status(404).json({ error: 'Task not found' });
        }

        // Update task fields
        updateFields.forEach(field => task[field] = updates[field]);
        
        // If updating deadline, ensure it's a valid date
        if (updates.deadline) {
            task.deadline = new Date(updates.deadline);
        }

        await task.save();

        // Send email notification for task update
        if (updates.completed) {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: req.user.email,
                subject: 'Task Completed - TaskMaster',
                html: `
                    <h1>Task Completed</h1>
                    <p><strong>Title:</strong> ${task.title}</p>
                    <p><strong>Completed on:</strong> ${new Date().toLocaleString()}</p>
                    <p>Great job on completing your task!</p>
                `
            };

            await transporter.sendMail(mailOptions);
        }

        console.log('Task updated successfully');
        res.json(task);
    } catch (error) {
        console.error('Error updating task:', error);
        res.status(500).json({ 
            error: 'Failed to update task',
            details: error.message 
        });
    }
});

// DELETE /api/tasks/:id - Delete a task
app.delete('/api/tasks/:id', auth, async (req, res) => {
    try {
        console.log('\n=== Deleting Task ===');
        const task = await Task.findOneAndDelete({ 
            _id: req.params.id,
            userId: req.user._id 
        });

        if (!task) {
            console.log('Task not found');
            return res.status(404).json({ error: 'Task not found' });
        }

        console.log('Task deleted successfully');
        res.json({ message: 'Task deleted successfully', task });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ 
            error: 'Failed to delete task',
            details: error.message 
        });
    }
});

// Create Task
app.post('/api/tasks', auth, async (req, res) => {
    try {
        console.log('\n=== Creating Task ===');
        const task = new Task({
            ...req.body,
            userId: req.user._id
        });
        await task.save();
        
        // Schedule notification for deadline
        const notificationDate = new Date(task.deadline);
        notificationDate.setHours(notificationDate.getHours() - 24); // Notify 24 hours before deadline
        
        if (notificationDate > new Date()) {
            setTimeout(async () => {
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: req.user.email,
                    subject: 'Task Deadline Reminder',
                    text: `Your task "${task.title}" is due in 24 hours!`
                };
                
                try {
                    await transporter.sendMail(mailOptions);
                } catch (error) {
                    console.error('Email notification error:', error);
                }
            }, notificationDate.getTime() - Date.now());
        }
        
        console.log('Task created successfully');
        res.status(201).send(task);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(400).send(error);
    }
});

// Get Tasks
app.get('/api/tasks', auth, async (req, res) => {
    try {
        console.log('\n=== Fetching Tasks ===');
        const tasks = await Task.find({ userId: req.user._id });
        console.log('Tasks fetched successfully');
        res.send(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).send(error);
    }
});

// Update Task
app.patch('/api/tasks/:id', auth, async (req, res) => {
    try {
        console.log('\n=== Updating Task ===');
        const task = await Task.findOneAndUpdate(
            { _id: req.params.id, userId: req.user._id },
            req.body,
            { new: true }
        );
        if (!task) {
            console.log('Task not found');
            return res.status(404).send();
        }
        console.log('Task updated successfully');
        res.send(task);
    } catch (error) {
        console.error('Error updating task:', error);
        res.status(400).send(error);
    }
});

// Delete Task
app.delete('/api/tasks/:id', auth, async (req, res) => {
    try {
        console.log('\n=== Deleting Task ===');
        const task = await Task.findOneAndDelete({
            _id: req.params.id,
            userId: req.user._id
        });
        if (!task) {
            console.log('Task not found');
            return res.status(404).send();
        }
        console.log('Task deleted successfully');
        res.send(task);
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).send(error);
    }
});

// Get Categories
app.get('/api/categories', auth, async (req, res) => {
    try {
        console.log('\n=== Fetching Categories ===');
        const tasks = await Task.find({ userId: req.user._id });
        const categories = [...new Set(tasks.flatMap(task => task.categories))];
        console.log('Categories fetched successfully');
        res.send(categories);
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).send(error);
    }
});

// Get Tags
app.get('/api/tags', auth, async (req, res) => {
    try {
        console.log('\n=== Fetching Tags ===');
        const tasks = await Task.find({ userId: req.user._id });
        const tags = [...new Set(tasks.flatMap(task => task.tags))];
        console.log('Tags fetched successfully');
        res.send(tags);
    } catch (error) {
        console.error('Error fetching tags:', error);
        res.status(500).send(error);
    }
});

// Test Email Route
app.get('/api/test-email', async (req, res) => {
    try {
        console.log('\n=== Sending Test Email ===');
        const testMailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER, // sending to the same email for testing
            subject: 'TaskMaster Email Test',
            text: 'This is a test email from TaskMaster application. If you receive this, your email configuration is working correctly!',
            html: `
                <h2>TaskMaster Email Test</h2>
                <p>This is a test email from your TaskMaster application.</p>
                <p>If you're seeing this message, your email configuration is working correctly! 🎉</p>
                <br>
                <p>You will receive notifications at this email address when:</p>
                <ul>
                    <li>Tasks are approaching their deadline (24 hours notice)</li>
                    <li>Tasks are marked as complete</li>
                    <li>New tasks are assigned to you</li>
                </ul>
                <br>
                <p>Best regards,<br>TaskMaster System</p>
            `
        };

        await transporter.sendMail(testMailOptions);
        console.log('Test email sent successfully');
        res.send({ message: 'Test email sent successfully! Check your inbox.' });
    } catch (error) {
        console.error('Email test error:', error);
        res.status(500).send({ error: 'Failed to send test email', details: error.message });
    }
});

// Toggle task completion status
app.patch('/api/tasks/:id/toggle', auth, async (req, res) => {
    try {
        const task = await Task.findOne({ 
            _id: req.params.id, 
            userId: req.user._id 
        });
        
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }

        task.completed = !task.completed;
        await task.save();
        
        res.json(task);
    } catch (error) {
        console.error('Toggle task error:', error);
        res.status(500).json({ 
            error: 'Failed to toggle task',
            details: error.message 
        });
    }
});

// MongoDB Connection
const connectDB = async (retries = 5) => {
    try {
        if (!process.env.MONGODB_URI) {
            throw new Error('MONGODB_URI is not defined in environment variables');
        }

        console.log('Connecting to MongoDB...');
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000, // Timeout after 10 seconds
            socketTimeoutMS: 45000, // Close sockets after 45 seconds
            family: 4, // Use IPv4, skip trying IPv6
            maxPoolSize: 50,
            connectTimeoutMS: 10000,
        });

        console.log(`MongoDB Connected: ${conn.connection.host}`);
        
        // Test database connection
        try {
            await User.countDocuments();
            console.log('Database connection test successful');
        } catch (testError) {
            console.error('Database test failed:', testError);
            throw testError;
        }
        
        // Set up connection error handler
        mongoose.connection.on('error', err => {
            console.error('MongoDB connection error:', err);
        });

        // Handle disconnection
        mongoose.connection.on('disconnected', () => {
            console.log('MongoDB disconnected. Attempting to reconnect...');
            setTimeout(() => connectDB(retries), 5000);
        });

        return conn;
    } catch (error) {
        console.error('MongoDB connection error:', error);
        
        if (retries > 0) {
            console.log(`Retrying connection... (${retries} attempts left)`);
            await new Promise(resolve => setTimeout(resolve, 5000));
            return connectDB(retries - 1);
        }
        
        console.error('Failed to connect to MongoDB after multiple attempts');
        process.exit(1);
    }
};

// Connect to MongoDB before starting the server
connectDB().then(() => {
    const server = app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV}`);
        console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
    }).on('error', (err) => {
        console.error('Server startup error:', err);
        if (err.code === 'EADDRINUSE') {
            console.log(`Port ${PORT} is in use, trying another port...`);
            setTimeout(() => {
                server.close();
                app.listen(0, () => {
                    console.log(`Server is running on random port ${server.address().port}`);
                });
            }, 1000);
        } else {
            process.exit(1);
        }
    });
}).catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    mongoose.connection.close(false, () => {
        console.log('MongoDB connection closed.');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received. Shutting down gracefully...');
    mongoose.connection.close(false, () => {
        console.log('MongoDB connection closed.');
        process.exit(0);
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    // Gracefully shutdown
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
    // Gracefully shutdown
    process.exit(1);
});
