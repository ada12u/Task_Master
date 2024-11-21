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

// CORS configuration
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000',
    'https://task-masters.onrender.com',
    'https://task-master.onrender.com'
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Middleware
app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
    // Log request
    console.log('\n--- Incoming Request ---');
    console.log('Time:', new Date().toISOString());
    console.log('Method:', req.method);
    console.log('Path:', req.path);
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);

    // Capture the original send
    const originalSend = res.send;
    res.send = function(data) {
        console.log('\n--- Outgoing Response ---');
        console.log('Status:', res.statusCode);
        console.log('Response Body:', data);
        return originalSend.call(this, data);
    };

    next();
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

// Apply rate limiting to all routes
app.use(limiter);

// MongoDB Connection
console.log('Attempting to connect to MongoDB...');
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('Successfully connected to MongoDB');
    // Test database connection by counting users
    User.countDocuments()
        .then(count => console.log('Number of users in database:', count))
        .catch(err => console.error('Error counting users:', err));
})
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit if we can't connect to database
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
        console.log('User found:', existingUser ? 'Yes' : 'No');

        if (existingUser) {
            console.log('User already exists');
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('Password hashed successfully');

        // Create new user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            isVerified: true // Temporarily set to true for testing
        });

        // Save user to database
        const savedUser = await user.save();
        console.log('User saved successfully:', savedUser._id);

        // Create JWT token
        const token = jwt.sign(
            { userId: savedUser._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log('Registration successful, sending response');
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

// User Login
app.post('/api/users/login', async (req, res) => {
    try {
        console.log('\n=== Login Attempt ===');
        console.log('Request body:', req.body);

        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            console.log('Missing credentials');
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user
        const user = await User.findOne({ email });
        console.log('User found:', user ? 'Yes' : 'No');

        if (!user) {
            console.log('User not found');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('Password valid:', isValidPassword);

        if (!isValidPassword) {
            console.log('Invalid password');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Prepare response
        const response = {
            message: 'Login successful',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            token
        };

        console.log('Login successful, sending response');
        return res.status(200).json(response);

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Login failed: ' + error.message });
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

// Email verification function
const sendVerificationEmail = async (user, token) => {
    const verificationUrl = `http://localhost:5000/api/users/verify/${token}`;
    
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'TaskMaster - Verify Your Email',
        html: `
            <h1>Welcome to TaskMaster!</h1>
            <p>Please click the link below to verify your email address:</p>
            <a href="${verificationUrl}">${verificationUrl}</a>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create this account, please ignore this email.</p>
        `
    };

    await transporter.sendMail(mailOptions);
};

// Authentication Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            throw new Error();
        }

        req.token = token;
        req.user = user;
        next();
    } catch (error) {
        res.status(401).send({ error: 'Please authenticate.' });
    }
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

// GET /api/tasks/:id - Get a specific task
app.get('/api/tasks/:id', auth, async (req, res) => {
    try {
        console.log('\n=== Fetching Task ===');
        const task = await Task.findOne({ 
            _id: req.params.id,
            userId: req.user._id 
        });

        if (!task) {
            console.log('Task not found');
            return res.status(404).json({ error: 'Task not found' });
        }

        console.log('Task fetched successfully');
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

// GET /api/tasks/search - Search tasks
app.get('/api/tasks/search', auth, async (req, res) => {
    try {
        console.log('\n=== Searching Tasks ===');
        const { query, priority, completed, startDate, endDate } = req.query;
        
        const searchCriteria = { userId: req.user._id };

        // Add search criteria based on query parameters
        if (query) {
            searchCriteria.$or = [
                { title: new RegExp(query, 'i') },
                { description: new RegExp(query, 'i') }
            ];
        }

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

        const tasks = await Task.find(searchCriteria)
            .sort({ deadline: 1 });

        console.log('Tasks searched successfully');
        res.json(tasks);
    } catch (error) {
        console.error('Error searching tasks:', error);
        res.status(500).json({ 
            error: 'Failed to search tasks',
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

// Health check endpoint
app.get('/api/health', (req, res) => {
    const healthcheck = {
        uptime: process.uptime(),
        message: 'OK',
        timestamp: Date.now()
    };
    try {
        res.send(healthcheck);
    } catch (error) {
        healthcheck.message = error;
        res.status(503).send();
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}).on('error', (err) => {
    console.error('Server error:', err);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    app.close(() => {
        console.log('Server shutting down');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    app.close(() => {
        console.log('Server shutting down');
        process.exit(0);
    });
});
