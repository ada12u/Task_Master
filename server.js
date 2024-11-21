require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 8080;

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

// Middleware
app.use(limiter);
app.use(cors());
app.use(express.json());

// Add logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`, {
        body: req.body,
        headers: req.headers
    });
    next();
});

// Serve static files from the root directory
app.use(express.static(path.join(__dirname)));

// Serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Apply rate limiting to registration and login routes
app.use('/api/users/register', limiter);
app.use('/api/users/login', limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/taskmaster', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verificationTokenExpires: Date,
    createdAt: { type: Date, default: Date.now }
});

const taskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    description: { type: String },
    deadline: { type: Date, required: true },
    priority: { type: String, enum: ['low', 'medium', 'high'], required: true },
    completed: { type: Boolean, default: false },
    categories: [{ type: String }],
    tags: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Task = mongoose.model('Task', taskSchema);

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
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
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

// Routes
// User Registration
app.post('/api/users/register', async (req, res) => {
    try {
        console.log('Registration request body:', req.body);
        
        // Check if request body is empty
        if (!req.body || Object.keys(req.body).length === 0) {
            console.error('Empty request body received');
            return res.status(400).json({ error: 'Request body is empty' });
        }

        const { name, email, password } = req.body;

        // Check if all required fields are present
        if (!name || !email || !password) {
            console.error('Missing required fields:', { name: !!name, email: !!email, password: !!password });
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            console.log('Invalid email format:', email);
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Validate password
        const passwordError = validatePassword(password);
        if (passwordError) {
            console.log('Password validation failed:', passwordError);
            return res.status(400).json({ error: passwordError });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log('Email already registered:', email);
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create verification token
        const verificationToken = jwt.sign(
            { email },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Create new user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            verificationToken,
            verificationTokenExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
        });

        await user.save();
        console.log('User created successfully:', { name, email });

        // Create JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Send success response first
        res.status(201).json({
            message: 'Registration successful',
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            token
        });

        // Then try to send verification email (non-blocking)
        try {
            await sendVerificationEmail(user, verificationToken);
            console.log('Verification email sent successfully');
        } catch (emailError) {
            console.error('Error sending verification email:', emailError);
            // Don't let email errors affect the registration response
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// Email Verification Endpoint
app.get('/api/users/verify/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Find and update user
        const user = await User.findOne({
            email: decoded.email,
            verificationToken: token,
            verificationTokenExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                error: 'Invalid or expired verification token'
            });
        }

        // Update user verification status
        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        res.status(200).json({
            message: 'Email verified successfully. You can now log in.'
        });

    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({
            error: 'Email verification failed. Please try again.'
        });
    }
});

// User Login
app.post('/api/users/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            return res.status(401).json({
                error: 'Please verify your email before logging in'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { 
                expiresIn: '7d',
                algorithm: 'HS512'
            }
        );

        res.json({
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                isVerified: user.isVerified
            },
            token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Token verification endpoint
app.get('/api/users/verify-token', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        res.json({
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                isVerified: user.isVerified
            }
        });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Task Routes with RESTful principles
// GET /api/tasks - Get all tasks for a user
app.get('/api/tasks', auth, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.user._id })
            .sort({ deadline: 1 });
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
        const { title, description, deadline, priority } = req.body;

        // Validate required fields
        if (!title || !deadline || !priority) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['title', 'deadline', 'priority']
            });
        }

        // Validate priority
        const validPriorities = ['low', 'medium', 'high'];
        if (!validPriorities.includes(priority)) {
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
        const updates = req.body;
        const allowedUpdates = ['title', 'description', 'deadline', 'priority', 'completed'];
        
        // Validate update fields
        const updateFields = Object.keys(updates);
        const isValidOperation = updateFields.every(field => allowedUpdates.includes(field));
        
        if (!isValidOperation) {
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
        const task = await Task.findOneAndDelete({ 
            _id: req.params.id,
            userId: req.user._id 
        });

        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }

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
        
        res.status(201).send(task);
    } catch (error) {
        res.status(400).send(error);
    }
});

// Get Tasks
app.get('/api/tasks', auth, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.user._id });
        res.send(tasks);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Update Task
app.patch('/api/tasks/:id', auth, async (req, res) => {
    try {
        const task = await Task.findOneAndUpdate(
            { _id: req.params.id, userId: req.user._id },
            req.body,
            { new: true }
        );
        if (!task) {
            return res.status(404).send();
        }
        res.send(task);
    } catch (error) {
        res.status(400).send(error);
    }
});

// Delete Task
app.delete('/api/tasks/:id', auth, async (req, res) => {
    try {
        const task = await Task.findOneAndDelete({
            _id: req.params.id,
            userId: req.user._id
        });
        if (!task) {
            return res.status(404).send();
        }
        res.send(task);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Get Categories
app.get('/api/categories', auth, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.user._id });
        const categories = [...new Set(tasks.flatMap(task => task.categories))];
        res.send(categories);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Get Tags
app.get('/api/tags', auth, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.user._id });
        const tags = [...new Set(tasks.flatMap(task => task.tags))];
        res.send(tags);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Test Email Route
app.get('/api/test-email', async (req, res) => {
    try {
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
        res.send({ message: 'Test email sent successfully! Check your inbox.' });
    } catch (error) {
        console.error('Email test error:', error);
        res.status(500).send({ error: 'Failed to send test email', details: error.message });
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
