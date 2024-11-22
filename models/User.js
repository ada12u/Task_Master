const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        minlength: [2, 'Name must be at least 2 characters long']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    resetToken: String,
    resetTokenExpiry: Date,
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Pre-save middleware to handle password hashing
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to validate password
userSchema.methods.validatePassword = async function(password) {
    return bcrypt.compare(password, this.password);
};

// Method to handle failed login attempts
userSchema.methods.handleFailedLogin = async function() {
    this.loginAttempts += 1;
    if (this.loginAttempts >= 5) {
        this.lockUntil = new Date(Date.now() + 3600000); // Lock for 1 hour
    }
    await this.save();
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
    this.loginAttempts = 0;
    this.lockUntil = undefined;
    this.lastLogin = new Date();
    await this.save();
};

const User = mongoose.model('User', userSchema);

module.exports = User;
