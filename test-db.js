require('dotenv').config();
const mongoose = require('mongoose');

console.log('Testing MongoDB connection...');
console.log('MongoDB URI:', process.env.MONGODB_URI);

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(async () => {
    console.log('Successfully connected to MongoDB');
    
    // Get the User model
    const User = require('./models/User');
    
    try {
        // Count users
        const userCount = await User.countDocuments();
        console.log('Number of users in database:', userCount);
        
        // List all users
        const users = await User.find({}, 'name email isVerified');
        console.log('Users in database:', users);
        
    } catch (err) {
        console.error('Error querying users:', err);
    }
    
    // Close the connection
    await mongoose.connection.close();
    console.log('Connection closed');
    process.exit(0);
})
.catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
});
