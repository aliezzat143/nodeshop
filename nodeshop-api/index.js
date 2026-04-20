const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const User = require('./models/user');
const Product = require('./models/product');

const JWT_SECRET = 'LKUHGDiouhiuugIYUGiyug978s69pjklhg';
const PORT = 3000;
const MONGODB_URL = 'mongodb://localhost:27017/eshop';

const app = express();
app.use(express.json());
app.use(cors());


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'token required' });

    jwt.verify(token,JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

function authenticateAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admins only' });
    }
    next();
}


app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        if (email === 'admin@gmail.com' && password === 'admin123') {
            const adminUser = new User({ name, email, password: hashedPassword, role: 'admin' });
            await adminUser.save();
            const token = jwt.sign({ id: adminUser._id, role: adminUser.role }, JWT_SECRET, { expiresIn: '7d' });
            return res.status(201).json({token:token, user: { id: adminUser._id, name: adminUser.name, email: adminUser.email, role: adminUser.role } });
        }
        const user = new User({ name, email, password: hashedPassword, role: 'user' });
        await user.save();
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({token:token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token:token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
        res.json({ user });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        let { id } = req.params;
        id = String(id).trim();
        try {
            id = new mongoose.Types.ObjectId(id);
        } catch (err) {
            return res.status(400).json({ message: 'Invalid product ID format' });
        }
        
        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json(product);
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/products', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { name, description, price } = req.body;
        if (!name || !description || !price) {
            return res.status(400).json({ message: 'Name, description, and price are required' });
        }
        const product = new Product({ name, description, price });
        await product.save();
        res.status(201).json({ product });
    } catch (error) {
        console.error('Create product error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/products/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        let { id } = req.params;
        id = String(id).trim();
        
        try {
            id = new mongoose.Types.ObjectId(id);
        } catch (err) {
            return res.status(400).json({ message: 'Invalid product ID format' });
        }
        
        const { name, description, price } = req.body;
        if (!name && !description && !price) {
            return res.status(400).json({ message: 'At least one field (name, description, or price) is required' });
        }
        const updateData = {};
        if (name) updateData.name = name;
        if (description) updateData.description = description;
        if (price) updateData.price = price;
        
        const product = await Product.findByIdAndUpdate(id, updateData);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ product });
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/products/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        let { id } = req.params;
        id = String(id).trim();
        
        try {
            id = new mongoose.Types.ObjectId(id);
        } catch (err) {
            return res.status(400).json({ message: 'Invalid product ID format' });
        }
        
        const product = await Product.findByIdAndDelete(id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.json({ message: 'Product deleted' });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const { name, password } = req.body;
        const updateData = {};
        
        if (name) {
            updateData.name = name;
        }
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }
        
        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ message: 'At least one field is required' });
        }
        
        const user = await User.findByIdAndUpdate(req.user.id, updateData);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ user });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/admin/users', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        console.error('Get admin users error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/admin/users/:id/role', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        let { id } = req.params;
        id = String(id).trim();
        
        try {
            id = new mongoose.Types.ObjectId(id);
        } catch (err) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        
        if (req.user.id.toString() === id.toString()) {
            return res.status(403).json({ message: 'You cannot change your own role' });
        }
        const { role } = req.body;
        if (!role) {
            return res.status(400).json({ message: 'Role is required' });
        }
        if (!['admin', 'user'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role. Must be admin or user' });
        }
        const user = await User.findByIdAndUpdate(id, { role });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ user });
    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        let { id } = req.params;
        id = String(id).trim();
        
        try {
            id = new mongoose.Types.ObjectId(id);
        } catch (err) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        
        if (req.user.id.toString() === id.toString()) {
            return res.status(403).json({ message: 'You cannot delete your own account' });
        }
        const user = await User.findByIdAndDelete(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

mongoose.connect(MONGODB_URL)
    .then(() => console.log('MongoDB connected successfully'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
