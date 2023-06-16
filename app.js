// Import required modules
const express = require('express');
const ejs = require('ejs');
const bcrypt = require('bcryptjs');
const { sha512 } = require('sha512');
const argon2 = require('argon2');
const mongoose = require('mongoose');

// Initialize Express
const app = express();

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Set up middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));


// Connect to MongoDB with Mongoose
mongoose.connect('mongodb://localhost/hash-table-DB', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

// Define a schema for the hash table data
const passwordSchema = new mongoose.Schema({
    password: String,
    bcryptHash: String,
    sha512Hash: String,
    argon2Hash: String
});

// Create a model using Mongoose
const Password = mongoose.model('Password', passwordSchema);

// Define routes
app.get('/', async(req, res) => {
    try {
        // Retrieve all stored passwords from the database
        const passwords = await Password.find();
        res.render('index', { passwords });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/create', async(req, res) => {
    try {
        const { password } = req.body;

        // Generate hashes using bcrypt, SHA512, and Argon2 algorithms
        const bcryptHash = await bcrypt.hash(password, 10);
        const sha512Hash = sha512(password);
        const argon2Hash = await argon2.hash(password);

        // Save the password and hashes in the database
        await Password.create({
            password,
            bcryptHash,
            sha512Hash,
            argon2Hash
        });

        res.redirect('/');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Start the server
app.listen(3000, function() {
    console.log("Server is running on port 3000");
});