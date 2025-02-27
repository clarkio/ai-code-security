const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const noteRoutes = require('./routes/noteRoutes');
const authRoutes = require('./routes/authRoutes');
require('dotenv').config();

const app = express();
app.set('view engine', 'ejs'); // Set EJS as the templating engine
app.set('views', __dirname + '/views');
app.use(express.json());
app.use(express.static('public')); // Serve static files from 'public' directory
app.use(helmet());
app.use(cors());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error(err));

app.use('/api/notes', noteRoutes);
app.use('/api/auth', authRoutes);
// Serve the frontend
app.get('/', (req, res) => {
    res.render('index'); // Render the index.ejs file
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));