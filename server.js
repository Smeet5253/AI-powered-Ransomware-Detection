// Mitigation Attempt 1:  
// Mitigation is working But the risk score is 50% for all the files. This means that the model is not working properly. This is a very serious issue.
/**
 * Express server for Ransomware Detection and Mitigation Framework
 * 
 * This server acts as a proxy between the frontend and the Python Flask API,
 * handles file uploads, and provides additional security features.
 */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const bodyParser = require('body-parser');

// Initialize express app
const app = express();
const PORT = process.env.PORT || 3000;
const FLASK_API_URL = process.env.FLASK_API_URL || 'http://localhost:5000';

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disabled for development - enable and configure for production
}));

app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:5173'],
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Parse JSON request bodies
app.use(bodyParser.json());

// Serve static files from the frontend directory
app.use(express.static(path.join(__dirname, 'frontend')));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Setup logging
const logDirectory = path.join(__dirname, 'logs');
fs.existsSync(logDirectory) || fs.mkdirSync(logDirectory);

// Create a write stream for the access log
const accessLogStream = fs.createWriteStream(
    path.join(logDirectory, 'access.log'),
    { flags: 'a' }
);
app.use(morgan('combined', { stream: accessLogStream }));

// Set up uploads directory
const uploadDir = path.join(__dirname, 'uploads');
fs.existsSync(uploadDir) || fs.mkdirSync(uploadDir);

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Generate unique filename with original extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, `${uniqueSuffix}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024, // 50MB max file size
        files: 1 // Max number of files
    }
});

// Helper function to forward errors
const handleError = (res, error) => {
    console.error('Error:', error);
    
    // Extract error message from axios error if available
    const errorMessage = error.response?.data?.message || error.message || 'Unknown error';
    const statusCode = error.response?.status || 500;
    
    res.status(statusCode).json({
        status: 'error',
        message: errorMessage
    });
};

// Check if Flask API is running
const checkFlaskAPI = async () => {
    try {
        const response = await axios.get(`${FLASK_API_URL}/api/status`, { timeout: 5000 });
        console.log(`Flask API status: ${response.data.status} at ${FLASK_API_URL}`);
        return true;
    } catch (error) {
        console.error(`Error connecting to Flask API at ${FLASK_API_URL}:`, error.message);
        return false;
    }
};

// Home route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// API Routes

// Status endpoint
app.get('/api/status', async (req, res) => {
    try {
        const isFlaskRunning = await checkFlaskAPI();
        
        if (!isFlaskRunning) {
            return res.json({
                status: 'degraded',
                message: 'Flask API is not responding, some features may be unavailable',
                server: 'Node.js Express',
                flask_api: 'unreachable'
            });
        }
        
        const response = await axios.get(`${FLASK_API_URL}/api/status`);
        res.json({
            ...response.data,
            server: 'Node.js Express',
            proxy_for: FLASK_API_URL
        });
    } catch (error) {
        handleError(res, error);
    }
});

// File analysis endpoint
app.post('/api/analyze', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                status: 'error',
                message: 'No file uploaded'
            });
        }

        // Create form data to send to Flask API
        const formData = new FormData();
        formData.append('file', fs.createReadStream(req.file.path));
        
        // Add auto-quarantine parameter if provided
        if (req.body.auto_quarantine) {
            formData.append('auto_quarantine', req.body.auto_quarantine);
        }

        // Send file to Flask API for analysis
        const response = await axios.post(`${FLASK_API_URL}/api/analyze`, formData, {
            headers: {
                ...formData.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        // Delete the uploaded file after analysis
        fs.unlink(req.file.path, (err) => {
            if (err) console.error(`Error deleting file: ${err}`);
        });

        // Return the response from the Flask API
        res.json(response.data);
    } catch (error) {
        // Delete the uploaded file if it exists
        if (req.file && req.file.path) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error(`Error deleting file: ${err}`);
            });
        }
        
        handleError(res, error);
    }
});

// Mitigation endpoint
app.post('/api/mitigate', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                status: 'error',
                message: 'No file uploaded'
            });
        }

        // Create form data to send to Flask API
        const formData = new FormData();
        formData.append('file', fs.createReadStream(req.file.path));

        // Send file to Flask API for mitigation analysis
        const response = await axios.post(`${FLASK_API_URL}/api/mitigate`, formData, {
            headers: {
                ...formData.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        // Delete the uploaded file after analysis
        fs.unlink(req.file.path, (err) => {
            if (err) console.error(`Error deleting file: ${err}`);
        });

        // Return the response from the Flask API
        res.json(response.data);
    } catch (error) {
        // Delete the uploaded file if it exists
        if (req.file && req.file.path) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error(`Error deleting file: ${err}`);
            });
        }
        
        handleError(res, error);
    }
});

// Quarantine file endpoint
app.post('/api/quarantine', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                status: 'error',
                message: 'No file uploaded'
            });
        }

        // Create form data to send to Flask API
        const formData = new FormData();
        formData.append('file', fs.createReadStream(req.file.path));

        // Send file to Flask API for quarantine
        const response = await axios.post(`${FLASK_API_URL}/api/quarantine`, formData, {
            headers: {
                ...formData.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        // Delete the uploaded file after quarantine
        fs.unlink(req.file.path, (err) => {
            if (err) console.error(`Error deleting file: ${err}`);
        });

        // Return the response from the Flask API
        res.json(response.data);
    } catch (error) {
        // Delete the uploaded file if it exists
        if (req.file && req.file.path) {
            fs.unlink(req.file.path, (err) => {
                if (err) console.error(`Error deleting file: ${err}`);
            });
        }
        
        handleError(res, error);
    }
});

// List quarantined files endpoint
app.get('/api/quarantine/list', async (req, res) => {
    try {
        const response = await axios.get(`${FLASK_API_URL}/api/quarantine/list`);
        res.json(response.data);
    } catch (error) {
        handleError(res, error);
    }
});

// Delete from quarantine endpoint
app.delete('/api/quarantine/:id', async (req, res) => {
    try {
        const quarantineId = req.params.id;
        const response = await axios.delete(`${FLASK_API_URL}/api/quarantine/${quarantineId}`);
        res.json(response.data);
    } catch (error) {
        handleError(res, error);
    }
});

// Restore from quarantine endpoint
app.post('/api/quarantine/:id/restore', async (req, res) => {
    try {
        const quarantineId = req.params.id;
        const response = await axios.post(
            `${FLASK_API_URL}/api/quarantine/${quarantineId}/restore`, 
            req.body
        );
        res.json(response.data);
    } catch (error) {
        handleError(res, error);
    }
});

// Incident reporting endpoint
app.post('/api/incident', async (req, res) => {
    try {
        const response = await axios.post(`${FLASK_API_URL}/api/incident`, req.body);
        res.json(response.data);
    } catch (error) {
        handleError(res, error);
    }
});

// Security metrics endpoint
app.get('/api/security-metrics', async (req, res) => {
    try {
        const response = await axios.get(`${FLASK_API_URL}/api/security-metrics`);
        res.json(response.data);
    } catch (error) {
        handleError(res, error);
    }
});

// Threat report endpoint
app.get('/api/threat-report', async (req, res) => {
    try {
        const response = await axios.get(`${FLASK_API_URL}/api/threat-report`);
        res.json(response.data);
    } catch (error) {
        handleError(res, error);
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        status: 'error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
});

// Start server
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Connecting to Flask API at ${FLASK_API_URL}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // Check if Flask API is running
    const isFlaskRunning = await checkFlaskAPI();
    if (!isFlaskRunning) {
        console.warn('Warning: Flask API is not responding. Make sure it is running for full functionality.');
    }
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    app.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});