const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const natural = require('natural');
const requestIp = require('request-ip');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const wordList = require('word-list');
const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = 'your_secret_key';

// Load dictionary words
const dictionaryWords = fs.readFileSync(require.resolve('word-list'), 'utf8').split('\n');

// Enhanced NLP components
const Analyzer = natural.SentimentAnalyzer;
const stemmer = natural.PorterStemmer;
const analyzer = new Analyzer("English", stemmer, "afinn");
const tokenizer = new natural.WordTokenizer();
const TfIdf = natural.TfIdf;

// Enhanced sentiment analysis patterns
const SENTIMENT_PATTERNS = {
  positive: [
    /\b(?:excellent|outstanding|superb|fantastic|amazing|wonderful|perfect|ideal|love|adore|happy|pleased|satisfied|impressed)\b/i,
    /\b(?:good|nice|great|awesome|recommend|worth it|value|happy with|pleased with|satisfied with)\b/i,
    /\b(?:high quality|top notch|well made|durable|reliable|comfortable|easy to use|user friendly|responsive|fast|smooth)\b/i
  ],
  negative: [
    /\b(?:terrible|horrible|awful|disgusting|disappointing|frustrating|annoying|unacceptable|poor|bad|worst|waste)\b/i,
    /\b(?:not good|not worth|not happy|not satisfied|not recommend|avoid|returning|refund|complaint|issue|problem|defect)\b/i,
    /\b(?:low quality|cheap|broken|faulty|unreliable|uncomfortable|difficult|hard to use|slow|laggy|unresponsive)\b/i
  ],
  negation: /\b(?:not|no|never|none|nothing|neither|nor|barely|hardly|scarcely|doesn't|isn't|aren't|wasn't|weren't|haven't|hasn't|hadn't|won't|wouldn't|don't|didn't|can't|couldn't)\b/i
};

// Universal e-commerce detection parameters
const DETECTION_CONFIG = {
  financialIncentives: /\b(?:discount|cashback|reward|paid|compensation|money|offer|free|gift|promo|credit|refund|bribe|pay|venmo|cash|transfer|wallet)\b/i,
  
  productAspects: new Set([
    'quality', 'color', 'material', 'fit', 'size', 'comfort', 'design', 'durability',
    'texture', 'weight', 'style', 'performance', 'delivery', 'packaging', 'service',
    'value', 'price', 'brand', 'shipping', 'return', 'assembly', 'ease', 'functionality',
    'accuracy', 'freshness', 'nutrition', 'smell', 'taste', 'warranty', 'instructions',
    'battery', 'display', 'resolution', 'processor', 'storage', 'memory', 'camera',
    'charging', 'connectivity', 'interface', 'software', 'hardware', 'thermal',
    'stitching', 'fabric', 'pattern', 'sleeve', 'neck', 'length', 'waist', 'hem',
    'lining', 'pocket', 'zipper', 'button', 'elastic', 'thread', 'dye', 'weave',
    'softness', 'stretch', 'breathable', 'care', 'maintenance', 'smoothness',
    'capacity', 'heat', 'safety', 'cleaning', 'non-stick', 'temperature', 'pressure',
    'absorption', 'skin', 'hair', 'moisturization', 'scent', 'lather', 'pH-balance',
    'content', 'binding', 'pages', 'author', 'plot', 'genre', 'edition', 'font'
  ]),

  timeThresholds: {
    electronics: 1800000,  // 30 minutes
    clothing: 900000,     // 25 minutes
    books: 1200000,       // 20 minutes
    general: 1200000      // 20 minutes
  },

  specificity: {
    minTerms: 3,
    minUnique: 2
  },

  similarityThreshold: 0.90,
  maxCapitalizationRatio: 0.3,
  punctuationThreshold: 6,
  minMeaningfulWords: 5,

  dictionary: new Set([
    ...dictionaryWords,
    'shirt', 't-shirt', 'blouse', 'top', 'jeans', 'pants', 'dress', 'skirt',
    'jacket', 'hoodie', 'sweater', 'activewear', 'underwear', 'lingerie',
    'electronics', 'apparel', 'footwear', 'accessories', 'home', 'kitchenware'
  ])
};

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(requestIp.mw());
app.use(express.static(path.join(__dirname, 'client/build')));

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/checkoutDB')
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// Schema definitions
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
});
const User = mongoose.model('User', userSchema);

const orderSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    address: { type: String, required: true },
    productName: { type: String, required: true },
    productPrice: { type: Number, required: true },
    productImage: { type: String, required: true },
    reviews: [{
        reviewText: String,
        sentiment: String,
        sentimentScore: Number,
        ipAddress: String,
        isFake: Boolean,
        reasons: [String],
        analysis: {
            specificity: Number,
            uniqueTerms: [String],
            similarityScore: Number,
            reviewDelay: Number,
            linguisticFlags: [String]
        },
        createdAt: { type: Date, default: Date.now }
    }],
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);

// Auth endpoints
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.json({ success: true, message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error registering user: ' + err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ success: true, token });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error logging in: ' + err.message });
    }
});

app.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find().lean();
        const enhancedOrders = orders.map(order => ({
            ...order,
            createdAt: order.createdAt,
            reviews: order.reviews.map(review => ({
                ...review,
                purchaseDate: order.createdAt,
                submittedAt: review.createdAt
            }))
        }));
        res.json({ success: true, orders: enhancedOrders });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error fetching orders: ' + err.message });
    }
});

// Enhanced sentiment analysis function
function analyzeSentiment(reviewText) {
    const lowerReview = reviewText.toLowerCase();
    const tokens = tokenizer.tokenize(lowerReview);
    let baseScore = analyzer.getSentiment(tokens);
    
    // Enhanced sentiment pattern matching
    let positiveMatches = 0;
    let negativeMatches = 0;
    
    SENTIMENT_PATTERNS.positive.forEach(pattern => {
        const matches = reviewText.match(pattern);
        if (matches) positiveMatches += matches.length;
    });
    
    SENTIMENT_PATTERNS.negative.forEach(pattern => {
        const matches = reviewText.match(pattern);
        if (matches) negativeMatches += matches.length;
    });
    
    // Check for negated positive phrases (e.g., "not good")
    const negatedPositives = [];
    const positivePhrases = reviewText.match(/\b(?:good|nice|great|awesome|excellent|perfect|amazing|love it)\b/gi) || [];
    positivePhrases.forEach(phrase => {
        const regex = new RegExp(`${SENTIMENT_PATTERNS.negation.source}\\s+${phrase.toLowerCase()}`, 'i');
        if (regex.test(reviewText)) {
            negatedPositives.push(phrase);
            positiveMatches--;
            negativeMatches++;
        }
    });
    
    // Calculate weighted score
    const weightedScore = baseScore + (positiveMatches * 0.5) - (negativeMatches * 0.7);
    
    // Determine final sentiment
    let sentiment;
    if (weightedScore > 1.5) {
        sentiment = 'Positive';
    } else if (weightedScore < -1.5) {
        sentiment = 'Negative';
    } else {
        // For neutral scores, check if we have strong opposing signals
        if (positiveMatches >= 2 && negativeMatches === 0) {
            sentiment = 'Positive';
        } else if (negativeMatches >= 2 && positiveMatches === 0) {
            sentiment = 'Negative';
        } else if (positiveMatches > 0 && negativeMatches > 0) {
            // Mixed review - determine dominant sentiment
            if (positiveMatches > negativeMatches * 1.5) {
                sentiment = 'Positive';
            } else if (negativeMatches > positiveMatches * 1.5) {
                sentiment = 'Negative';
            } else {
                sentiment = 'Mixed';
            }
        } else {
            sentiment = 'Neutral';
        }
    }
    
    return {
        sentiment,
        score: weightedScore,
        positiveMatches,
        negativeMatches,
        negatedPositives
    };
}

app.post('/api/reviews', async (req, res) => {
    const { orderId, reviewText } = req.body;
    const ipAddress = req.clientIp;

    try {
        if (!reviewText || reviewText.trim().length < 20) {
            return res.status(400).json({ 
                success: false, 
                message: 'Review must be at least 20 characters' 
            });
        }

        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ success: false, message: 'Order not found' });

        const existingReview = order.reviews.find(r => r.ipAddress === ipAddress);
        if (existingReview) {
            return res.status(409).json({ 
                success: false, 
                message: 'One review per customer allowed',
                errorType: 'DUPLICATE_REVIEW' 
            });
        }

        // Enhanced sentiment analysis
        const sentimentAnalysis = analyzeSentiment(reviewText);
        
        // Enhanced term extraction
        const tfidf = new TfIdf();
        tfidf.addDocument(reviewText);
        let specificTerms = new Set();
        
        tfidf.listTerms(0).forEach(({ term }) => {
            const normalizedTerm = term.toLowerCase()
                .replace(/[^a-z]/g, '')
                .replace(/(ing|s|es|ed)$/, '');

            if (DETECTION_CONFIG.productAspects.has(normalizedTerm)) {
                specificTerms.add(normalizedTerm);
            }

            const stemmedTerm = natural.PorterStemmer.stem(normalizedTerm);
            if (DETECTION_CONFIG.productAspects.has(stemmedTerm)) {
                specificTerms.add(stemmedTerm);
            }

            const compoundTerms = normalizedTerm.split(/(?=[A-Z])/);
            compoundTerms.forEach(t => {
                const trimmedTerm = t.replace(/^\W+|\W+$/g, '');
                if (DETECTION_CONFIG.productAspects.has(trimmedTerm)) {
                    specificTerms.add(trimmedTerm);
                }
            });
        });

        const linguisticFlags = [];
        const purchaseDate = order.createdAt;
        const reviewDate = new Date();
        const analysis = {
            specificity: specificTerms.size,
            uniqueTerms: Array.from(specificTerms),
            similarityScore: 0,
            reviewDelay: reviewDate - purchaseDate,
            linguisticFlags
        };

        let isFake = false;
        const reasons = [];

        // Category-aware time thresholds
        const productCategory = getProductCategory(order.productName);
        const effectiveThreshold = DETECTION_CONFIG.timeThresholds[productCategory] 
                                 || DETECTION_CONFIG.timeThresholds.general;

        if (analysis.reviewDelay < effectiveThreshold) {
            reasons.push(`Reviewed ${formatDuration(analysis.reviewDelay)} after purchase`);
            isFake = true;
            linguisticFlags.push('Rushed review');
        }

        // Similarity check
        let maxSimilarity = 0;
        order.reviews.forEach(existing => {
            const similarity = natural.JaroWinklerDistance(
                existing.reviewText.toLowerCase(), 
                reviewText.toLowerCase()
            );
            maxSimilarity = Math.max(maxSimilarity, similarity);
        });
        analysis.similarityScore = maxSimilarity;

        if (DETECTION_CONFIG.financialIncentives.test(reviewText)) {
            reasons.push('Financial incentive detected');
            isFake = true;
        }

        if (specificTerms.size < DETECTION_CONFIG.specificity.minTerms) {
            reasons.push(`Insufficient product details (${specificTerms.size}/${DETECTION_CONFIG.specificity.minTerms} terms)`);
            isFake = true;
        }

        const capRatio = (reviewText.match(/[A-Z]/g) || []).length / reviewText.length;
        if (capRatio > DETECTION_CONFIG.maxCapitalizationRatio) {
            reasons.push('Excessive capitalization');
            linguisticFlags.push('Capitalization');
            isFake = true;
        }

        if ((reviewText.match(/[!?]/g) || []).length > DETECTION_CONFIG.punctuationThreshold) {
            reasons.push('Overuse of punctuation');
            linguisticFlags.push('Punctuation');
            isFake = true;
        }

        // Enhanced sentiment mismatch detection
        const hasNegativeTerms = SENTIMENT_PATTERNS.negative.some(p => p.test(reviewText));
        const sentimentMismatch = (
            (sentimentAnalysis.sentiment === 'Positive' && hasNegativeTerms) ||
            (sentimentAnalysis.sentiment === 'Negative' && !hasNegativeTerms) ||
            (sentimentAnalysis.sentiment === 'Neutral' && Math.abs(sentimentAnalysis.score) > 2)
        );
        if (sentimentMismatch) {
            reasons.push(`Conflicting sentiment (score: ${sentimentAnalysis.score.toFixed(1)})`);
            isFake = true;
        }

        const newReview = {
            reviewText,
            sentiment: sentimentAnalysis.sentiment,
            sentimentScore: sentimentAnalysis.score,
            ipAddress,
            isFake,
            reasons,
            analysis,
            createdAt: reviewDate
        };

        order.reviews.push(newReview);
        await order.save();

        res.json({ 
            success: true,
            message: isFake ? 'Review submitted but marked fake' : 'Review submitted successfully',
            review: {
                ...newReview,
                purchaseDate: order.createdAt,
                analysis: {
                    ...analysis,
                    reviewDelay: analysis.reviewDelay,
                    positiveMatches: sentimentAnalysis.positiveMatches,
                    negativeMatches: sentimentAnalysis.negativeMatches,
                    negatedPositives: sentimentAnalysis.negatedPositives
                }
            }
        });

    } catch (err) {
        console.error('Review submission error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error submitting review: ' + err.message 
        });
    }
});

// Helper functions
function getProductCategory(productName) {
    const categories = {
        electronics: /\b(phone|smartphone|tablet|laptop|computer|tv|headphones|earbuds|camera|charger|battery)\b/i,
        clothing: /\b(shirt|blouse|top|tee|t-shirt|polo|dress|jeans|pants|skirt|jacket|hoodie|sweater|apparel|wear)\b/i,
        home: /\b(furniture|sofa|chair|table|bed|mattress|pillow|blanket|curtain|rug|decor|kitchen|appliance)\b/i,
        beauty: /\b(shampoo|conditioner|moisturizer|cosmetic|makeup|skincare|fragrance|perfume|deodorant)\b/i,
        books: /\b(book|novel|textbook|magazine|ebook|audiobook|publication|literature)\b/i
    };

    for (const [category, pattern] of Object.entries(categories)) {
        if (pattern.test(productName.toLowerCase())) return category;
    }
    return 'general';
}

function formatDuration(ms) {
    const minutes = Math.floor(ms / 60000);
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours}h ${remainingMinutes}m`;
}

// Checkout endpoint
app.post('/api/checkout', async (req, res) => {
    try {
        const { name, email, address, productName, productPrice, productImage } = req.body;
        if (!name || !email || !address || !productName || !productPrice || !productImage) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        const newOrder = new Order({ 
            name, 
            email, 
            address, 
            productName, 
            productPrice, 
            productImage, 
            reviews: [] 
        });
        await newOrder.save();
        res.json({ success: true, message: 'Checkout successful', orderId: newOrder._id });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error processing checkout: ' + err.message });
    }
});

// Client routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

// Server startup
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});