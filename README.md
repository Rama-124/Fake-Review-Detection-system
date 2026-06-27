# Fake Product Review Monitoring System

This project is a Node.js and MongoDB web application for monitoring suspicious product reviews in an e-commerce-style workflow. It lets users browse products, place sample orders, submit reviews, and analyze those reviews using sentiment scoring, text heuristics, and behavioral checks such as review timing, repeated wording, IP tracking, and suspicious language patterns.

## Overview

The system is designed to demonstrate how fake review detection can be integrated into an online shopping experience. Instead of using a static dataset alone, the application simulates the full review lifecycle:

- users register and log in
- products are fetched from external catalog APIs and cached locally
- users place orders through a checkout flow
- submitted reviews are analyzed and marked as suspicious or legitimate
- admins can inspect review outcomes from the review analysis page

## Implemented Features

- Review sentiment analysis using the `natural` NLP library
- Heuristic fake-review detection based on:
  - rushed review submission after purchase
  - duplicated or highly similar review text
  - excessive capitalization or punctuation
  - financially motivated language
  - low-specificity product descriptions
  - conflicting sentiment patterns
- IP capture for submitted reviews
- Product catalog loading from Fake Store API and DummyJSON with local cache fallback
- User registration and login with hashed passwords
- Order storage and review history in MongoDB
- Frontend pages for home, login, registration, checkout, shop, and review monitoring

## Tech Stack

- Backend: Node.js, Express
- Database: MongoDB with Mongoose
- NLP and text analysis: `natural`, `word-list`
- Authentication: `bcrypt`, `jsonwebtoken`
- HTTP/data utilities: `axios`, `cors`, `body-parser`, `request-ip`
- Frontend: HTML, CSS, JavaScript

## Project Structure

```text
.
|-- server.js
|-- package.json
|-- products-cache.json
|-- home.html
|-- index.html
|-- login.html
|-- registration.html
|-- checkout.html
|-- review.html
|-- shop.html
|-- public/
`-- client/
```

## How the Detection Flow Works

1. Products are loaded from external APIs and normalized into a consistent format.
2. A user places an order, which is stored in MongoDB.
3. The user submits a review for that order.
4. The backend analyzes the review text for sentiment and suspicious patterns.
5. The system compares the review against behavior and content rules.
6. The review is saved with:
   - sentiment label and score
   - IP address
   - fake/real status
   - reasons for flagging
   - analysis metadata

## Main API Endpoints

- `GET /` - serves the home page
- `POST /api/register` - create a user account
- `POST /api/login` - authenticate a user
- `GET /api/products` - fetch normalized product data
- `POST /api/checkout` - place an order
- `GET /api/orders` - retrieve orders and associated reviews
- `POST /api/reviews` - submit and analyze a review

## Getting Started

### Prerequisites

- Node.js 18 or later recommended
- MongoDB running locally on `mongodb://127.0.0.1:27017/checkoutDB`

### Installation

```bash
git clone https://github.com/Rama-124/Fake-Review-Detection-system.git
cd Fake-Review-Detection-system
npm install
```

### Run the Application

Start MongoDB first, then run:

```bash
npm start
```

The server runs on:

```text
http://localhost:5000
```

Useful pages:

- Home page: `http://localhost:5000/`
- Review dashboard: `http://localhost:5000/review.html`
- Shop page: `http://localhost:5000/shop.html`

## Deployment

This repository includes:

- `render.yaml` for Render web service setup
- `.env.example` for required environment variables

To deploy on Render:

1. Push the latest code to GitHub.
2. Create a MongoDB Atlas database and copy its connection string.
3. In Render, create a new web service from this repository or import the included `render.yaml`.
4. Set `MONGODB_URI` and `JWT_SECRET` in the Render environment settings.
5. Deploy and open the generated `onrender.com` URL.

The frontend now uses same-origin API calls, so the deployed site works without editing hardcoded `localhost` URLs.

### Custom Domain on Render

After the Render service is live, attach a custom domain from the Render dashboard:

1. Open the Render web service.
2. Go to `Settings` > `Custom Domains`.
3. Add your domain, for example `reviews.example.com`.
4. Copy the DNS target Render provides.
5. In your domain registrar, add the required DNS record.
6. Wait for DNS verification, then use the HTTPS URL Render issues.

Use a `CNAME` record for a subdomain such as `reviews.example.com`. For a root domain such as `example.com`, follow Render's `A` or `ALIAS/ANAME` instructions shown in the dashboard.

## Data Model Summary

The application stores:

- users with name, email, and hashed password
- orders with customer details and product information
- reviews nested under orders with analysis results and timestamps

## Notes

- The current implementation uses rule-based NLP and behavioral heuristics rather than a transformer model such as BERT.
- Product data is pulled from public demo APIs, so availability can depend on network access.
- `server.js` now supports `MONGODB_URI` and `JWT_SECRET` through environment variables, with local fallbacks for development.

## Future Improvements

- Add role-based admin authentication
- Introduce model training pipelines for advanced review classification
- Add multilingual analysis support
- Add automated tests for API and review-detection logic

## License

This project currently does not declare a license in `package.json`. Add one if you plan to distribute it publicly.
