# Cybersecurity Honeypot Prototype

A comprehensive honeypot system with social login integration, real-time threat monitoring, and alert capabilities.

## Features

- **Decoy Login Portal**: Realistic corporate login interface to attract attackers
- **Social Login Integration**: Google, LinkedIn, and Facebook OAuth tracking
- **Real-time Monitoring**: Live activity feeds and threat detection
- **Alert System**: Automated notifications for suspicious activities
- **Analytics Dashboard**: Comprehensive threat intelligence and statistics

## Setup Instructions

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure OAuth Applications

#### Google OAuth Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `http://localhost:5000/auth/google/callback`

#### LinkedIn OAuth Setup
1. Go to [LinkedIn Developer Portal](https://www.linkedin.com/developers/)
2. Create a new app
3. Add OAuth 2.0 redirect URL: `http://localhost:5000/auth/linkedin/callback`
4. Request access to Sign In with LinkedIn

#### Facebook OAuth Setup
1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create a new app
3. Add Facebook Login product
4. Add OAuth redirect URI: `http://localhost:5000/auth/facebook/callback`

### 3. Environment Configuration
```bash
cp .env.example .env
```

Edit `.env` with your OAuth credentials:
```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret
FACEBOOK_APP_ID=your_facebook_app_id
FACEBOOK_APP_SECRET=your_facebook_app_secret
SESSION_SECRET=your_secure_session_secret
```

### 4. Run the Application

#### Option 1: Run Both Frontend and Backend
```bash
npm run dev:full
```

#### Option 2: Run Separately
```bash
# Terminal 1 - Backend
npm run dev:backend

# Terminal 2 - Frontend
npm run dev
```

## Usage

1. **Access the Honeypot**: Visit `http://localhost:5173`
2. **Toggle Views**: Click the "Admin" button to switch between decoy and dashboard
3. **Test Social Logins**: Try logging in with Google, LinkedIn, or Facebook
4. **Monitor Activity**: View real-time logs and alerts in the dashboard

## Security Features

- **Activity Logging**: All login attempts and social OAuth flows are logged
- **Threat Detection**: Automated analysis of suspicious patterns
- **Real-time Alerts**: Immediate notifications for high-risk activities
- **IP Tracking**: Geographic and behavioral analysis
- **Social Engineering Detection**: OAuth flow monitoring

## Production Deployment

For production deployment:

1. **Secure Environment Variables**: Use proper secret management
2. **HTTPS Configuration**: Enable SSL/TLS certificates
3. **Database Integration**: Replace in-memory storage with persistent database
4. **Alert Integration**: Connect Twilio, WhatsApp Business API, or email services
5. **Rate Limiting**: Implement proper request throttling
6. **Logging**: Set up centralized logging and monitoring

## API Endpoints

- `POST /api/login` - Handle login attempts
- `GET /api/logs` - Retrieve activity logs
- `GET /api/alerts` - Get security alerts
- `GET /api/stats` - Fetch system statistics
- `GET /auth/google` - Google OAuth initiation
- `GET /auth/linkedin` - LinkedIn OAuth initiation
- `GET /auth/facebook` - Facebook OAuth initiation

## Educational Purpose

This system is designed for cybersecurity research and education. It demonstrates:
- Social engineering attack vectors
- OAuth security considerations
- Threat detection methodologies
- Real-time monitoring systems
- Alert and response mechanisms

## License

This project is for educational and research purposes only.