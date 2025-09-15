# Honeypot Backend API Documentation

## Overview
This API provides endpoints for the Chameleon Lite honeypot system, including activity logging, threat analysis, and real-time alerting capabilities.

**Base URL:** `http://localhost:5000`

## Authentication
Most endpoints are public for honeypot functionality. Dashboard endpoints may require authentication in production.

## Rate Limiting
- Login endpoints: 10 requests per 15 minutes
- API endpoints: 100 requests per 15 minutes
- Dashboard endpoints: 200 requests per 15 minutes

## Endpoints

### Health Check
```http
GET /api/health
```

**Response:**
```json
{
  "status": "OK",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": 3600,
  "version": "1.0.0"
}
```

### Authentication Endpoints

#### Login (Honeypot)
```http
POST /auth/login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:** (Always fails for honeypot)
```json
{
  "success": false,
  "message": "Invalid credentials. Please check your email and password."
}
```

#### OAuth Endpoints
- `GET /auth/google` - Initiate Google OAuth
- `GET /auth/linkedin` - Initiate LinkedIn OAuth  
- `GET /auth/facebook` - Initiate Facebook OAuth
- `GET /auth/{provider}/callback` - OAuth callback (redirects with error)

### Activity Logging

#### Get Activity Logs
```http
GET /api/logs?page=1&limit=50
```

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 50, max: 100)

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "type": "Failed Login Attempt",
      "email": "admin@company.com",
      "ip": "192.168.1.100",
      "timestamp": "10:30:45 AM",
      "userAgent": "Mozilla/5.0...",
      "provider": null,
      "severity": "high",
      "success": false
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 1
  }
}
```

#### Get Live Activity Feed
```http
GET /api/live-feed
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "type": "SQL Injection Attempt",
      "email": "admin' OR '1'='1",
      "ip": "10.0.0.50",
      "timestamp": "10:35:12 AM",
      "severity": "high",
      "provider": null
    }
  ],
  "timestamp": "2024-01-15T10:35:15.000Z"
}
```

### Alerts

#### Get Alerts
```http
GET /api/alerts?page=1&limit=20
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "title": "Multiple Failed Login Attempts",
      "description": "Detected 5 consecutive failed login attempts from IP 192.168.1.100",
      "level": "high",
      "timestamp": "1/15/2024, 10:30:00 AM",
      "ip": "192.168.1.100",
      "email": "admin@company.com",
      "reasonCode": "brute_force",
      "resolved": false,
      "alertSent": true
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 1
  }
}
```

#### Resolve Alert
```http
PUT /api/alerts/{id}/resolve
```

**Response:**
```json
{
  "success": true,
  "message": "Alert marked as resolved"
}
```

### Statistics

#### Get System Statistics
```http
GET /api/stats
```

**Response:**
```json
{
  "success": true,
  "data": {
    "totalAttempts": 1247,
    "uniqueIPs": 89,
    "socialLogins": 23,
    "failedLogins": 1224,
    "highAlerts": 12,
    "totalAlerts": 45,
    "recentAlerts": 8,
    "alerting": {
      "smsEnabled": true,
      "whatsappEnabled": true,
      "rateLimitMinutes": 5,
      "activeRateLimits": 3,
      "twilioConfigured": true
    },
    "lastUpdated": "2024-01-15T10:30:00.000Z"
  }
}
```

### Threat Analysis

#### Get Threat Analysis
```http
GET /api/threat-analysis
```

**Response:**
```json
{
  "success": true,
  "data": {
    "recentThreats": [
      {
        "type": "Failed Login Attempt",
        "severity": "high",
        "count": 15,
        "last_seen": "2024-01-15 10:30:00"
      }
    ],
    "topAttackingIPs": [
      {
        "ip_address": "192.168.1.100",
        "attempts": 25,
        "failed_attempts": 25
      }
    ],
    "analysisTimestamp": "2024-01-15T10:30:00.000Z"
  }
}
```

### Testing

#### Send Test Alert
```http
POST /api/test-alert
```

**Response:**
```json
{
  "success": true,
  "message": "Test alert sent",
  "result": {
    "success": true,
    "results": [
      {
        "type": "SMS",
        "success": true,
        "id": "SM1234567890"
      }
    ]
  }
}
```

## Error Responses

All endpoints return errors in this format:
```json
{
  "success": false,
  "error": "Error message",
  "details": [] // Optional validation details
}
```

## HTTP Status Codes
- `200` - Success
- `400` - Bad Request (validation errors)
- `401` - Unauthorized
- `404` - Not Found
- `429` - Too Many Requests (rate limited)
- `500` - Internal Server Error

## Threat Detection

The system automatically detects and classifies these threat types:

### Attack Types
- **SQL Injection**: Malicious SQL patterns in input
- **XSS Attempts**: Cross-site scripting patterns
- **Directory Traversal**: Path traversal attempts
- **Brute Force**: High-frequency login attempts
- **Credential Stuffing**: Multiple emails from same IP
- **Password Spraying**: Multiple attempts on same email
- **Bot Scanning**: Automated scanning behavior
- **Admin Targeting**: Attempts on administrative accounts

### Severity Levels
- **High**: Immediate threat requiring alert
- **Medium**: Suspicious activity worth monitoring
- **Low**: General reconnaissance or minor issues

## Alert Integration

### SMS Alerts (via Twilio)
Configure Twilio credentials in environment variables:
```env
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+1234567890
ALERT_PHONE_NUMBER=+1234567890
```

### WhatsApp Alerts (via Twilio)
```env
TWILIO_WHATSAPP_NUMBER=+1234567890
ALERT_WHATSAPP_NUMBER=whatsapp:+1234567890
```

### Rate Limiting
Alerts are rate-limited to prevent spam:
- Default: 1 alert per IP per 5 minutes
- Configurable via `ALERT_RATE_LIMIT_MINUTES`

## Database Schema

### activity_logs
- `id` - Primary key
- `timestamp` - When activity occurred
- `type` - Type of activity/attack
- `email` - Email used in attempt
- `password_hash` - Partial password (first 3 chars + asterisks)
- `ip_address` - Source IP address
- `user_agent` - Browser/client user agent
- `success` - Whether attempt succeeded (always false for honeypot)
- `provider` - OAuth provider (if applicable)
- `profile_id` - OAuth profile ID
- `payload` - Additional data (JSON)
- `severity` - Threat severity level
- `created_at` - Record creation time

### alerts
- `id` - Primary key
- `title` - Alert title
- `description` - Alert description
- `severity` - Alert severity (high/medium/low)
- `reason_code` - Threat classification code
- `ip_address` - Source IP
- `email` - Associated email
- `alert_sent` - Whether notification was sent
- `resolved` - Whether alert is resolved
- `created_at` - Alert creation time

### ip_tracking
- `id` - Primary key
- `ip_address` - IP address (unique)
- `first_seen` - First activity timestamp
- `last_seen` - Most recent activity
- `attempt_count` - Total attempts from IP
- `failed_attempts` - Failed attempt count
- `success_attempts` - Successful attempt count
- `is_blocked` - Whether IP is blocked
- `threat_score` - Calculated threat score

## Deployment Notes

### Environment Variables
See `.env.production` for complete configuration options.

### Security Considerations
- Use HTTPS in production
- Configure proper CORS origins
- Set secure session secrets
- Enable rate limiting
- Configure proper logging
- Use strong database passwords
- Regularly rotate API keys

### Monitoring
- Monitor log files in `logs/` directory
- Set up alerts for high-severity threats
- Monitor database size and performance
- Track API response times
- Monitor Twilio usage and costs

### Scaling
- Consider PostgreSQL for high-volume deployments
- Implement database connection pooling
- Use Redis for session storage
- Consider horizontal scaling with load balancers
- Implement proper caching strategies