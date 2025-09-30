# 🚀 QUICK START GUIDE

## For the Impatient (but Security-Conscious) Developer

### Step 1: Install Dependencies (2 minutes)

```bash
cd claude-sonnet-4.5
npm install
```

**Note:** This app uses `bcryptjs` instead of native `bcrypt`, so no compilation issues on Windows! ✅

### Step 2: Verify Configuration (30 seconds)

```bash
node setup-check.js
```

This will check your .env file and show any issues.

### Step 3: Start the Server (10 seconds)

**Development mode:**

```bash
npm run dev
```

**Production mode:**

```bash
npm start
```

### Step 4: Access the Application

Open your browser to: **http://localhost:3000**

## First Use

1. **Register an account:**

   - Username: 3-30 characters (letters, numbers, \_, -)
   - Password: Min 8 chars with uppercase, lowercase, number, and special character
   - Example: `TestUser123!`

2. **Create a note:**

   - Click "New Note"
   - Add a title and content
   - Click "Save"

3. **Manage your notes:**
   - View all notes in the left panel
   - Click to edit
   - Delete when done

## Testing the API

### Using curl:

```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"SecurePass123!","confirmPassword":"SecurePass123!"}'

# Login (save the token)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"username":"testuser","password":"SecurePass123!"}'

# Create a note
curl -X POST http://localhost:3000/api/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt \
  -d '{"title":"My Note","content":"Note content"}'

# Get all notes
curl http://localhost:3000/api/notes \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt
```

See **API_EXAMPLES.md** for complete API documentation.

## Common Issues

### Issue: Module not found errors

**Solution:**

```bash
rm -rf node_modules package-lock.json
npm install
```

### Issue: Port 3000 already in use

**Solution:** Change PORT in .env file:

```env
PORT=3001
```

### Issue: Default secrets warning

**Solution:** Generate new secrets:

```bash
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(48).toString('base64'))"
node -e "console.log('COOKIE_SECRET=' + require('crypto').randomBytes(48).toString('base64'))"
```

Update these in your .env file.

### Issue: CORS error

**Solution:** Add your origin to ALLOWED_ORIGINS in .env:

```env
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

## Security Quick Checks

### ✅ Before Development:

- [ ] Dependencies installed (`npm install`)
- [ ] .env file exists
- [ ] Running in development mode

### ✅ Before Production:

- [ ] All default secrets changed
- [ ] NODE_ENV=production set
- [ ] HTTPS enabled
- [ ] CORS configured for production domain
- [ ] Database configured (not in-memory)
- [ ] Redis configured for rate limiting
- [ ] Monitoring set up
- [ ] Backups configured

## File Structure Overview

```
├── src/
│   ├── server.js           # Main app
│   ├── middleware/         # Security & validation
│   ├── routes/             # API endpoints
│   ├── controllers/        # Business logic
│   └── models/             # Data models
├── public/                 # Frontend files
├── .env                    # Configuration
└── [docs]                  # Documentation
```

## Key Scripts

```bash
npm start          # Start production server
npm run dev        # Start with auto-reload (nodemon)
npm run lint       # Check code quality
npm audit          # Security audit
node setup-check.js # Verify configuration
```

## Environment Variables

**Required:**

- `JWT_SECRET` - Token signing secret (CHANGE IN PRODUCTION!)
- `COOKIE_SECRET` - Cookie signing secret (CHANGE IN PRODUCTION!)

**Optional but Recommended:**

- `PORT` - Server port (default: 3000)
- `ALLOWED_ORIGINS` - CORS origins (default: http://localhost:3000)
- `BCRYPT_ROUNDS` - Hash rounds (default: 12)
- `RATE_LIMIT_MAX_REQUESTS` - Rate limit (default: 100)

See `.env.example` for all options.

## Next Steps

1. **Read the docs:**

   - README.md - Complete documentation
   - SECURITY.md - Security policy
   - DEPLOYMENT.md - Production deployment
   - API_EXAMPLES.md - API testing examples

2. **Run security checks:**

   ```bash
   npm audit
   node setup-check.js
   ```

3. **Test the application:**

   - Register a user
   - Create some notes
   - Test the API endpoints

4. **Prepare for production:**
   - Review DEPLOYMENT.md
   - Change all secrets
   - Set up database
   - Configure HTTPS

## Support

- **Security issues:** See SECURITY.md for reporting
- **Bug reports:** Create an issue
- **Questions:** Check documentation first

## Key Security Features

🔒 **Authentication:** JWT + Bcrypt
🛡️ **Protection:** OWASP Top 10 covered
🚦 **Rate Limiting:** 5 attempts per 15 min (auth)
✅ **Validation:** All inputs validated & sanitized
🔐 **Encryption:** Bcrypt (12 rounds)
📊 **Monitoring:** Health check at /health
🌐 **Headers:** Helmet.js security headers

## Quick Health Check

After starting the server:

```bash
curl http://localhost:3000/health
```

Should return:

```json
{
  "status": "ok",
  "timestamp": "2025-09-30T..."
}
```

---

**Ready to go!** Your secure notes app is up and running. 🎉

For detailed information, see:

- 📖 README.md - Complete guide
- 🔒 SECURITY_REPORT.md - Security analysis
- 🚀 DEPLOYMENT.md - Production deployment
- 🧪 API_EXAMPLES.md - API testing
