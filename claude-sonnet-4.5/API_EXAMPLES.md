# API Testing Examples

This file contains examples for testing the Secure Notes App API using curl.

## Base URL

```
http://localhost:3000/api
```

## Health Check

```bash
curl http://localhost:3000/health
```

## Authentication

### Register a New User

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!",
    "confirmPassword": "SecurePass123!"
  }'
```

Expected Response:

```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "testuser"
  }
}
```

### Login

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

Save the token from the response for subsequent requests.

### Get Current User

```bash
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt
```

### Logout

```bash
curl -X POST http://localhost:3000/api/auth/logout \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt
```

## Notes Management

### Create a Note

```bash
curl -X POST http://localhost:3000/api/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt \
  -d '{
    "title": "My First Note",
    "content": "This is the content of my first note."
  }'
```

### Get All Notes

```bash
curl -X GET http://localhost:3000/api/notes \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt
```

### Get a Single Note

```bash
curl -X GET http://localhost:3000/api/notes/NOTE_ID_HERE \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt
```

### Update a Note

```bash
curl -X PUT http://localhost:3000/api/notes/NOTE_ID_HERE \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt \
  -d '{
    "title": "Updated Note Title",
    "content": "Updated note content."
  }'
```

### Delete a Note

```bash
curl -X DELETE http://localhost:3000/api/notes/NOTE_ID_HERE \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -b cookies.txt
```

## Security Testing

### Test Rate Limiting

Run this multiple times quickly:

```bash
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"wrong"}' &
done
```

After 5 attempts, you should get a rate limit error.

### Test Invalid Input (XSS Protection)

```bash
curl -X POST http://localhost:3000/api/notes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "title": "<script>alert(\"XSS\")</script>",
    "content": "Test content"
  }'
```

The script tags should be sanitized.

### Test SQL Injection (Should Fail)

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin\" OR \"1\"=\"1",
    "password": "password"
  }'
```

Should return invalid credentials.

### Test Authorization

Try to access another user's note (should fail):

1. Create a note with User A
2. Login as User B
3. Try to access User A's note ID

```bash
curl -X GET http://localhost:3000/api/notes/USER_A_NOTE_ID \
  -H "Authorization: Bearer USER_B_TOKEN"
```

Should return 403 Forbidden.

### Test CSRF Protection

Try to make a request without proper headers:

```bash
curl -X POST http://localhost:3000/api/notes \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  --referer "http://malicious-site.com"
```

### Test Content-Type Validation

```bash
curl -X POST http://localhost:3000/api/notes \
  -H "Content-Type: text/plain" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d "title=Test&content=Test"
```

## Password Strength Testing

### Too Short

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser2",
    "password": "Short1!",
    "confirmPassword": "Short1!"
  }'
```

### Missing Requirements

```bash
# No special character
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser3",
    "password": "NoSpecial123",
    "confirmPassword": "NoSpecial123"
  }'

# No uppercase
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser4",
    "password": "nouppercase123!",
    "confirmPassword": "nouppercase123!"
  }'
```

## Performance Testing

### Concurrent Requests

```bash
# Install apache bench: sudo apt-get install apache2-utils

# Test GET endpoint (after authentication)
ab -n 1000 -c 10 -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  http://localhost:3000/api/notes/
```

## Using Postman

Import the following environment variables:

- `base_url`: http://localhost:3000/api
- `token`: (will be set after login)
- `note_id`: (will be set after creating a note)

Then use `{{base_url}}`, `{{token}}`, and `{{note_id}}` in your requests.

## Using HTTPie (Alternative to curl)

```bash
# Install: pip install httpie

# Register
http POST localhost:3000/api/auth/register \
  username=testuser \
  password=SecurePass123! \
  confirmPassword=SecurePass123!

# Login
http POST localhost:3000/api/auth/login \
  username=testuser \
  password=SecurePass123!

# Create note
http POST localhost:3000/api/notes \
  Authorization:"Bearer YOUR_TOKEN" \
  title="My Note" \
  content="Note content"

# Get notes
http GET localhost:3000/api/notes \
  Authorization:"Bearer YOUR_TOKEN"
```

## Automated Testing Script

```bash
#!/bin/bash
# save as test-api.sh

BASE_URL="http://localhost:3000/api"
USERNAME="testuser_$(date +%s)"
PASSWORD="SecurePass123!"

echo "🧪 Testing Secure Notes API"

# Register
echo -e "\n1️⃣ Registering user..."
RESPONSE=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"confirmPassword\":\"$PASSWORD\"}")

TOKEN=$(echo $RESPONSE | jq -r '.token')

if [ "$TOKEN" = "null" ]; then
  echo "❌ Registration failed"
  exit 1
fi
echo "✅ User registered, token: ${TOKEN:0:20}..."

# Create note
echo -e "\n2️⃣ Creating note..."
NOTE_RESPONSE=$(curl -s -X POST "$BASE_URL/notes" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Test Note","content":"This is a test"}')

NOTE_ID=$(echo $NOTE_RESPONSE | jq -r '.data.id')

if [ "$NOTE_ID" = "null" ]; then
  echo "❌ Note creation failed"
  exit 1
fi
echo "✅ Note created, ID: $NOTE_ID"

# Get notes
echo -e "\n3️⃣ Fetching notes..."
NOTES=$(curl -s -X GET "$BASE_URL/notes" \
  -H "Authorization: Bearer $TOKEN")

COUNT=$(echo $NOTES | jq '.count')
echo "✅ Found $COUNT note(s)"

# Update note
echo -e "\n4️⃣ Updating note..."
curl -s -X PUT "$BASE_URL/notes/$NOTE_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"Updated Note","content":"Updated content"}' > /dev/null
echo "✅ Note updated"

# Delete note
echo -e "\n5️⃣ Deleting note..."
curl -s -X DELETE "$BASE_URL/notes/$NOTE_ID" \
  -H "Authorization: Bearer $TOKEN" > /dev/null
echo "✅ Note deleted"

echo -e "\n✨ All tests passed!\n"
```

Make it executable and run:

```bash
chmod +x test-api.sh
./test-api.sh
```
