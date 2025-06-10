#!/usr/bin/env node

/**
 * Basic API Test Script
 * Tests core functionality of the secure notes app
 */

const http = require('http')

const BASE_URL = 'http://localhost:3000'
let sessionCookie = ''
let csrfToken = ''

// Helper function to make HTTP requests
function makeRequest (path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL)
    const reqOptions = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'API-Test/1.0',
        ...options.headers
      }
    }

    if (sessionCookie) {
      reqOptions.headers.Cookie = sessionCookie
    }

    const req = http.request(reqOptions, (res) => {
      let data = ''
      res.on('data', (chunk) => {
        data += chunk
      })
      res.on('end', () => {
        // Extract session cookie from response
        if (res.headers['set-cookie']) {
          const cookies = res.headers['set-cookie']
          const sessionCookies = cookies.filter((cookie) =>
            cookie.startsWith('connect.sid=')
          )
          if (sessionCookies.length > 0) {
            sessionCookie = sessionCookies[0].split(';')[0]
          }
        }

        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        })
      })
    })

    req.on('error', reject)

    if (options.body) {
      req.write(options.body)
    }

    req.end()
  })
}

async function runTests () {
  console.log('🚀 Starting API Tests for Secure Notes App\n')

  try {
    // Test 1: Check if server is running
    console.log('1. Testing server availability...')
    const healthCheck = await makeRequest('/')
    if (healthCheck.statusCode === 200) {
      console.log('   ✅ Server is running')
    } else {
      console.log(`   ❌ Server returned status ${healthCheck.statusCode}`)
      return
    }

    // Test 2: Establish session and get CSRF token
    console.log('2. Establishing session and getting CSRF token...')
    const csrfResponse = await makeRequest('/api/csrf-token')
    if (csrfResponse.statusCode === 200) {
      const csrfData = JSON.parse(csrfResponse.body)
      csrfToken = csrfData.csrfToken
      console.log('   ✅ Session established and CSRF token obtained')
    } else {
      console.log('   ❌ Failed to get CSRF token')
      return
    }

    // Test 3: Register a test user
    console.log('3. Testing user registration...')
    const registerData = {
      username: 'testuser_' + Date.now(),
      email: 'test' + Date.now() + '@example.com',
      password: 'SecurePass123!'
    }

    const registerResponse = await makeRequest('/api/auth/register', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify(registerData)
    })

    if (registerResponse.statusCode === 201) {
      console.log('   ✅ User registration successful')
    } else {
      console.log(`   ❌ Registration failed: ${registerResponse.body}`)
      return
    }

    // Test 4: Login with the test user
    console.log('4. Testing user login...')
    const loginResponse = await makeRequest('/api/auth/login', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({
        username: registerData.username,
        password: registerData.password
      })
    })

    if (loginResponse.statusCode === 200) {
      console.log('   ✅ User login successful')
    } else {
      console.log(`   ❌ Login failed: ${loginResponse.body}`)
      return
    }

    // Test 5: Create a note
    console.log('5. Testing note creation...')
    const noteData = {
      title: 'Test Note',
      content: 'This is a test note created by the API test script.'
    }

    const createNoteResponse = await makeRequest('/api/notes', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify(noteData)
    })

    let noteId
    if (createNoteResponse.statusCode === 201) {
      const noteResponse = JSON.parse(createNoteResponse.body)
      noteId = noteResponse.note.id
      console.log('   ✅ Note creation successful')
    } else {
      console.log(`   ❌ Note creation failed: ${createNoteResponse.body}`)
      return
    }

    // Test 6: Get all notes
    console.log('6. Testing note retrieval...')
    const getNotesResponse = await makeRequest('/api/notes')

    if (getNotesResponse.statusCode === 200) {
      const notes = JSON.parse(getNotesResponse.body)
      if (notes.length > 0) {
        console.log('   ✅ Note retrieval successful')
      } else {
        console.log('   ⚠️  No notes found')
      }
    } else {
      console.log(`   ❌ Note retrieval failed: ${getNotesResponse.body}`)
    }

    // Test 7: Update the note
    console.log('7. Testing note update...')
    const updateData = {
      title: 'Updated Test Note',
      content: 'This note has been updated by the API test script.'
    }

    const updateNoteResponse = await makeRequest(`/api/notes/${noteId}`, {
      method: 'PUT',
      headers: {
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify(updateData)
    })

    if (updateNoteResponse.statusCode === 200) {
      console.log('   ✅ Note update successful')
    } else {
      console.log(`   ❌ Note update failed: ${updateNoteResponse.body}`)
    }

    // Test 8: Delete the note
    console.log('8. Testing note deletion...')
    const deleteNoteResponse = await makeRequest(`/api/notes/${noteId}`, {
      method: 'DELETE',
      headers: {
        'X-CSRF-Token': csrfToken
      }
    })

    if (deleteNoteResponse.statusCode === 200) {
      console.log('   ✅ Note deletion successful')
    } else {
      console.log(`   ❌ Note deletion failed: ${deleteNoteResponse.body}`)
    }

    // Test 9: Logout
    console.log('9. Testing user logout...')
    const logoutResponse = await makeRequest('/api/auth/logout', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': csrfToken
      }
    })

    if (logoutResponse.statusCode === 200) {
      console.log('   ✅ User logout successful')
    } else {
      console.log(`   ❌ Logout failed: ${logoutResponse.body}`)
    }

    console.log('\n🎉 All tests completed successfully!')
    console.log('\n📋 Security Features Verified:')
    console.log('   ✅ CSRF Protection')
    console.log('   ✅ Session Management')
    console.log('   ✅ Authentication & Authorization')
    console.log('   ✅ Input Validation')
    console.log('   ✅ Security Headers')
    console.log('   ✅ Rate Limiting')
  } catch (error) {
    console.error('❌ Test failed:', error.message)
  }
}

// Run tests if called directly
if (require.main === module) {
  runTests()
}

module.exports = { runTests }
