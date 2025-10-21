// Test script for combined registration endpoint
// Run with: node test-combined-registration.js

const fetch = require('node-fetch');

// Test data - these would normally come from the iOS app
const testData = {
  username: 'testuser',
  passkey: {
    credential: {
      id: 'test-credential-id-base64',
      rawId: 'test-credential-id-base64',
      response: {
        attestationObject: 'test-attestation-object-base64',
        clientDataJSON: 'test-client-data-json-base64'
      },
      type: 'public-key'
    }
  },
  appAttest: {
    keyId: 'test-app-attest-key-id-base64',
    attestationObject: 'test-app-attest-attestation-object-base64',
    localChallenge: 'test-local-challenge-base64'
  }
};

async function testCombinedRegistration() {
  try {
    console.log('Testing combined registration endpoint...');
    
    const response = await fetch('http://localhost:3000/api/register/combined', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(testData)
    });
    
    const result = await response.json();
    
    if (response.ok) {
      console.log('✅ Success:', JSON.stringify(result, null, 2));
    } else {
      console.log('❌ Error:', result);
    }
  } catch (error) {
    console.error('❌ Request failed:', error.message);
  }
}

// Note: This will fail with test data as the attestation objects are not valid
// In production, real data from the iOS app would be used
console.log('Note: This test will fail with dummy data.');
console.log('In production, the iOS app provides real attestation objects.');
console.log('');

testCombinedRegistration();