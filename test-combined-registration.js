/**
 * Test script for iOS Combined Registration
 * Tests the /api/register/combined endpoint with iOS-specific data
 */

const axios = require('axios');

// Configuration
const API_BASE_URL = process.env.API_URL || 'http://localhost:3000';
const TEST_USERNAME = `testuser_${Date.now()}`;

// Simulate iOS credential data
const mockIOSCredential = {
  id: "test_credential_id_base64url",
  rawId: "test_credential_id_base64url",
  type: "public-key",
  response: {
    attestationObject: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_test_attestation_object",
    clientDataJSON: "Gq3PUh7XBwj8kHkiRnH5FhNjCfpZCIhFKUPBmhXU6vE" // This is a hash, not JSON!
  }
};

// Simulate App Attest data
const mockAppAttest = {
  keyId: "test_app_attest_key_id",
  attestationObject: "o2NmbXRmYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAi0wggIpMIIB_test_app_attest",
  localChallenge: "test_local_challenge_base64url"
};

async function testCombinedRegistration() {
  console.log('\n🚀 Testing iOS Combined Registration');
  console.log('================================');
  console.log(`API URL: ${API_BASE_URL}`);
  console.log(`Username: ${TEST_USERNAME}`);

  try {
    // Step 1: Get registration challenge
    console.log('\n📝 Step 1: Getting registration challenge...');
    const challengeResponse = await axios.post(`${API_BASE_URL}/api/register`, {
      username: TEST_USERNAME
    });
    
    const challenge = challengeResponse.data.challenge;
    console.log('✅ Challenge received:', challenge);

    // Step 2: Send combined registration
    console.log('\n📱 Step 2: Sending combined registration...');
    const combinedRequest = {
      username: TEST_USERNAME,
      passkey: {
        credential: mockIOSCredential,
        challenge: challenge // Server challenge for audit
      },
      appAttest: mockAppAttest,
      platform: "ios-extension" // Critical: tell backend this is iOS
    };

    console.log('\nRequest payload:');
    console.log(JSON.stringify(combinedRequest, null, 2));

    const registrationResponse = await axios.post(
      `${API_BASE_URL}/api/register/combined`,
      combinedRequest,
      {
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );

    console.log('\n✅ Combined registration successful!');
    console.log('Response:', JSON.stringify(registrationResponse.data, null, 2));

  } catch (error) {
    console.error('\n❌ Test failed!');
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Error:', error.response.data);
      console.error('\nFull response:', JSON.stringify(error.response.data, null, 2));
    } else {
      console.error('Error:', error.message);
    }
    process.exit(1);
  }
}

// Run the test
testCombinedRegistration()
  .then(() => {
    console.log('\n✅ All tests completed successfully!');
    process.exit(0);
  })
  .catch(error => {
    console.error('\n❌ Unexpected error:', error);
    process.exit(1);
  });