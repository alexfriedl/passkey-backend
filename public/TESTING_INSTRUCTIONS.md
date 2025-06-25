# Android Device Testing Instructions for Passkey Authentication

## Overview
We are developing a passkey authentication app that works in a WebView context without Google Play Services. Your device testing helps us understand what features and compatibility layers we need to build for different Android devices.

## Testing Steps

### 1. Download the APK
- Download the APK file from: `https://passkey-app-2c349882cba6.herokuapp.com/app-debug.apk`
- The file will be saved to your device's Downloads folder

### 2. Install the APK
1. Open your device's **Settings**
2. Go to **Security** or **Privacy & Security**
3. Enable **"Install apps from unknown sources"** or **"Allow from this source"** for your browser/file manager
4. Open your **File Manager** app
5. Navigate to the **Downloads** folder
6. Tap on the **app-debug.apk** file
7. Tap **Install** when prompted
8. Wait for installation to complete

### 3. Test the Application
1. Open the installed app from your home screen or app drawer
2. The app will display a registration form
3. Enter **any username** you want (e.g., "testuser123")
4. Tap the **"Register"** button
5. The app will attempt to create a passkey credential
6. **Important**: The process may succeed or fail - both outcomes provide valuable data for us

### 4. What We're Collecting
When you tap "Register", the app automatically logs your device information including:
- Device model and manufacturer
- Android version and API level
- WebView version
- Hardware security chip availability
- WebAuthn/Passkey support status
- Play Services installation status

**Example log data:**
```json
{
  "event": "deviceInfoCollected",
  "details": {
    "model": "Pixel 6",
    "manufacturer": "Google",
    "androidVersion": "13",
    "webViewVersion": "136.0.7103.125",
    "hasHardwareChip": true,
    "playServicesInstalled": true,
    "webAuthnStubbed": false,
    "finalWebAuthnState": {
      "credentialsCreateAvailable": true,
      "publicKeyCredentialAvailable": true
    }
  }
}
```

### 5. Privacy Notice
- We only collect technical device specifications
- No personal information is stored
- The username you enter is not saved permanently
- All data is used solely for compatibility development

### 6. After Testing
- You can uninstall the app after testing if desired
- Your participation helps us build better passkey authentication for users worldwide
- Thank you for contributing to passwordless authentication technology!

## Troubleshooting

**If installation fails:**
- Make sure "Unknown sources" is enabled in Security settings
- Try downloading the APK again
- Restart your device and try again

**If the app crashes:**
- This is expected on some devices - the crash data is also valuable for us
- Try opening the app 2-3 times to generate multiple data points

**If registration seems to hang:**
- Wait up to 30 seconds for the process to complete
- The logging happens automatically in the background

## Technical Background
We're building a universal passkey solution that works across all Android devices, regardless of Google Play Services availability. Your device data helps us understand the current state of WebAuthn support and hardware security features across different Android ecosystems, particularly in markets where Play Services may not be standard.

---
*This testing contributes to making passwordless authentication accessible to everyone, everywhere.*