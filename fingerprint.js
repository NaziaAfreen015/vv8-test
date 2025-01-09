async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function getScreenResolution() {
    return `${window.screen.width}x${window.screen.height}`;
}

function getUserAgent() {
    return navigator.userAgent;
}

function getCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText("Canvas Fingerprint Test", 2, 2);
    return canvas.toDataURL();
}

async function collectAndDisplayFingerprintData() {
    const screenResolution = getScreenResolution();
    const userAgent = getUserAgent();
    const canvasFingerprint = getCanvasFingerprint();

    const fingerprintData = {
        'Screen Resolution': screenResolution,
        'User Agent': userAgent,
        'Canvas Data': canvasFingerprint
    };

    // Display collected data
    const output = document.getElementById("output");
    output.innerHTML = `<pre>${JSON.stringify(fingerprintData, null, 2)}</pre>`;

    // Hash the fingerprint data
    const dataString = JSON.stringify(fingerprintData);
    const hashedData = await sha256(dataString);

    // Display hashed data
    document.getElementById("hashedData").textContent = hashedData;
}

// Call the function to collect and display the data
// collectAndDisplayFingerprintData();

// async function sha256(message) {\x0a    const msgBuffer = new TextEncoder().encode(message);\x0a    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);\x0a    const hashArray = Array.from(new Uint8Array(hashBuffer));\x0a    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');\x0a}

// \x0a\x0afunction getScreenResolution() {\x0a    return `${window.screen.width}x${window.screen.height}`;

// \x0a}\x0a\x0afunction getUserAgent() {\x0a    return navigator.userAgent;\x0a}

// \x0a\x0afunction getCanvasFingerprint() {\x0a    const canvas = document.createElement('canvas');\x0a    const ctx = canvas.getContext('2d');\x0a    ctx.textBaseline = 'top';\x0a    ctx.font = '14px Arial';\x0a    ctx.fillText("Canvas Fingerprint Test", 2, 2);\x0a    return canvas.toDataURL();\x0a}

// \x0a\x0aasync function collectAndDisplayFingerprintData() {\x0a    const screenResolution = getScreenResolution();\x0a    const userAgent = getUserAgent();\x0a    const canvasFingerprint = getCanvasFingerprint();\x0a\x0a    const fingerprintData = {\x0a        'Screen Resolution'\: screenResolution,\x0a        'User Agent'\: userAgent,\x0a        'Canvas Data'\: canvasFingerprint\x0a    };\x0a\x0a    // Display collected data\x0a 
//    const output = document.getElementById("output");\x0a    output.innerHTML = `<pre>${JSON.stringify(fingerprintData, null, 2)}</pre>`;\x0a\x0a   
//     // Hash the fingerprint data\x0a    
//     const dataString = JSON.stringify(fingerprintData);\x0a    const hashedData = await sha256(dataString);\x0a\x0a   
//      // Display hashed data\x0a   
//       document.getElementById("hashedData").textContent = hashedData;\x0a}
      
//       \x0a\x0a
//       // Call the function to collect and display the data
//       \x0acollectAndDisplayFingerprintData();\x0a
