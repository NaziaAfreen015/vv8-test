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
collectAndDisplayFingerprintData();
