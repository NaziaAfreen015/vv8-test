async function collectAndDisplayFingerprintData() {
    const fpPromise = import('https://openfpcdn.io/fingerprintjs/v4')
          .then(FingerprintJS => FingerprintJS.load())
      
        // Get the visitor identifier when you need it.
        fpPromise
          .then(fp => fp.get())
          .then(result => {
            // This is the visitor identifier:
            const visitorId = result.visitorId
            // console.log(visitorId)
            document.getElementById("hashedData").textContent = visitorId;
          })

}


// Call the function to collect and display the data
collectAndDisplayFingerprintData();