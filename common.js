function setResult(value, status = "Done") {
  document.getElementById("result").textContent = value;
  document.getElementById("status").textContent = status;
}

function setError(err) {
  const msg = err instanceof Error ? err.message : String(err);
  setResult(`ERROR: ${msg}`, "Failed");
}

function safeStringify(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

function pickBestId(obj) {
  if (obj == null) return "No result";

  const candidates = [
    obj.visitorId,
    obj.deviceId,
    obj.clusterUUID,
    obj.hash,
    obj.fingerprint,
    obj.id,
    obj.thumbmark,
    obj.botScore,
  ].filter(Boolean);

  return candidates.length ? String(candidates[0]) : safeStringify(obj);
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.async = true;
    s.onload = resolve;
    s.onerror = () => reject(new Error(`Failed to load script: ${src}`));
    document.head.appendChild(s);
  });
}