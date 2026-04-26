"use strict";

// ── Base64url helpers ──────────────────────────────────────
function b64urlToBuffer(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}

function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ── Decode server-sent PublicKeyCredentialCreationOptions ──
function prepareCreationOptions(opts) {
  opts.challenge = b64urlToBuffer(opts.challenge);
  opts.user.id = b64urlToBuffer(opts.user.id);
  if (opts.excludeCredentials) {
    opts.excludeCredentials = opts.excludeCredentials.map(c => ({
      ...c, id: b64urlToBuffer(c.id),
    }));
  }
  return opts;
}

// ── Decode server-sent PublicKeyCredentialRequestOptions ───
function prepareRequestOptions(opts) {
  opts.challenge = b64urlToBuffer(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map(c => ({
      ...c, id: b64urlToBuffer(c.id),
    }));
  }
  return opts;
}

// ── Encode a newly created credential for the server ──────
function encodeCredential(cred) {
  const resp = cred.response;
  const out = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToB64url(resp.clientDataJSON),
    },
  };
  if (resp.attestationObject) {
    out.response.attestationObject = bufferToB64url(resp.attestationObject);
  }
  if (resp.authenticatorData) {
    out.response.authenticatorData = bufferToB64url(resp.authenticatorData);
    out.response.signature = bufferToB64url(resp.signature);
    if (resp.userHandle) out.response.userHandle = bufferToB64url(resp.userHandle);
  }
  return out;
}

// ── WebAuthn registration flow (portal, bearer auth) ──────
async function waRegister(beginUrl, finishUrl, deviceName) {
  const token = document.cookie.match(/portal_tok=([^;]+)/)?.[1] || "";
  const beginResp = await fetch(beginUrl, {
    method: "POST",
    headers: { "Authorization": "Bearer " + token },
  });
  if (!beginResp.ok) throw new Error(await beginResp.text());
  const { options, session_id } = await beginResp.json();

  const cred = await navigator.credentials.create({ publicKey: prepareCreationOptions(options.publicKey) });
  const finishResp = await fetch(`${finishUrl}?session_id=${session_id}&device_name=${encodeURIComponent(deviceName)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: JSON.stringify(encodeCredential(cred)),
  });
  if (!finishResp.ok) throw new Error(await finishResp.text());
  return finishResp.json();
}

// ── WebAuthn SSO login flow ───────────────────────────────
async function waSSOLogin(beginUrl, finishUrl) {
  const status = document.getElementById("wa-status");
  const setStatus = msg => { if (status) status.textContent = msg; };

  setStatus("Requesting challenge…");
  const beginResp = await fetch(beginUrl, { method: "POST" });
  if (!beginResp.ok) throw new Error(await beginResp.text());
  const { options, session_id } = await beginResp.json();

  setStatus("Waiting for authenticator…");
  const assertion = await navigator.credentials.get({ publicKey: prepareRequestOptions(options.publicKey) });

  setStatus("Verifying…");
  const finishResp = await fetch(`${finishUrl}?session_id=${session_id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(encodeCredential(assertion)),
  });
  if (!finishResp.ok) throw new Error(await finishResp.text());
  const { redirect_to } = await finishResp.json();
  window.location.href = redirect_to;
}

// ── Portal WebAuthn registration (cookie auth) ────────────
async function waRegisterPortal(beginUrl, finishUrl, deviceName) {
  const beginResp = await fetch(beginUrl, { method: "POST" });
  if (!beginResp.ok) throw new Error(await beginResp.text());
  const { options, session_id } = await beginResp.json();

  const cred = await navigator.credentials.create({ publicKey: prepareCreationOptions(options.publicKey) });
  const finishResp = await fetch(`${finishUrl}?session_id=${session_id}&device_name=${encodeURIComponent(deviceName)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(encodeCredential(cred)),
  });
  if (!finishResp.ok) throw new Error(await finishResp.text());
  return finishResp.json();
}
