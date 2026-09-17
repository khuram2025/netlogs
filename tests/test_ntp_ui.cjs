const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('fastapi_app/templates/system/_ntp_panel.html', 'utf8');
const elements = new Map();
const element = () => ({style:{},value:'',textContent:'',append(){},replaceChildren(){}});
const get = id => {if (!elements.has(id)) elements.set(id,element()); return elements.get(id);};
let interval, calls = [];
let status = {synchronized:false,service_active:true,service_state:'active',reference:null,offset_seconds:null,
 now_utc:'2026-09-18T10:00:00+00:00',timezone:'UTC',last_sync:null,stratum:0,servers:['10.10.192.10'],peers:[],errors:[]};
vm.runInNewContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], {
 document:{getElementById:get,createElement:element,cookie:'zentryc_csrf=test'},
 setInterval:fn=>{interval=fn;},
 fetch:async (url,options)=>{const body=JSON.parse(options.body);calls.push({url,body});
  if(url.endsWith('time.update'))status={...status,servers:body.servers};
  return {ok:true,json:async()=>url.endsWith('time.status')?status:{message:'Saved'}};}
});
(async()=>{
 await new Promise(setImmediate);
 assert.equal(get('ntp-sync').textContent,'Not synchronized');
 assert.equal(get('ntp-servers').value,'10.10.192.10');
 assert.equal(get('ntp-clock').textContent,'2026-09-18 10:00:00 UTC');
 status={...status,timezone:'Asia/Riyadh',now_utc:'2026-09-17T22:30:00+00:00',last_sync:'2026-09-17T15:22:27.406058+00:00'};
 await interval();
 assert.equal(get('ntp-clock').textContent,'2026-09-18 01:30:00 UTC+03:00');
 assert.equal(get('ntp-last').textContent,'Last synchronized (Asia/Riyadh): 2026-09-17 18:22:27 UTC+03:00');
 assert.equal(get('ntp-zone').textContent,'System timezone: Asia/Riyadh');
 status={...status,timezone:'America/New_York',last_sync:'2026-01-17T15:22:27Z'};await interval();
 assert.equal(get('ntp-last').textContent,'Last synchronized (America/New_York): 2026-01-17 10:22:27 UTC-05:00');
 status={...status,last_sync:'2026-07-17T15:22:27Z'};await interval();
 assert.equal(get('ntp-last').textContent,'Last synchronized (America/New_York): 2026-07-17 11:22:27 UTC-04:00');
 status={...status,timezone:'invalid/zone'};await interval();
 assert.equal(get('ntp-last').textContent,'Last synchronized (UTC): 2026-07-17 15:22:27 UTC');
 assert.equal(get('ntp-zone').textContent,'System timezone unavailable; showing UTC');
 get('ntp-servers').value='10.10.192.10, ntp.example.com\n2001:db8::1';get('ntp-servers').oninput();
 await interval();
 assert.equal(get('ntp-servers').value,'10.10.192.10, ntp.example.com\n2001:db8::1');
 await get('ntp-form').onsubmit({preventDefault(){}});
 assert.deepEqual(calls.find(c=>c.url.endsWith('time.update')).body.servers,['10.10.192.10','ntp.example.com','2001:db8::1']);
 assert.equal(get('ntp-servers').value,'10.10.192.10\nntp.example.com\n2001:db8::1');
 status={...status,synchronized:true,reference:'10.10.192.10',offset_seconds:0.001};await interval();
 assert.equal(get('ntp-sync').textContent,'Synchronized');
 status={...status,synchronized:null};await interval();
 assert.equal(get('ntp-sync').textContent,'Status unavailable');
 await get('ntp-retry').onclick();
 assert(calls.some(c=>c.url.endsWith('time.retry')));
 console.log('NTP UI: status, multiple servers, unsaved edits and retry passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
