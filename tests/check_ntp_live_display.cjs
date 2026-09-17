// Execute the deployed panel script using its real, read-only API response.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const {script,status}=JSON.parse(fs.readFileSync(0,'utf8'));
const elements=new Map();
const element=()=>({style:{},append(){},replaceChildren(){}});
const get=id=>{if(!elements.has(id))elements.set(id,element());return elements.get(id);};
vm.runInNewContext(script,{
 document:{getElementById:get,createElement:element,cookie:''},setInterval(){},
 fetch:async url=>{assert.equal(url,'/api/appliance/time.status');return {ok:true,json:async()=>status};}
});
setImmediate(()=>{
 assert.equal(status.timezone,'Asia/Riyadh');
 const expected=value=>new Date(new Date(value).getTime()+3*3600000).toISOString().slice(0,19).replace('T',' ')+' UTC+03:00';
 assert.equal(get('ntp-clock').textContent,expected(status.now_utc));
 if(status.last_sync)assert.equal(get('ntp-last').textContent,'Last synchronized (Asia/Riyadh): '+expected(status.last_sync));
 assert.equal(get('ntp-zone').textContent,'System timezone: Asia/Riyadh');
 console.log(JSON.stringify({case:'live-ntp-timezone',timezone:status.timezone,synchronized:status.synchronized,
  clock:get('ntp-clock').textContent,last_sync:get('ntp-last').textContent,passed:true}));
});
