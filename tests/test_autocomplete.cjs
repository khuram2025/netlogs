const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('fastapi_app/templates/logs/log_list.html', 'utf8');
const code = source.slice(source.indexOf('    function scheduleAutocomplete('), source.indexOf('    function nqlEsc('));
const calls = [], rendered = [];
const context = {
    nqlSuggestTimer: null, nqlSuggestSeq: 0, nqlSuggestController: null,
    nqlSuggestCache: new Map(), nqlInput: {value:'srcip:172', selectionStart:9},
    nqlAcLoading: {classList:{add(){},remove(){}}},
    nqlTimeRange: ()=>'1m', renderAutocomplete: data=>rendered.push(data),
    hideAutocomplete(){}, AbortController, setTimeout, clearTimeout,
    fetch: (url, options)=>new Promise(resolve=>calls.push({url,options,resolve})),
};
vm.createContext(context); vm.runInContext(code, context);
(async()=>{
    const first = context.fetchAutocomplete();
    context.nqlInput.value='srcip:172.20';
    context.scheduleAutocomplete(10000);
    assert.equal(calls[0].options.signal.aborted, true);
    calls[0].resolve({ok:true,json:async()=>({old:true})});
    await first;
    assert.deepEqual(rendered, []);
    clearTimeout(context.nqlSuggestTimer);
    const second = context.fetchAutocomplete();
    context.nqlInput.value='srcip:172';
    context.nqlSuggestCache.set('1m\0'+9+'\0srcip:172', {cached:true});
    await context.fetchAutocomplete();
    calls[1].resolve({ok:true,json:async()=>({stale:true})});
    await second;
    assert.deepEqual(rendered, [{cached:true}]);
    console.log('Autocomplete cancellation and cached-response race checks passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
