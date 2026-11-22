#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const { chromium } = createRequire(import.meta.url)('playwright');
const root = process.env.IELTS_TEST_SOURCE_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const scripts = ['js/data/remoteApiClient.js','js/data/dataSources/remotePracticeDataSource.js','js/data/repositories/baseRepository.js','js/data/repositories/practiceRepository.js','js/core/practiceCore.js','js/core/practiceStore.js','js/views/legacyViewBundle.js','js/main.js'];
let records = [1,2].map(n=>({id:'record-'+n,type:'listening',title:'Synthetic attempt '+n,score:1,date:'2026-11-23T10:00:00Z',duration:n===1?216:426}));
let failWrites=false;
const host=`<!doctype html><html><body><div id="history-list"></div><div id="messages"></div>
${scripts.map(file=>'<script src="/'+file+'"></script>').join('\n')}
<script>
const mirror=new Map();
window.storage={getKey:k=>k,async get(k,f){return mirror.get(k)??f;},async set(k,v){mirror.set(k,v);return true;}};
window.remoteApiClient=new ExamData.RemoteApiClient();remoteApiClient.user={id:'synthetic-user'};remoteApiClient.csrfToken='synthetic-csrf';
const source=new ExamData.RemotePracticeDataSource({read:storage.get,write:storage.set,async remove(k){mirror.delete(k);}},remoteApiClient);
window.dataRepositories={practice:new ExamData.PracticeRepository(source)};
window.practiceRecords=[];
window.getPracticeRecordsState=()=>practiceRecords;
window.setPracticeRecordsState=records=>window.practiceRecords=records;
window.getExamIndexState=()=>[];
window.refreshBrowseProgressFromRecords=()=>{};
window.getBulkDeleteModeState=()=>false;
window.getMessageCenter=()=>({show(message,type){document.getElementById('messages').textContent=type+':'+message;}});
window.updatePracticeView=()=>document.getElementById('history-list').replaceChildren(...practiceRecords.map(record=>PracticeHistoryRenderer.createRecordNode(record)));
setupPracticeHistoryInteractions();
syncPracticeRecords();
</script></body></html>`;
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');res.setHeader('Content-Type','application/json');
 if(url.pathname==='/api/practice-records'&&req.method==='GET')return res.end(JSON.stringify({records}));
 if(url.pathname.startsWith('/api/practice-records')&&req.method!=='GET'){
  let body='';for await(const chunk of req)body+=chunk;
  if(failWrites){res.statusCode=500;return res.end('{"error":"Temporary failure"}');}
  const incoming=JSON.parse(body).records;
  records=url.pathname.endsWith('/sync')?[...incoming,...records.filter(r=>!incoming.some(n=>n.id===r.id))]:incoming;
  return res.end(JSON.stringify(url.pathname.endsWith('/sync')?{ok:true}:{records}));
 }
 if(scripts.includes(url.pathname.slice(1))){res.setHeader('Content-Type','text/javascript;charset=utf-8');return res.end(fs.readFileSync(path.join(root,url.pathname.slice(1))));}
 if(url.pathname==='/'){res.setHeader('Content-Type','text/html;charset=utf-8');return res.end(host);}
 res.writeHead(404).end();
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
let browser;
try{
 browser=await chromium.launch({headless:true,...(process.env.IELTS_PLAYWRIGHT_EXECUTABLE?{executablePath:process.env.IELTS_PLAYWRIGHT_EXECUTABLE}:{})});
 const page=await browser.newPage();page.setDefaultTimeout(5000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
 page.on('dialog',dialog=>dialog.accept());
 await page.goto('http://127.0.0.1:'+server.address().port);
 await page.locator('[data-record-action=delete]').first().waitFor();
 assert.deepEqual(await page.locator('.duration-time').allTextContents(),['03:36','07:06']);
 await page.evaluate(async()=>{await dataRepositories.practice.upsert({id:'saved-first',type:'listening',title:'Saved before delete',score:1,date:'2026-11-23',duration:5});await syncPracticeRecords();});
 await page.locator('[data-record-action=delete][data-record-id=saved-first]').click();
 await page.waitForFunction(()=>document.querySelectorAll('[data-record-action=delete]').length===2);
 assert.equal(records.some(r=>r.id==='saved-first'),false,'save then delete must reach the remote store');
 await page.reload();await page.locator('[data-record-action=delete]').first().waitFor();
 assert.equal(await page.locator('[data-record-action=delete]').count(),2,'deleted record must stay removed after reload');
 failWrites=true;
 await page.locator('[data-record-action=delete][data-record-id=record-1]').click();
 await page.waitForFunction(()=>document.getElementById('messages').textContent.startsWith('error:'));
 assert.equal(await page.locator('[data-record-action=delete]').count(),2,'failed remote deletion leaves the displayed rows intact');
 assert.equal(records.length,2);
 assert.deepEqual(errors,[]);
 console.log('PASS browser: exact history times, save-before-delete, durable deletion after reload, visible network failure with records preserved');
}finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
