(()=>{
'use strict';
const bootstrap="__BOOTSTRAP__";
const relayOrigin='https://__HOST__',carrierCapabilities='https,https-lanes,websocket,websocket-lanes';
const negotiationEnabled=__NEGOTIATION_ENABLED__,candidateCount=__CANDIDATE_COUNT__,candidateDeadlines=[__CARRIER_DEADLINES__];
const longPollMs=__LONG_POLL_SECS__*1000,bridgeRequestMs=__BRIDGE_REQUEST_SECS__*1000,bridgeRetryMs=__BRIDGE_RETRY_SECS__*1000;
const probeCoalesceMs=__CARRIER_PROBE_COALESCE_MS__;
let negotiatedCandidateCount=candidateCount,negotiatedFinalDeadline=candidateDeadlines[3],negotiatedFrozen=false;
const batchLimit=__BATCH_LIMIT__,queueLimit=__QUEUE_LIMIT__,queueItemLimit=__QUEUE_ITEMS__;
const laneQueueLimit=Math.min(queueLimit,8388608),laneItemLimit=Math.min(queueItemLimit,1024),closedLaneLimit=4096;
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'';
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',cleanupToken='',createStarted=false,socket=null,socketReady=false,carrier='';
let queuedBytes=0,queuedItems=0,upSequence=1,downCursor='0',upRunning=false,upLease=null,pollController=null;
let helloFrame=null,welcomeSent=false,carrierAttempt=1,carrierFailure='',carrierCommitted=false;
let negotiationStartedAt=0,carrierTimer=null,probeTimer=null,attemptController=null,attemptEpoch=1,candidateRunning=false,switching=false,currentAttempt=null;
const pending=[],upPending=[],lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];
const status=state=>{if(port&&!closed)port.postMessage({t:'status',state})};
const pause=(milliseconds,signal)=>new Promise((resolve,reject)=>{
 if(signal&&signal.aborted){reject(new Error('request aborted'));return}
 const timer=setTimeout(done,milliseconds);function done(){if(signal)signal.removeEventListener('abort',abort);resolve()}
 function abort(){clearTimeout(timer);signal.removeEventListener('abort',abort);reject(new Error('request aborted'))}
 if(signal)signal.addEventListener('abort',abort,{once:true});
});
const socketURL=()=>relayOrigin.replace(/^https:/,'wss:')+'/api/v1/ws';
const options=(method,token,body,headers,signal,keepalive)=>({
 method,body,signal,keepalive:!!keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
 headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{},headers||{})
});
const attemptHeaders=(attempt,failure)=>negotiationEnabled?Object.assign({'X-Carrier-Capabilities':carrierCapabilities,'X-Carrier-Attempt':String(attempt)},failure?{'X-Carrier-Failure':failure}:{}):{};
function reserve(data,lane){
 let buffered=socket?socket.bufferedAmount:0;for(const value of lanes.values())if(value.socket)buffered+=value.socket.bufferedAmount;
 if(!data.byteLength||data.byteLength>queueLimit-queuedBytes-buffered||queuedItems>=queueItemLimit)return false;
 if(lane&&(data.byteLength>laneQueueLimit-lane.bytes-(lane.socket?lane.socket.bufferedAmount:0)||lane.items>=laneItemLimit))return false;
 queuedBytes+=data.byteLength;queuedItems++;if(lane){lane.bytes+=data.byteLength;lane.items++}return true;
}
function release(bytes,items,lane){
 if(bytes>queuedBytes||items>queuedItems||(lane&&(bytes>lane.bytes||items>lane.items)))throw new Error('queue accounting invariant');
 queuedBytes-=bytes;queuedItems-=items;if(lane){lane.bytes-=bytes;lane.items-=items}
}
function releasePending(values,lane){
 if(!values.length)return;let bytes=0;for(const value of values)bytes+=value.byteLength;
 const items=values.length;values.length=0;release(bytes,items,lane);
}
function frameBound(value,maxFrames,maxBytes){
 const view=new DataView(value);let offset=0,frames=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8)throw new Error('invalid frame batch');
  const size=view.getUint32(offset+4),end=offset+8+size;
  if(size>1048576||end>value.byteLength)throw new Error('invalid frame');
  if(frames>0&&(frames>=maxFrames||end>maxBytes))break;
  frames++;offset=end;
 }
 if(!frames)throw new Error('empty frame batch');
 return {frames,bytes:offset};
}
function splitFrames(value){
 const view=new DataView(value),result=[];let offset=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8||result.length>=4096)throw new Error('invalid frame batch');
  const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
  const size=view.getUint32(offset+4),end=offset+8+size;
  if((type===2&&!size)||size>1048576||end>value.byteLength)throw new Error('invalid frame');
  result.push({type,id,data:offset===0&&end===value.byteLength?value:value.slice(offset,end)});offset=end;
 }
 if(!result.length)throw new Error('empty frame batch');return result;
}
function probeFrames(){
 const result=[];let scanned=0;
 for(let index=0;index<pending.length;index++){
  const source=pending[index],view=new DataView(source);let start=0;
  while(start<source.byteLength){
   if(source.byteLength-start<8||result.length>=4096)throw new Error('invalid frame batch');
   const type=view.getUint8(start),id=(view.getUint8(start+1)<<16)|(view.getUint8(start+2)<<8)|view.getUint8(start+3);
   const size=view.getUint32(start+4),end=start+8+size,bytes=end-start;
   if((type===2&&!size)||size>1048576||end>source.byteLength)throw new Error('invalid frame');
   if(scanned+bytes>batchLimit)return result;
   result.push({source,index,start,end,type,id});scanned+=bytes;start=end;
  }
 }
 return result;
}
function findProbe(includeData){
 const frames=probeFrames(),first=frames.findIndex(frame=>frame.type===1||frame.type===2);if(first<0)return null;
 const laneMode=carrier==='https-lanes'||carrier==='websocket-lanes',selected=[];let hasData=frames[first].type===2;
 if(laneMode){
  selected.push(frames[first]);
  if(includeData&&!hasData)for(let index=first+1;index<frames.length;index++)if(frames[index].id===frames[first].id){selected.push(frames[index]);if(frames[index].type===2){hasData=true;break}}
 }else{
  let last=first;
  if(includeData&&!hasData)for(let index=first+1;index<frames.length;index++){if(frames[index].id===frames[first].id&&frames[index].type===2){last=index;hasData=true;break}}
  for(let index=0;index<=(hasData?last:first);index++)selected.push(frames[index]);
 }
 const spans=[];let total=0;
 for(const frame of selected){
  const previous=spans[spans.length-1];total+=frame.end-frame.start;
  if(previous&&previous.source===frame.source&&previous.end===frame.start)previous.end=frame.end;
  else spans.push({source:frame.source,index:frame.index,start:frame.start,end:frame.end});
 }
 const joined=new Uint8Array(total);let offset=0;
 for(const span of spans){const part=new Uint8Array(span.source,span.start,span.end-span.start);joined.set(part,offset);offset+=part.byteLength}
 return {spans,id:frames[first].id,data:joined.buffer,hasData};
}
function consumeProbe(probe){
 const groups=new Map();
 for(const span of probe.spans){if(pending[span.index]!==span.source)throw new Error('stale carrier probe');const values=groups.get(span.index)||[];values.push(span);groups.set(span.index,values)}
 const indexes=Array.from(groups.keys()).sort((left,right)=>right-left);
 for(const index of indexes){
  const source=pending[index],spans=groups.get(index).sort((left,right)=>left.start-right.start);let removed=0,offset=0;
  for(const span of spans){if(span.start<offset)throw new Error('overlapping carrier probe');removed+=span.end-span.start;offset=span.end}
  if(removed===source.byteLength){pending.splice(index,1);release(removed,1,null);continue}
  const merged=new Uint8Array(source.byteLength-removed);let write=0;offset=0;
  for(const span of spans){merged.set(new Uint8Array(source,offset,span.start-offset),write);write+=span.start-offset;offset=span.end}
  merged.set(new Uint8Array(source,offset),write);pending[index]=merged.buffer;release(removed,0,null);
 }
}
function joinPending(values,lane){
 let total=0,count=0,frames=0;
 while(count<values.length){
  const bound=frameBound(values[count],4096,batchLimit),whole=bound.bytes===values[count].byteLength;
  if(count===0&&!whole){
   const head=new Uint8Array(values[0],0,bound.bytes).slice();
   values[0]=values[0].slice(bound.bytes);queuedItems++;if(lane)lane.items++;
   return {body:head.buffer,total:bound.bytes,count:1};
  }
  if(count&&(total+values[count].byteLength>batchLimit||frames+bound.frames>4096))break;
  total+=values[count].byteLength;frames+=bound.frames;count++;
 }
 const joined=new Uint8Array(total);let offset=0;
 for(const data of values.splice(0,count)){joined.set(new Uint8Array(data),offset);offset+=data.byteLength}
 return {body:joined.buffer,total,count};
}
function takeBatch(values,lane){
 const batch=joinPending(values,lane);
 return Object.assign(batch,{lane,controller:null,cancelled:false,settled:false});
}
function settleBatch(lease){
 if(!lease||lease.settled)return false;lease.settled=true;
 if(lease.lane){if(lease.lane.upLease===lease)lease.lane.upLease=null}else if(upLease===lease)upLease=null;
 release(lease.total,lease.count,lease.lane);return true;
}
function cancelBatch(lease){
 if(!lease||lease.settled)return;lease.cancelled=true;if(lease.controller)lease.controller.abort();settleBatch(lease);
}
function retryAfterMs(response){
 const header=response.headers.get('Retry-After');
 if(!header)return 0;
 const seconds=Number(header);
 if(Number.isFinite(seconds)&&seconds>=0)return Math.min(seconds*1000,30000);
 const when=Date.parse(header);
 if(Number.isFinite(when)){const delta=when-Date.now();return delta>0?Math.min(delta,30000):0}
 return 0;
}
function retryableStatus(status){return status===408||status===429||status===502||status===503||status===504}
async function request(path,frozenOptions){
 let delay=250,attempt=0;const deadline=Date.now()+bridgeRetryMs,external=frozenOptions.signal;
 const attemptLimit=path==='/api/v1/down'?longPollMs+bridgeRequestMs:bridgeRequestMs;
 while(attempt<9){
  if(closed||(external&&external.aborted))throw new Error('request aborted');
  const remaining=deadline-Date.now();if(remaining<=0)break;attempt++;
  const controller=new AbortController(),abort=()=>controller.abort();
  if(external)external.addEventListener('abort',abort,{once:true});
  const requestOptions=Object.assign({},frozenOptions,{signal:controller.signal});
  const timer=setTimeout(abort,Math.max(1,Math.min(attemptLimit,remaining)));
  let response=null,wait=0;
  try{
   const fetched=await fetch(relayOrigin+path,requestOptions),body=await fetched.arrayBuffer();
   response={status:fetched.status,headers:fetched.headers,body};
   if(!retryableStatus(response.status))return response;
   wait=retryAfterMs(response);
  }catch(error){
   if(closed||(external&&external.aborted))throw error;
  }finally{clearTimeout(timer);if(external)external.removeEventListener('abort',abort)}
  const after=deadline-Date.now();if(attempt>=9||after<=0)break;
  status('reconnecting');
  const backoff=wait||delay+Math.floor(Math.random()*Math.max(1,delay/4));
  await pause(Math.min(backoff,after),external);delay=Math.min(delay*2,5000);
 }
 throw new Error('carrier retry limit reached');
}
function fail(){if(closed)return;status('failed');if(port)port.postMessage({t:'close'});close(true)}
function knownCarrier(value){return value==='https'||value==='https-lanes'||value==='websocket'||value==='websocket-lanes'}
function sessionEcho(response,expectedAttempt,states,exactAttempt){
 const selected=response.headers.get('X-Carrier-Mode')||'',echo=response.headers.get('X-Carrier-Attempt')||'';
 if(!knownCarrier(selected))throw new Error('invalid carrier mode');
 if(!negotiationEnabled){if(echo!=='')throw new Error('unexpected carrier attempt');return {selected,state:''}}
 const count=response.headers.get('X-Carrier-Candidate-Count')||'',deadline=response.headers.get('X-Carrier-Deadline')||'',state=response.headers.get('X-Carrier-State')||'';
 if(!/^[1-4]$/.test(count)||!/^[1-9]\d*$/.test(deadline)||!states.includes(state))throw new Error('invalid carrier state');
 const echoedAttempt=Number(echo),parsedCount=Number(count),parsedDeadline=Number(deadline);
 if(!Number.isInteger(echoedAttempt)||echoedAttempt<1||(exactAttempt?echoedAttempt!==expectedAttempt:echoedAttempt>expectedAttempt))throw new Error('invalid carrier attempt');
 if(parsedCount>candidateCount||parsedDeadline>candidateDeadlines[3])throw new Error('invalid carrier bounds');
 if(!negotiatedFrozen){negotiatedCandidateCount=parsedCount;negotiatedFinalDeadline=parsedDeadline;negotiatedFrozen=true}
 else if(parsedCount!==negotiatedCandidateCount||parsedDeadline!==negotiatedFinalDeadline)throw new Error('changed carrier bounds');
 if(echoedAttempt>negotiatedCandidateCount)throw new Error('carrier attempt exceeds candidates');
 return {selected,state};
}
function armCarrierDeadline(epoch){
 if(!negotiationStartedAt||epoch!==attemptEpoch)return;
 if(carrierTimer)clearTimeout(carrierTimer);
 const deadline=carrierAttempt>=negotiatedCandidateCount?negotiatedFinalDeadline:candidateDeadlines[carrierAttempt-1];
 const remaining=negotiationStartedAt+deadline*1000-Date.now();
 carrierTimer=setTimeout(()=>advanceCarrier('timeout',epoch),Math.max(0,remaining));
}
function clearProbeTimer(){if(probeTimer){clearTimeout(probeTimer.timer);probeTimer=null}}
function resetCandidate(){
 clearProbeTimer();
 if(pollController)pollController.abort();pollController=null;
 if(socket){const previous=socket;socket=null;previous.close()}socketReady=false;
 cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket)lane.socket.close();
 }
 lanes.clear();closedLanes.clear();closedLaneOrder.length=0;upSequence=1;downCursor='0';upRunning=false;
 sessionToken='';carrier='';candidateRunning=false;currentAttempt=null;
}
function advanceConfirmed(reason,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch)return;
 resetCandidate();
 if(carrierAttempt>=negotiatedCandidateCount||Date.now()>=negotiationStartedAt+negotiatedFinalDeadline*1000){switching=false;fail();return}
 carrierAttempt++;carrierFailure=reason;attemptEpoch++;const nextEpoch=attemptEpoch;switching=false;
 status('reconnecting');armCarrierDeadline(nextEpoch);createSession(nextEpoch);
}
function advanceCarrier(reason,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch||switching)return;
 if(!negotiationEnabled){fail();return}
 switching=true;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;clearProbeTimer();
 const snapshot=currentAttempt;if(attemptController)attemptController.abort();attemptController=null;
 if(!snapshot||snapshot.epoch!==epoch){switching=false;fail();return}
 if(snapshot.selected){advanceConfirmed(reason,epoch);return}
 resolveAttempt(reason,epoch,snapshot);
}
async function resolveAttempt(reason,epoch,snapshot){
 const controller=new AbortController();attemptController=controller;
 const remaining=negotiationStartedAt+negotiatedFinalDeadline*1000-Date.now();
 if(remaining<=0){switching=false;fail();return}
 const timer=setTimeout(()=>controller.abort(),remaining);
 try{
  const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(snapshot.attempt,snapshot.failure),controller.signal);
  const response=await request('/api/v1/session',frozen);
  if(closed||epoch!==attemptEpoch)return
  if(response.status===409){sessionEcho(response,snapshot.attempt,['committed','healthy'],false);switching=false;fail();return}
  if(response.status!==200){switching=false;fail();return}
  const echo=sessionEcho(response,snapshot.attempt,['provisional','committed','healthy'],true);
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'||(snapshot.selected&&echo.selected!==snapshot.selected))throw new Error('changed carrier replay');
  const welcome=response.body;if(closed||epoch!==attemptEpoch)return;
  cleanupToken=token;
  if(!welcomeSent){welcomeSent=true;port.postMessage(welcome,[welcome])}
  if(echo.state!=='provisional'){switching=false;fail();return}
  advanceConfirmed(reason,epoch);
 }catch(error){if(!closed&&epoch===attemptEpoch){switching=false;fail()}}
 finally{clearTimeout(timer);if(attemptController===controller)attemptController=null}
}
function startCandidate(probe,epoch){
 if(!probe||closed||carrierCommitted||!sessionToken||candidateRunning||epoch!==attemptEpoch)return;
 clearProbeTimer();candidateRunning=true;
 if(carrier==='https')probeHttp(probe,null,epoch);
 else if(carrier==='https-lanes')probeHttp(probe,probe.id,epoch);
 else if(carrier==='websocket')openCandidateSocket(probe,null,epoch);
 else if(carrier==='websocket-lanes')openCandidateSocket(probe,probe.id,epoch);
 else advanceCarrier('protocol',epoch);
}
function maybeStartCandidate(){
 if(closed||carrierCommitted||!sessionToken||candidateRunning)return;const epoch=attemptEpoch;
 let probe;try{probe=findProbe(probeCoalesceMs>0)}catch(error){fail();return}if(!probe)return;
 if(!probeCoalesceMs||probe.hasData){startCandidate(probe,epoch);return}
 if(probeTimer)return;const owner={epoch,timer:null};
 owner.timer=setTimeout(()=>{if(probeTimer!==owner||closed||owner.epoch!==attemptEpoch)return;probeTimer=null;let current;try{current=findProbe(false)}catch(error){fail();return}startCandidate(current,owner.epoch)},probeCoalesceMs);
 probeTimer=owner;
}
async function createSession(epoch){
 const controller=new AbortController(),attempt=carrierAttempt,failure=carrierFailure;
 const snapshot={epoch,attempt,failure,hello:helloFrame,selected:''};currentAttempt=snapshot;attemptController=controller;
 try{
  status('connecting');
  const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(attempt,failure),controller.signal);
  const response=await request('/api/v1/session',frozen);
  if(closed||epoch!==attemptEpoch)return
  if(response.status===409){sessionEcho(response,attempt,['committed','healthy'],false);fail();return}
  if(response.status!==200){advanceCarrier('http',epoch);return}
  const echo=sessionEcho(response,attempt,['provisional'],true),selected=echo.selected;snapshot.selected=selected;
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'){advanceCarrier('protocol',epoch);return}
  const welcome=response.body;if(closed||epoch!==attemptEpoch)return;
  carrier=selected;sessionToken=token;cleanupToken=token;downCursor=cursor;
  if(!welcomeSent){welcomeSent=true;port.postMessage(welcome,[welcome])}
  if(carrier==='websocket')openCandidateSocket(null,null,epoch);
  maybeStartCandidate();
 }catch(error){if(closed||epoch!==attemptEpoch)return;advanceCarrier('network',epoch)}
}
async function probeHttp(probe,laneID,epoch){
 try{
  const headers={'X-Up-Seq':'1'},token=sessionToken,controller=attemptController,body=probe.data;if(laneID!==null)headers['X-Lane-ID']=String(laneID);
  const response=await request('/api/v1/up',options('POST',token,body,headers,controller.signal));
  if(closed||epoch!==attemptEpoch)return
  if(response.status!==204){advanceCarrier('http',epoch);return}
  if(response.headers.get('X-Up-Ack')!=='1'){advanceCarrier('protocol',epoch);return}
  if(laneID===null)upSequence=2;else ensureLane(laneID).sequence=2;
  commitCarrier(probe,epoch);
 }catch(error){if(!closed&&epoch===attemptEpoch)advanceCarrier('network',epoch)}
}
function commitCarrier(probe,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch)return;
 if(switching){fail();return}
 clearProbeTimer();try{consumeProbe(probe)}catch(error){fail();return}
 carrierCommitted=true;candidateRunning=false;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;
 attemptController=null;currentAttempt=null;
 status('connected');
 if(carrier==='https')poll();
 else if(carrier==='https-lanes'){const lane=lanes.get(probe.id);if(lane&&!lane.polling)pollLane(lane)}
 for(const data of pending.splice(0)){release(data.byteLength,1,null);queueCarrier(data)}
}
function queueCarrier(data){
 try{
  if(carrier==='https')queueUp(data);
  else if(carrier==='websocket')queueSocket(data);
  else for(const value of splitFrames(data))queueLane(value);
 }catch(error){fail()}
}
function queueUp(data){if(!reserve(data,null)){fail();return}upPending.push(data);runUp()}
async function runUp(){
 if(upRunning)return;upRunning=true;let lease=null;
 try{
  while(!closed&&sessionToken&&upPending.length){
   lease=takeBatch(upPending,null);upLease=lease;lease.controller=new AbortController();const sequence=String(upSequence);
   const response=await request('/api/v1/up',options('POST',sessionToken,lease.body,{'X-Up-Seq':sequence},lease.controller.signal));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('uplink rejected');
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});upSequence++;lease=null;
  }
 }catch(error){if(!closed&&!(lease&&lease.cancelled))fail()}
 finally{upRunning=false;if(!closed&&sessionToken&&upPending.length)runUp()}
}
function sendCandidateSocket(next){
 const state=next.telemt;if(!state||state.sent||next.readyState!==WebSocket.OPEN||!state.probe)return;
 let probe=state.probe;
 try{const fresh=findProbe(true);if(fresh&&fresh.id===probe.id)probe=fresh;next.send(probe.data)}catch(error){advanceCarrier('upgrade',state.epoch);return}
 state.probe=probe;state.sent=true;if(!negotiationEnabled)commitCarrier(probe,state.epoch);
}
function openCandidateSocket(probe,laneID,epoch){
 let lane=laneID===null?null:ensureLane(laneID),next=lane?lane.socket:socket;
 if(next){if(!next.telemt||next.telemt.epoch!==epoch){advanceCarrier('protocol',epoch);return}if(probe)next.telemt.probe=probe;sendCandidateSocket(next);return}
 const token=sessionToken,protocol=laneID===null?(negotiationEnabled?'tproxy-auto-v1.':'tproxy-v1.')+token:(negotiationEnabled?'tproxy-auto-lane-v1.':'tproxy-lane-v1.')+token+'.'+String(laneID);
 next=new WebSocket(socketURL(),protocol);next.binaryType='arraybuffer';next.telemt={epoch,lane,probe,opened:false,sent:false};
 if(lane)lane.socket=next;else socket=next;
 next.onopen=()=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch){next.close();return}state.opened=true;
  if(state.lane){state.lane.ready=true}else socketReady=true;sendCandidateSocket(next);
 };
 next.onmessage=event=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch||!(event.data instanceof ArrayBuffer))return;
  if(!carrierCommitted){if(!state.sent||event.data.byteLength!==0){advanceCarrier('protocol',state.epoch);return}commitCarrier(state.probe,state.epoch);return}
  try{
   if(state.lane){const values=splitFrames(event.data);for(const value of values)if(value.id!==state.lane.id)throw new Error('cross-lane frame');if(values.some(value=>value.type===3))state.lane.remoteClosed=true}
   else{const bound=frameBound(event.data,4096,batchLimit);if(bound.bytes!==event.data.byteLength)throw new Error('invalid frame batch')}
  }catch(error){if(state.lane)finishLane(state.lane,true);else fail();return}
  port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 next.onerror=()=>{};
 next.onclose=()=>{
  const state=next.telemt;if(state.epoch!==attemptEpoch||closed)return;
  if(!carrierCommitted){advanceCarrier(state.opened?'network':'upgrade',state.epoch);return}
  if(state.lane){state.lane.ready=false;state.lane.socket=null;finishLane(state.lane,true)}else{socketReady=false;fail()}
 };
}
function queueSocket(data){if(!reserve(data,null)){fail();return}upPending.push(data);runSocketUp()}
async function waitSocket(next,size,limit,signal){
 while(!closed&&next.readyState===WebSocket.OPEN&&next.bufferedAmount>limit-size)await pause(10,signal);
 if(closed||(signal&&signal.aborted)||next.readyState!==WebSocket.OPEN)throw new Error('websocket closed');
}
async function runSocketUp(){
 if(upRunning||!socketReady)return;upRunning=true;let lease=null;
 try{
  while(!closed&&socketReady&&upPending.length){
   lease=takeBatch(upPending,null);upLease=lease;lease.controller=new AbortController();
   await waitSocket(socket,lease.total,queueLimit,lease.controller.signal);socket.send(lease.body);
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lease=null;
  }
 }catch(error){if(!closed&&!(lease&&lease.cancelled))fail()}
 finally{upRunning=false;if(!closed&&socketReady&&upPending.length)runSocketUp()}
}
async function poll(){
 while(!closed&&sessionToken){
  try{
   pollController=new AbortController();
   const response=await request('/api/v1/down',options('POST',sessionToken,null,{'X-Down-Cursor':downCursor},pollController.signal));
   if(response.status===204){status('connected');continue}
   if(response.status!==200)throw new Error('downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=response.body;
   if(!next||!data.byteLength)throw new Error('invalid downlink response');
   if(closed)return;
   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);downCursor=next;status('connected');
  }catch(error){if(!closed)fail();return}
 }
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id,sequence:1,cursor:'0',pending:[],bytes:0,items:0,running:false,upLease:null,polling:false,controller:null,socket:null,ready:false,remoteClosed:false};lanes.set(id,lane)}
 return lane;
}
function rememberLaneClosed(id){
 if(!id||closedLanes.has(id))return;
 if(closedLaneOrder.length===closedLaneLimit)closedLanes.delete(closedLaneOrder.shift());
 closedLanes.add(id);closedLaneOrder.push(id);
}
function closeFrame(id){const value=new Uint8Array(8);value[0]=3;value[1]=(id>>>16)&255;value[2]=(id>>>8)&255;value[3]=id&255;return value.buffer}
function finishLane(lane,notifyClient){
 if(lanes.get(lane.id)!==lane)return;
 if(lane.controller)lane.controller.abort();lane.controller=null;cancelBatch(lane.upLease);
 if(lane.socket&&lane.socket.readyState<WebSocket.CLOSING)lane.socket.close();
 releasePending(lane.pending,lane);lanes.delete(lane.id);rememberLaneClosed(lane.id);
 if(notifyClient&&!lane.remoteClosed&&port){const frame=closeFrame(lane.id);port.postMessage(frame,[frame])}
}
function queueLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!lane&&closedLanes.has(value.id))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(!reserve(value.data,lane)){fail();return}
 lane.pending.push(value.data);
 if(carrier==='websocket-lanes'){openLaneSocket(lane);runLaneSocketUp(lane)}else runLaneUp(lane);
}
function openLaneSocket(lane){
 if(lane.socket||closed)return;lane.socket=new WebSocket(socketURL(),'tproxy-lane-v1.'+sessionToken+'.'+String(lane.id));lane.socket.binaryType='arraybuffer';
 lane.socket.onopen=()=>{if(closed||lanes.get(lane.id)!==lane)return;lane.ready=true;status('connected');runLaneSocketUp(lane)};
 lane.socket.onmessage=event=>{
  if(closed||lanes.get(lane.id)!==lane||!(event.data instanceof ArrayBuffer)){finishLane(lane,true);return}
  let values;try{values=splitFrames(event.data);for(const value of values)if(value.id!==lane.id)throw new Error('cross-lane frame')}catch(error){finishLane(lane,true);return}
  if(values.some(value=>value.type===3))lane.remoteClosed=true;
  port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 lane.socket.onerror=()=>{};lane.socket.onclose=()=>{lane.ready=false;lane.socket=null;if(!closed)finishLane(lane,true)};
}
async function runLaneSocketUp(lane){
 if(lane.running||!lane.ready)return;lane.running=true;let lease=null;
 try{
  while(!closed&&lane.ready&&lanes.get(lane.id)===lane&&lane.pending.length){
   lease=takeBatch(lane.pending,lane);lane.upLease=lease;lease.controller=new AbortController();
   await waitSocket(lane.socket,lease.total,laneQueueLimit,lease.controller.signal);lane.socket.send(lease.body);
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lease=null;
  }
 }catch(error){if(!closed&&lanes.get(lane.id)===lane&&!(lease&&lease.cancelled))finishLane(lane,true)}
 finally{lane.running=false;if(!closed&&lanes.get(lane.id)===lane&&lane.ready&&lane.pending.length)runLaneSocketUp(lane)}
}
async function runLaneUp(lane){
 if(lane.running)return;lane.running=true;let lease=null;
 try{
  while(!closed&&sessionToken&&lane.pending.length){
   lease=takeBatch(lane.pending,lane);lane.upLease=lease;lease.controller=new AbortController();
   const sequence=String(lane.sequence),laneID=String(lane.id);
   const response=await request('/api/v1/up',options('POST',sessionToken,lease.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID},lease.controller.signal));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('lane uplink rejected');
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lane.sequence++;lease=null;
   if(!lane.polling)pollLane(lane);
  }
 }catch(error){if(!closed&&lanes.get(lane.id)===lane&&!(lease&&lease.cancelled))fail()}
 finally{lane.running=false;if(!closed&&lanes.get(lane.id)===lane&&sessionToken&&lane.pending.length)runLaneUp(lane)}
}
async function pollLane(lane){
 if(!lane||lane.polling)return;lane.polling=true;
 try{
  while(!closed&&sessionToken&&lanes.get(lane.id)===lane){
   const controller=new AbortController(),laneID=String(lane.id);lane.controller=controller;
   const response=await request('/api/v1/down',options('POST',sessionToken,null,{'X-Down-Cursor':lane.cursor,'X-Lane-ID':laneID},controller.signal));
   if(response.status===204){
    if(response.headers.get('X-Lane-Closed')==='1'){finishLane(lane,false);return}
    status('connected');continue;
   }
   if(response.status!==200)throw new Error('lane downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=response.body;
   if(!next||!data.byteLength)throw new Error('invalid lane downlink response');
   for(const value of splitFrames(data))if(value.id!==lane.id)throw new Error('cross-lane frame');
   if(closed)return;
   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);lane.cursor=next;status('connected');
  }
 }catch(error){if(!closed)fail()}
 finally{lane.polling=false;lane.controller=null}
}
function deleteSession(){
 const token=cleanupToken||sessionToken;if(token)fetch(relayOrigin+'/api/v1/session',options('DELETE',token,null,null,undefined,true)).catch(()=>{});
}
function close(notifyServer){
 if(closed)return;closed=true;if(carrierTimer)clearTimeout(carrierTimer);clearProbeTimer();if(attemptController)attemptController.abort();if(pollController)pollController.abort();
 if(socket)socket.close();cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket)lane.socket.close();
 }
 if(notifyServer)deleteSession();releasePending(pending,null);lanes.clear();if(port)port.close();
 if(queuedBytes!==0||queuedItems!==0)throw new Error('queue accounting leak');
}
function activatePort(nextPort){
 initialized=true;port=nextPort;
 port.onmessage=message=>{
  if(message.data instanceof ArrayBuffer){
   if(!createStarted){createStarted=true;helloFrame=message.data;if(negotiationEnabled){negotiationStartedAt=Date.now();armCarrierDeadline(attemptEpoch)}createSession(attemptEpoch)}
   else if(!carrierCommitted){if(!reserve(message.data,null)){fail();return}pending.push(message.data);maybeStartCandidate()}
   else queueCarrier(message.data);
  }else if(message.data&&message.data.t==='close')close(true);
 };
 port.start();status('connecting');
}
addEventListener('message',event=>{
 if(initialized||event.source!==parent||event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
},{once:false});
const androidBridge=globalThis.TelegramWebProxy;
if(!initialized&&androidNonce&&androidBridge&&typeof androidBridge.postMessage==='function'){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){
   let frames;try{frames=splitFrames(value)}catch(error){fail();return}
   for(const frame of frames)androidBridge.postMessage(frame.data);
  }else androidBridge.postMessage(JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}if(androidPort.onmessage)androidPort.onmessage({data})};
 activatePort(androidPort);androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
addEventListener('pagehide',()=>close(true),{once:true});
})();
