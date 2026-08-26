use base64::Engine as _;

use crate::crypto::SecureRandom;

/// Browser security policy for the transient Telegram Desktop bridge page.
pub(crate) const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()";

/// Fully rendered bridge response and its per-response script policy.
pub(crate) struct BridgePage {
    /// Complete transient HTML document.
    pub(crate) body: String,
    /// Nonce-bound policy that authorizes only the embedded bridge script.
    pub(crate) content_security_policy: String,
}

/// Renders the bounded WEB carrier-negotiation bridge with a fresh CSP nonce.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render(
    host: &str,
    bootstrap: &str,
    batch_limit: usize,
    queue_limit: usize,
    queue_items: usize,
    negotiation_enabled: bool,
    candidate_count: usize,
    carrier_deadlines: [u64; 4],
    rng: &SecureRandom,
) -> BridgePage {
    let mut nonce = [0u8; 18];
    rng.fill(&mut nonce);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let body = DOCUMENT
        .replace("__NONCE__", &nonce)
        .replace("__HOST__", host)
        .replace("__BOOTSTRAP__", bootstrap)
        .replace("__BATCH_LIMIT__", &batch_limit.to_string())
        .replace("__QUEUE_LIMIT__", &queue_limit.to_string())
        .replace("__QUEUE_ITEMS__", &queue_items.to_string())
        .replace(
            "__NEGOTIATION_ENABLED__",
            if negotiation_enabled { "true" } else { "false" },
        )
        .replace("__CANDIDATE_COUNT__", &candidate_count.to_string())
        .replace(
            "__CARRIER_DEADLINES__",
            &carrier_deadlines
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    BridgePage {
        body,
        content_security_policy: format!(
            "default-src 'none'; base-uri 'none'; child-src 'none'; connect-src 'self' wss://{host}; font-src 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; frame-src 'none'; img-src 'none'; manifest-src 'none'; media-src 'none'; object-src 'none'; script-src 'nonce-{nonce}'; style-src 'none'; worker-src 'none'; sandbox allow-same-origin allow-scripts"
        ),
    }
}

const DOCUMENT: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
(()=>{
'use strict';
const bootstrap="__BOOTSTRAP__";
const relayOrigin='https://__HOST__',carrierCapabilities='https,https-lanes,websocket,websocket-lanes';
const negotiationEnabled=__NEGOTIATION_ENABLED__,candidateCount=__CANDIDATE_COUNT__,candidateDeadlines=[__CARRIER_DEADLINES__];
let negotiatedCandidateCount=candidateCount,negotiatedFinalDeadline=candidateDeadlines[3],negotiatedFrozen=false;
const batchLimit=__BATCH_LIMIT__,queueLimit=__QUEUE_LIMIT__,queueItemLimit=__QUEUE_ITEMS__;
const laneQueueLimit=Math.min(queueLimit,8388608),laneItemLimit=Math.min(queueItemLimit,1024),closedLaneLimit=4096;
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'';
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',cleanupToken='',createStarted=false,socket=null,socketReady=false,carrier='';
let queuedBytes=0,queuedItems=0,upSequence=1,downCursor='0',upRunning=false,pollController=null;
let helloFrame=null,welcomeSent=false,carrierAttempt=1,carrierFailure='',carrierCommitted=false;
let negotiationStartedAt=0,carrierTimer=null,attemptController=null,attemptEpoch=1,candidateRunning=false,switching=false,currentAttempt=null;
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
function release(bytes,items,lane){queuedBytes-=bytes;queuedItems-=items;if(lane){lane.bytes-=bytes;lane.items-=items}}
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
function findProbe(){
 for(let index=0;index<pending.length;index++){
  const value=pending[index],view=new DataView(value);let offset=0,frames=0;
  while(offset<value.byteLength){
   if(value.byteLength-offset<8||frames++>=4096)throw new Error('invalid frame batch');
   const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
   const size=view.getUint32(offset+4),end=offset+8+size;
   if((type===2&&!size)||size>1048576||end>value.byteLength)throw new Error('invalid frame');
   if(type===1||type===2)return {source:value,index,start:offset,end,id,data:value.slice(offset,end)};
   offset=end;
  }
 }
 return null;
}
function consumeProbe(probe){
 if(pending[probe.index]!==probe.source)throw new Error('stale carrier probe');
 const before=probe.source.slice(0,probe.start),after=probe.source.slice(probe.end),remaining=before.byteLength+after.byteLength;
 if(!remaining){pending.splice(probe.index,1);release(probe.end-probe.start,1,null);return}
 const merged=new Uint8Array(remaining);merged.set(new Uint8Array(before),0);merged.set(new Uint8Array(after),before.byteLength);
 pending[probe.index]=merged.buffer;release(probe.end-probe.start,0,null);
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
function retryAfterMs(response){
 const header=response.headers.get('Retry-After');
 if(!header)return 0;
 const seconds=Number(header);
 if(Number.isFinite(seconds)&&seconds>=0)return Math.min(seconds*1000,30000);
 const when=Date.parse(header);
 if(Number.isFinite(when)){const delta=when-Date.now();return delta>0?Math.min(delta,30000):0}
 return 0;
}
async function request(path,frozenOptions){
 let delay=250,attempt=0;const deadline=Date.now()+90000;
 while(true){
  const controller=new AbortController(),external=frozenOptions.signal;
  if(closed||(external&&external.aborted))throw new Error('request aborted');
  const abort=()=>controller.abort();if(external)external.addEventListener('abort',abort,{once:true});
  const requestOptions=Object.assign({},frozenOptions,{signal:controller.signal});const timer=setTimeout(abort,90000);
  let serviceUnavailable=false,wait=0;
  try{
   const response=await fetch(relayOrigin+path,requestOptions);
   if(response.status!==503)return response;
   serviceUnavailable=true;wait=retryAfterMs(response);await response.arrayBuffer();
  }catch(error){
   if(closed||(external&&external.aborted))throw error;
   if(++attempt===9)throw new Error('carrier retry limit reached');
  }finally{clearTimeout(timer);if(external)external.removeEventListener('abort',abort)}
  if(serviceUnavailable&&Date.now()>=deadline)throw new Error('carrier retry limit reached');
  status('reconnecting');await pause(wait||(delay+Math.floor(Math.random()*Math.max(1,delay/4))),external);
  if(closed||(external&&external.aborted))throw new Error('request aborted');
  if(!serviceUnavailable)delay=Math.min(delay*2,5000);
 }
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
function resetCandidate(){
 if(pollController)pollController.abort();pollController=null;
 if(socket){const previous=socket;socket=null;previous.close()}socketReady=false;
 for(const lane of lanes.values()){if(lane.controller)lane.controller.abort();if(lane.socket)lane.socket.close()}
 lanes.clear();closedLanes.clear();closedLaneOrder.length=0;upPending.length=0;upSequence=1;downCursor='0';upRunning=false;
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
 switching=true;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;
 const snapshot=currentAttempt;if(attemptController)attemptController.abort();attemptController=null;
 if(!snapshot||snapshot.epoch!==epoch){switching=false;fail();return}
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
  if(closed||epoch!==attemptEpoch){await response.arrayBuffer();return}
  if(response.status===409){sessionEcho(response,snapshot.attempt,['committed','healthy'],false);await response.arrayBuffer();switching=false;fail();return}
  if(response.status!==200){await response.arrayBuffer();switching=false;fail();return}
  const echo=sessionEcho(response,snapshot.attempt,['provisional','committed','healthy'],true);
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'||(snapshot.selected&&echo.selected!==snapshot.selected))throw new Error('changed carrier replay');
  const welcome=await response.arrayBuffer();if(closed||epoch!==attemptEpoch)return;
  cleanupToken=token;
  if(!welcomeSent){welcomeSent=true;port.postMessage(welcome,[welcome])}
  if(echo.state!=='provisional'){switching=false;fail();return}
  advanceConfirmed(reason,epoch);
 }catch(error){if(!closed&&epoch===attemptEpoch){switching=false;fail()}}
 finally{clearTimeout(timer);if(attemptController===controller)attemptController=null}
}
function maybeStartCandidate(){
 let probe;try{probe=findProbe()}catch(error){fail();return}
 if(!probe||closed||carrierCommitted)return;
 if(!sessionToken||candidateRunning)return;
 candidateRunning=true;const epoch=attemptEpoch;
 if(carrier==='https')probeHttp(probe,null,epoch);
 else if(carrier==='https-lanes')probeHttp(probe,probe.id,epoch);
 else if(carrier==='websocket')openCandidateSocket(probe,null,epoch);
 else if(carrier==='websocket-lanes')openCandidateSocket(probe,probe.id,epoch);
 else advanceCarrier('protocol',epoch);
}
async function createSession(epoch){
 const controller=new AbortController(),attempt=carrierAttempt,failure=carrierFailure;
 const snapshot={epoch,attempt,failure,hello:helloFrame,selected:''};currentAttempt=snapshot;attemptController=controller;
 try{
  status('connecting');
  const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(attempt,failure),controller.signal);
  const response=await request('/api/v1/session',frozen);
  if(closed||epoch!==attemptEpoch){await response.arrayBuffer();return}
  if(response.status===409){sessionEcho(response,attempt,['committed','healthy'],false);await response.arrayBuffer();fail();return}
  if(response.status!==200){await response.arrayBuffer();advanceCarrier('http',epoch);return}
  const echo=sessionEcho(response,attempt,['provisional'],true),selected=echo.selected;snapshot.selected=selected;
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'){await response.arrayBuffer();advanceCarrier('protocol',epoch);return}
  const welcome=await response.arrayBuffer();if(closed||epoch!==attemptEpoch)return;
  carrier=selected;sessionToken=token;cleanupToken=token;downCursor=cursor;
  if(!welcomeSent){welcomeSent=true;port.postMessage(welcome,[welcome])}
  maybeStartCandidate();
 }catch(error){if(closed||epoch!==attemptEpoch)return;advanceCarrier('network',epoch)}
}
async function probeHttp(probe,laneID,epoch){
 try{
  const headers={'X-Up-Seq':'1'},token=sessionToken,controller=attemptController,body=probe.data;if(laneID!==null)headers['X-Lane-ID']=String(laneID);
  const response=await request('/api/v1/up',options('POST',token,body,headers,controller.signal));
  if(closed||epoch!==attemptEpoch){await response.arrayBuffer();return}
  if(response.status!==204){await response.arrayBuffer();advanceCarrier('http',epoch);return}
  if(response.headers.get('X-Up-Ack')!=='1'){advanceCarrier('protocol',epoch);return}
  if(laneID===null)upSequence=2;else ensureLane(laneID).sequence=2;
  commitCarrier(probe,epoch);
 }catch(error){if(!closed&&epoch===attemptEpoch)advanceCarrier('network',epoch)}
}
function commitCarrier(probe,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch)return;
 if(switching){fail();return}
 try{consumeProbe(probe)}catch(error){fail();return}
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
 if(upRunning)return;upRunning=true;
 try{
  while(!closed&&sessionToken&&upPending.length){
   const batch=joinPending(upPending,null),sequence=String(upSequence);
   const response=await request('/api/v1/up',options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('uplink rejected');
   release(batch.total,batch.count,null);port.postMessage({t:'traffic',up:batch.total,down:0});upSequence++;
  }
 }catch(error){fail()}
 finally{upRunning=false;if(!closed&&sessionToken&&upPending.length)runUp()}
}
function openCandidateSocket(probe,laneID,epoch){
 const token=sessionToken,protocol=laneID===null?(negotiationEnabled?'tproxy-auto-v1.':'tproxy-v1.')+token:(negotiationEnabled?'tproxy-auto-lane-v1.':'tproxy-lane-v1.')+token+'.'+String(laneID);
 const next=new WebSocket(socketURL(),protocol);next.binaryType='arraybuffer';let opened=false,lane=null;
 if(laneID===null)socket=next;else{lane=ensureLane(laneID);lane.socket=next}
 next.onopen=()=>{
  if(closed||epoch!==attemptEpoch)return;opened=true;
  if(lane){lane.ready=true}else socketReady=true;
  try{next.send(probe.data);if(!negotiationEnabled)commitCarrier(probe,epoch)}catch(error){advanceCarrier('upgrade',epoch)}
 };
 next.onmessage=event=>{
  if(closed||epoch!==attemptEpoch||!(event.data instanceof ArrayBuffer))return;
  if(!carrierCommitted){if(event.data.byteLength!==0){advanceCarrier('protocol',epoch);return}commitCarrier(probe,epoch);return}
  try{
   if(lane){const values=splitFrames(event.data);for(const value of values)if(value.id!==lane.id)throw new Error('cross-lane frame');if(values.some(value=>value.type===3))lane.remoteClosed=true}
   else{const bound=frameBound(event.data,4096,batchLimit);if(bound.bytes!==event.data.byteLength)throw new Error('invalid frame batch')}
  }catch(error){if(lane)finishLane(lane,true);else fail();return}
  port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 next.onerror=()=>{};
 next.onclose=()=>{
  if(epoch!==attemptEpoch||closed)return;
  if(!carrierCommitted){advanceCarrier(opened?'network':'upgrade',epoch);return}
  if(lane){lane.ready=false;lane.socket=null;finishLane(lane,true)}else{socketReady=false;fail()}
 };
}
function queueSocket(data){if(!reserve(data,null)){fail();return}upPending.push(data);runSocketUp()}
async function waitSocket(next,size,limit){
 while(!closed&&next.readyState===WebSocket.OPEN&&next.bufferedAmount>limit-size)await pause(10);
 if(closed||next.readyState!==WebSocket.OPEN)throw new Error('websocket closed');
}
async function runSocketUp(){
 if(upRunning||!socketReady)return;upRunning=true;
 try{
  while(!closed&&socketReady&&upPending.length){
   const batch=joinPending(upPending,null);await waitSocket(socket,batch.total,queueLimit);socket.send(batch.body);
   release(batch.total,batch.count,null);port.postMessage({t:'traffic',up:batch.total,down:0});
  }
 }catch(error){if(!closed)fail()}
 finally{upRunning=false;if(!closed&&socketReady&&upPending.length)runSocketUp()}
}
async function poll(){
 while(!closed&&sessionToken){
  try{
   pollController=new AbortController();
   const response=await request('/api/v1/down',options('POST',sessionToken,null,{'X-Down-Cursor':downCursor},pollController.signal));
   if(response.status===204){status('connected');continue}
   if(response.status!==200)throw new Error('downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();
   if(!next||!data.byteLength)throw new Error('invalid downlink response');
   if(closed)return;
   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);downCursor=next;status('connected');
  }catch(error){if(!closed)fail();return}
 }
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id,sequence:1,cursor:'0',pending:[],bytes:0,items:0,running:false,polling:false,controller:null,socket:null,ready:false,remoteClosed:false};lanes.set(id,lane)}
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
 if(lane.socket&&lane.socket.readyState<WebSocket.CLOSING)lane.socket.close();
 if(lane.bytes||lane.items)release(lane.bytes,lane.items,lane);
 lane.pending.length=0;lanes.delete(lane.id);rememberLaneClosed(lane.id);
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
 if(lane.running||!lane.ready)return;lane.running=true;
 try{
  while(!closed&&lane.ready&&lanes.get(lane.id)===lane&&lane.pending.length){
   const batch=joinPending(lane.pending,lane);await waitSocket(lane.socket,batch.total,laneQueueLimit);lane.socket.send(batch.body);
   release(batch.total,batch.count,lane);port.postMessage({t:'traffic',up:batch.total,down:0});
  }
 }catch(error){if(!closed)finishLane(lane,true)}
 finally{lane.running=false;if(!closed&&lane.ready&&lane.pending.length)runLaneSocketUp(lane)}
}
async function runLaneUp(lane){
 if(lane.running)return;lane.running=true;
 try{
  while(!closed&&sessionToken&&lane.pending.length){
   const batch=joinPending(lane.pending,lane),sequence=String(lane.sequence),laneID=String(lane.id);
   const response=await request('/api/v1/up',options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID}));
   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('lane uplink rejected');
   release(batch.total,batch.count,lane);port.postMessage({t:'traffic',up:batch.total,down:0});lane.sequence++;
   if(!lane.polling)pollLane(lane);
  }
 }catch(error){fail()}
 finally{lane.running=false;if(!closed&&sessionToken&&lane.pending.length)runLaneUp(lane)}
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
   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();
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
 if(closed)return;closed=true;if(carrierTimer)clearTimeout(carrierTimer);if(attemptController)attemptController.abort();if(pollController)pollController.abort();
 if(socket)socket.close();for(const lane of lanes.values()){if(lane.controller)lane.controller.abort();if(lane.socket)lane.socket.close()}
 if(notifyServer)deleteSession();pending.length=0;upPending.length=0;
 for(const lane of lanes.values())lane.pending.length=0;lanes.clear();queuedBytes=0;queuedItems=0;if(port)port.close();
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
</script>
</body>
</html>
"##;

// Rendered wire-contract tests remain separate from the embedded document.
#[cfg(test)]
mod tests;
