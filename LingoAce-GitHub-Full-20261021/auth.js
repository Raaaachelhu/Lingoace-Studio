/* Static-site entrance lock. Policy checks cannot replace server authorization. */
(()=>{
 'use strict';
 const src=new URL(document.currentScript.src),base=new URL('.',src);
 base.pathname=base.pathname.replace(/(?:LingoAce-Full-20261019|LingoAce-GitHub-Full-20261021|LingoAce-Website-00)\/$/,'');
 const scope=base.pathname,policyURL=new URL('auth-policy.json',base);
 const key='lingoace-live-session-v3:'+scope,signal='lingoace-live-revoke:'+scope;
 const ttl=12*60*60*1000,interval=10000;
 let unlocked=false,policy=null,lastChecked=0,pending=null,expires=0,started=false;
 document.documentElement.classList.add('auth-locked');
 function readSession(){try{return JSON.parse(sessionStorage.getItem(key)||'null')}catch{return null}}
 function matches(s,p){return s?.revision===p.revision&&s?.passwordSha256===p.passwordSha256&&Number.isFinite(s.expires)&&s.expires>Date.now()}
 function unlock(session){
  unlocked=true;expires=session.expires;window.__LINGOACE_ENTRY__={scope,revision:policy.revision,expires};
  document.documentElement.classList.remove('auth-locked');document.getElementById('access-gate')?.remove();
  // Older standalone pages originally concealed this wrapper with an inline lock.
  const content=document.getElementById('gatedContent');if(content)content.style.display='';
 }
 function lock(message='密码已更新，请重新输入访问密码。',clear=true){
  unlocked=false;expires=0;window.__LINGOACE_ENTRY__=null;
  if(clear)try{sessionStorage.removeItem(key)}catch{}
  document.documentElement.classList.add('auth-locked');
  if(document.body){show();const error=document.getElementById('access-error');if(error)error.textContent=message}
 }
 function announce(p){try{localStorage.setItem(signal,JSON.stringify({revision:p.revision,passwordSha256:p.passwordSha256}))}catch{}}
 async function checkPolicy(){
  if(pending)return pending;
  pending=(async()=>{
   const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);
   try{
    const url=new URL(policyURL);url.searchParams.set('_',String(Date.now()));
    const response=await fetch(url.href,{cache:'no-store',credentials:'same-origin',signal:controller.signal});
    if(!response.ok)throw Error('policy unavailable');
    const next=await response.json();
    if(typeof next.revision!=='string'||!next.revision||!(/^[a-f0-9]{64}$/.test(next.passwordSha256)))throw Error('invalid policy');
    const changed=policy&&(policy.revision!==next.revision||policy.passwordSha256!==next.passwordSha256);
    policy=next;lastChecked=Date.now();
    if(changed){lock();announce(next)}
    const saved=readSession();
    if(!changed&&matches(saved,next)){unlock(saved)}
    else if(unlocked){lock('登录已过期，请重新输入访问密码。')}
    return next;
   }catch(error){lock('暂时无法验证访问权限，请联网后重新输入密码。');return null}
   finally{clearTimeout(timer);pending=null}
  })();
  return pending;
 }
 async function login(event){
  event.preventDefault();const input=document.getElementById('access-password'),value=input.value;
  const button=document.querySelector('.access-submit');if(button)button.disabled=true;
  try{
   const current=await checkPolicy();if(!current)return;
   if(sha256(value)!==current.passwordSha256){document.getElementById('access-error').textContent='密码不正确，请重新输入。';input.value='';input.focus();return}
   const session={revision:current.revision,passwordSha256:current.passwordSha256,expires:Date.now()+ttl};
   try{sessionStorage.setItem(key,JSON.stringify(session))}catch{}
   unlock(session);
  }finally{if(button)button.disabled=false}
 }
 function sha256(text){
  const bytes=new TextEncoder().encode(text),len=bytes.length,padded=((len+9+63)>>6)<<6;
  const data=new Uint8Array(padded);data.set(bytes);data[len]=128;
  const view=new DataView(data.buffer);view.setUint32(padded-4,len*8,false);view.setUint32(padded-8,Math.floor(len/0x20000000),false);
  const k=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],w=new Uint32Array(64),rotr=(x,n)=>(x>>>n)|(x<<(32-n));
  for(let offset=0;offset<padded;offset+=64){
   for(let t=0;t<16;t++)w[t]=view.getUint32(offset+t*4,false);
   for(let t=16;t<64;t++){const x=w[t-15],y=w[t-2];w[t]=(w[t-16]+(rotr(x,7)^rotr(x,18)^(x>>>3))+w[t-7]+(rotr(y,17)^rotr(y,19)^(y>>>10)))>>>0}
   let [a,b,c,d,e,f,g,j]=h;
   for(let t=0;t<64;t++){const t1=(j+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+k[t]+w[t])>>>0,t2=((rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;j=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0}
   [a,b,c,d,e,f,g,j].forEach((v,i)=>h[i]=(h[i]+v)>>>0);
  }
  return h.map(x=>x.toString(16).padStart(8,'0')).join('');
 }
 function show(){
  if(unlocked||document.getElementById('access-gate'))return;
  const gate=document.createElement('div');gate.id='access-gate';gate.setAttribute('role','dialog');gate.setAttribute('aria-modal','true');gate.setAttribute('aria-labelledby','access-title');
  gate.innerHTML='<form class="access-panel" id="access-form"><div class="access-brand"><span class="access-logo">a</span>lingoace</div><div class="access-eyebrow">TEACHING & LEARNING STUDIO</div><h1 id="access-title">欢迎回到教学工作台。</h1><p class="access-description">每一份专业，都从用心准备开始。<br>请输入访问密码，开启今天的教学工作。</p><label class="access-label" for="access-password">访问密码</label><div class="access-input-wrap"><input id="access-password" type="password" autocomplete="current-password" placeholder="请输入访问密码" required><button class="access-reveal" id="access-reveal" type="button" aria-label="显示密码" aria-pressed="false">◉</button></div><button class="access-submit" type="submit">进入工作台 ↗</button><p class="access-error" id="access-error" role="alert" aria-live="polite"></p><div class="access-footer"><span>CONTENT & CARE</span><span>developer: Rachel Hu</span></div></form>';
  document.body.appendChild(gate);const input=document.getElementById('access-password');
  document.getElementById('access-form').addEventListener('submit',login);
  document.getElementById('access-reveal').addEventListener('click',event=>{const visible=input.type==='password';input.type=visible?'text':'password';event.currentTarget.setAttribute('aria-pressed',String(visible));event.currentTarget.setAttribute('aria-label',visible?'隐藏密码':'显示密码');input.focus()});
  gate.addEventListener('keydown',event=>{if(event.key!=='Tab')return;const controls=[...gate.querySelectorAll('input,button')],first=controls[0],last=controls[controls.length-1];if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus()}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus()}});
  input.focus();
 }

 function ready(){
  if(started)return;started=true;if(!unlocked)show();checkPolicy();
  const header=document.querySelector('.header-actions');
  if(header){const btn=document.createElement('button');btn.type='button';btn.className='session-lock';btn.title='锁定工作台';btn.setAttribute('aria-label','锁定工作台');btn.textContent='⌑';btn.addEventListener('click',()=>lock('请输入访问密码。'));header.prepend(btn)}
  setInterval(()=>{if(unlocked&&expires<=Date.now())lock('登录已过期，请重新输入访问密码。');checkPolicy()},interval);
 }
 function resume(){if(document.visibilityState==='hidden')return;if(unlocked&&Date.now()-lastChecked>=interval)lock('正在验证访问权限…',false);checkPolicy()}
 window.addEventListener('focus',resume);window.addEventListener('pageshow',resume);
 document.addEventListener('visibilitychange',resume);
 window.addEventListener('storage',event=>{
  if(event.key!==signal||!event.newValue||!policy)return;
  try{const next=JSON.parse(event.newValue);if(next.revision!==policy.revision||next.passwordSha256!==policy.passwordSha256){lock();checkPolicy()}}catch{}
 });
 // Stop interaction while locked, including a resumed tab awaiting a fresh check.
 for(const type of ['pointerdown','click','keydown','submit'])document.addEventListener(type,event=>{
  if(unlocked&&(expires<=Date.now()||Date.now()-lastChecked>=interval)){lock('正在验证访问权限…',expires<=Date.now());checkPolicy()}
  if(!unlocked&&!event.target.closest?.('#access-gate')){event.preventDefault();event.stopImmediatePropagation()}
 },true);
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',ready,{once:true});else ready();
})();
