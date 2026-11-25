// Service worker: funcionamento offline + notificações cifradas.
const V='financas-v4';
const FILES=['./','index.html','manifest.webmanifest','icon-ms-180.png','icon-ms-192.png','icon-ms-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(FILES)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const u=new URL(e.request.url);
  if(u.pathname.startsWith('/api/'))return; // servidor: nunca do cache
  if(u.origin!==location.origin){
    if(!/fonts\.(googleapis|gstatic)\.com$/.test(u.hostname))return;
    e.respondWith(caches.open(V).then(c=>c.match(e.request).then(r=>r||fetch(e.request).then(n=>{c.put(e.request,n.clone());return n}))));return}
  e.respondWith(fetch(e.request).then(n=>{if(n.ok){const cp=n.clone();caches.open(V).then(c=>c.put(e.request,cp))}return n}).catch(()=>caches.match(e.request).then(r=>r||caches.match('index.html'))));
});

// ---- push: o servidor entrega um bloco cifrado; só este aparelho tem a chave ----
const unb64u=s=>{s=String(s).replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const x=atob(s),o=new Uint8Array(x.length);for(let i=0;i<x.length;i++)o[i]=x.charCodeAt(i);return o};
function getKey(){return new Promise(res=>{try{const r=indexedDB.open('financas',1);r.onupgradeneeded=()=>r.result.createObjectStore('keys');
  r.onsuccess=()=>{try{const g=r.result.transaction('keys').objectStore('keys').get('k');g.onsuccess=()=>res(g.result||null);g.onerror=()=>res(null)}catch(e){res(null)}};r.onerror=()=>res(null)}catch(e){res(null)}})}
async function decode(data){
  let title='Finanças',body='Você tem avisos de contas. Abra o app para ver.';
  try{const d=data?data.json():{};
    if(d.iv&&d.c){const k=await getKey();if(k&&k.enc){const p=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64u(d.iv),additionalData:new TextEncoder().encode('sched')},k.enc,unb64u(d.c));const m=JSON.parse(new TextDecoder().decode(p));title=m.title||title;body=m.body||body}}
    else if(d.title){title=d.title;body=d.body||''}}catch(e){}
  return{title,body}}
self.addEventListener('push',e=>{e.waitUntil(decode(e.data).then(m=>self.registration.showNotification(m.title,{body:m.body,icon:'icon-ms-192.png',badge:'icon-ms-192.png',tag:'financas',renotify:true,data:{url:'./'}})))});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(ws=>{for(const w of ws){if('focus' in w)return w.focus()}return clients.openWindow('./')}))});
