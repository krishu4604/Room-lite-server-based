'use strict';
const $ = id => document.getElementById(id);
const titles = {
  devices: ['Devices & subscriptions', 'Approve the right devices. Give each one exactly the access it needs.'],
  groups: ['Account groups', 'Private account files on your server. Simple group choices on the phone.'],
  jobs: ['Live jobs', 'See each panel’s progress and stop it whenever you need.'],
  audit: ['Activity', 'An administrative history of access and account-group changes.'],
  setup: ['App connection', 'Public configuration for your licensed Android release.']
};
const names = {room:'Room & chat',audio:'Listen & microphone',music:'Music streaming',effects:'Voice effects',multi_account:'Four accounts',auto_chat:'Auto Chat',audio_target:'Audio Route',ktv:'KTV queue'};
const presets = {basic:['room'],audio:['room','audio','music','effects'],auto:['auto_chat'],complete:Object.keys(names)};
let csrf='', authenticated=false, snapshot=null, currentDevice=null, refreshing=false;
function node(tag, text='', cls='') { const result=document.createElement(tag); result.textContent=text; if(cls) result.className=cls; return result; }
function notice(message,bad=false) { $('notice').textContent=message; $('notice').classList.remove('hidden'); $('notice').classList.toggle('bad',bad); }
function date(seconds) { return seconds ? new Date(seconds*1000).toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'}) : 'Not approved'; }
function badge(text) { return node('span',text,'badge '+text); }
function empty(text) { return node('p',text,'empty'); }
function showLogin() { authenticated=false; snapshot=null; $('app').classList.add('hidden'); $('login-screen').classList.remove('hidden'); $('device-dialog').close(); }
async function api(path,body,method) {
  const options={method:method || (body ? 'POST':'GET'),credentials:'same-origin',headers:{}};
  if(options.method!=='GET') options.headers['X-CSRF-Token']=csrf;
  if(body instanceof FormData) options.body=body;
  else if(body) { options.headers['Content-Type']='application/json'; options.body=JSON.stringify(body); }
  const response=await fetch('/admin/api/'+path,options);
  const data=await response.json();
  if(!response.ok) { if(response.status===401 && path!=='login') showLogin(); throw new Error(data.error || 'Request failed.'); }
  return data;
}
async function sessionState() {
  try {
    const data=await api('session'); csrf=data.csrf; authenticated=data.authenticated;
    if(authenticated) { $('login-screen').classList.add('hidden'); $('app').classList.remove('hidden'); await refresh(); }
    else showLogin();
  } catch(error) { showLogin(); $('login-error').textContent=error.message; }
}
async function refresh(silent=false) {
  if(refreshing || !authenticated) return;
  refreshing=true; $('refresh').disabled=true;
  try {
    snapshot=await api('overview'); render();
    $('last-updated').textContent='Updated '+new Date().toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});
  } catch(error) { if(!silent) notice(error.message,true); }
  finally { refreshing=false; $('refresh').disabled=false; }
}
function render() {
  const {devices,groups,jobs}=snapshot;
  $('total-devices').textContent=devices.length;
  $('active-devices').textContent=devices.filter(d=>d.status==='active').length;
  $('pending-devices').textContent=devices.filter(d=>d.status==='pending').length;
  $('pending-count').textContent=$('pending-devices').textContent;
  $('running-jobs').textContent=jobs.filter(j=>j.running).length;
  renderDevices();
  $('group-cards').replaceChildren();
  if(!groups.length) $('group-cards').append(empty('No account groups yet. Upload your first JSON export.'));
  for(const group of groups) {
    const card=node('div','','group-card'), details=node('div'); details.append(node('h3',group.name),node('p',group.id+' · '+devices.filter(d=>d.groups.includes(group.id)).length+' assigned devices','mono'));
    card.append(details,node('div',group.count,'group-number')); $('group-cards').append(card);
  }
  $('job-cards').replaceChildren();
  if(!jobs.length) $('job-cards').append(empty('No jobs yet. Start a panel from the licensed phone app.'));
  for(const job of jobs) {
    const card=node('article','','job-card'), top=node('div','','job-top'); top.append(node('h3','Panel '+(job.panel+1)+' · '+job.group),badge(job.running && job.phase!=='Stopping'?'running':job.phase.toLowerCase()));
    const counters=node('div','','job-counters');
    for(const [label,value] of [['Acknowledged',job.sent],['Failed',job.failed],['Round',job.round]]) { const item=node('div'); item.append(node('strong',value),node('span',label)); counters.append(item); }
    card.append(top,node('p',job.device,'mono'),counters);
    if(job.running) { const stop=node('button',job.phase==='Stopping'?'Stopping…':'Stop panel','secondary'); stop.disabled=job.phase==='Stopping'; stop.addEventListener('click',async()=>{ stop.disabled=true; stop.textContent='Stopping…'; try { await api('jobs/stop',{device:job.device,panel:job.panel}); notice('Stop accepted. Closing panel connections.'); await refresh(); setTimeout(()=>refresh(true),1500); } catch(error) { notice(error.message,true); stop.disabled=false; stop.textContent='Stop panel'; } }); card.append(stop); }
    $('job-cards').append(card);
  }
  $('audit-list').replaceChildren();
  if(!snapshot.audit.length) $('audit-list').append(empty('Administrative activity will appear here.'));
  for(const event of snapshot.audit) { const row=node('div','','audit-event'), detail=node('div'); detail.append(node('h3',event.action.replaceAll('_',' ')),node('p',event.target,'mono')); row.append(detail,node('time',new Date(event.time*1000).toLocaleString())); $('audit-list').append(row); }
  $('api-origin').value=location.origin; $('server-key').value=snapshot.server_public_key;
}
function renderDevices() {
  if(!snapshot) return;
  const search=$('search').value.trim().toLowerCase(), status=$('status-filter').value;
  const devices=snapshot.devices.filter(d=>d.id.includes(search) && (status==='all'||d.status===status));
  $('device-rows').replaceChildren(); $('devices-empty').classList.toggle('hidden',devices.length>0);
  for(const device of devices) {
    const row=node('tr'), id=node('td'), state=node('td'), features=node('td'), expires=node('td'), groups=node('td'), action=node('td');
    id.append(node('div',device.id.slice(0,12)+'…'+device.id.slice(-6),'mono'),node('small',device.online?'● Connected recently':'Device activation key')); id.title=device.id;
    state.append(badge(device.status));
    const tags=node('div','','feature-tags'); for(const feature of device.features) tags.append(node('span',names[feature]||feature,'tag')); if(!device.features.length) tags.append(node('span','No features','muted')); features.append(tags);
    expires.textContent=date(device.expires); groups.textContent=device.groups.length+' assigned';
    const manage=node('button','Manage','secondary'); manage.addEventListener('click',()=>openDevice(device)); action.append(manage);
    row.append(id,state,features,expires,groups,action); $('device-rows').append(row);
  }
}
function checkbox(value,label,checked,category) {
  const wrapper=node('label'), input=document.createElement('input'); input.type='checkbox'; input.value=value; input.checked=checked; input.dataset.category=category;
  wrapper.append(input,node('span',label)); return wrapper;
}
function openDevice(device) {
  currentDevice=device; $('device-id').textContent=device.id; $('dialog-error').textContent='';
  $('feature-options').replaceChildren();
  for(const feature of snapshot.features) { const option=checkbox(feature,names[feature]||feature,device.features.includes(feature),'feature'); option.querySelector('input').addEventListener('change',()=>{$('plan').value='custom';}); $('feature-options').append(option); }
  $('plan').value=Object.keys(presets).find(key=>presets[key].length===device.features.length && presets[key].every(f=>device.features.includes(f)))||'custom';
  if(!device.features.length) { $('plan').value='basic'; applyPreset(); }
  $('assignment-options').replaceChildren();
  for(const group of snapshot.groups) $('assignment-options').append(checkbox(group.id,group.name+' · '+group.count+' accounts',device.groups.includes(group.id),'group'));
  if(!snapshot.groups.length) $('assignment-options').append(node('p','Upload an account group first.','muted'));
  $('revoke-device').disabled=device.status==='revoked'; $('device-dialog').showModal();
}
function applyPreset() { const selected=presets[$('plan').value]; if(selected) for(const input of $('feature-options').querySelectorAll('input')) input.checked=selected.includes(input.value); }
function selected(category) { return [...document.querySelectorAll('input[data-category="'+category+'"]:checked')].map(input=>input.value); }
$('login-form').addEventListener('submit',async event=>{
  event.preventDefault(); const button=event.submitter; button.disabled=true; $('login-error').textContent='';
  try { const reply=await api('login',{username:$('username').value,password:$('password').value}); csrf=reply.csrf; $('password').value=''; await sessionState(); }
  catch(error) { $('login-error').textContent=error.message; } finally { button.disabled=false; }
});
$('logout').addEventListener('click',async()=>{ try { await api('logout',{}); showLogin(); await sessionState(); } catch(error) { notice(error.message,true); } });
document.querySelectorAll('button[data-page]').forEach(button=>button.addEventListener('click',()=>{
  document.querySelectorAll('.page').forEach(page=>page.classList.add('hidden')); $(button.dataset.page+'-page').classList.remove('hidden');
  document.querySelectorAll('.nav').forEach(nav=>nav.classList.toggle('active',nav===button));
  const [title,description]=titles[button.dataset.page]; $('page-title').textContent=title; $('page-description').textContent=description;
}));
$('refresh').addEventListener('click',()=>refresh()); $('search').addEventListener('input',renderDevices); $('status-filter').addEventListener('change',renderDevices);
$('plan').addEventListener('change',applyPreset); $('close-dialog').addEventListener('click',()=> $('device-dialog').close());
$('device-form').addEventListener('submit',async event=>{
  event.preventDefault(); const button=event.submitter; button.disabled=true; $('dialog-error').textContent='';
  try { await api('devices/'+currentDevice.id+'/subscription',{features:selected('feature'),days:Number($('days').value),extend:$('extend').value==='true'}); $('device-dialog').close(); await refresh(); notice('Subscription saved. The phone can now check its subscription. Existing server jobs were stopped to apply the new permissions.'); }
  catch(error) { $('dialog-error').textContent=error.message; } finally { button.disabled=false; }
});
$('save-groups').addEventListener('click',async()=>{
  $('save-groups').disabled=true; $('dialog-error').textContent='';
  try { await api('devices/'+currentDevice.id+'/groups',{groups:selected('group')}); await refresh(); notice('Group assignments saved. Existing jobs for this device were stopped.'); }
  catch(error) { $('dialog-error').textContent=error.message; } finally { $('save-groups').disabled=false; }
});
$('revoke-device').addEventListener('click',async()=>{
  if(!confirm('Revoke this device’s subscription and stop its server jobs?')) return;
  try { await api('devices/'+currentDevice.id+'/revoke',{}); $('device-dialog').close(); await refresh(); notice('Access revoked and server jobs stopped.'); }
  catch(error) { $('dialog-error').textContent=error.message; }
});
$('upload-form').addEventListener('submit',async event=>{
  event.preventDefault(); const button=event.submitter; const data=new FormData(event.target);
  if(snapshot.groups.some(group=>group.id===data.get('id')) && !confirm('Replace the existing account file for this group?')) return;
  button.disabled=true; try { await api('groups',data); event.target.reset(); await refresh(); notice('Account group stored encrypted. Assign it to a device in Manage access.'); }
  catch(error) { notice(error.message,true); } finally { button.disabled=false; }
});
async function copy(id) { try { await navigator.clipboard.writeText($(id).value); notice('Copied.'); } catch(error) { notice('Select the value and copy it manually.'); } }
$('copy-origin').addEventListener('click',()=>copy('api-origin')); $('copy-key').addEventListener('click',()=>copy('server-key'));
setInterval(()=>{if(authenticated) refresh(true);},15000);
sessionState();
