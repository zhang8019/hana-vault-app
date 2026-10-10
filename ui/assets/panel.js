import { hana } from './sdk.js';

const $ = (id) => document.getElementById(id);
const state = { status: null, rows: [], selected: null, trash: false, busy: false };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const secretKeys = ['password','apiKey','privateKey','secret','accessToken','refreshToken','otpSecret','cardNumber','cardCvv'];
const labels = { title:'标题',kind:'类别',username:'账号',email:'邮箱',phone:'手机号',password:'口令',host:'主机',port:'端口',privateKey:'私钥',apiKey:'API Key',secret:'密钥',accessToken:'访问令牌',refreshToken:'刷新令牌',otpSecret:'TOTP 密钥',cardNumber:'卡号',cardExpiry:'有效期',cardCvv:'CVV',cardHolder:'持卡人',url:'网址',notes:'备注',tags:'标签（逗号分隔）' };
const kinds = ['login','ssh','api-key','secret','oauth','cookie','card','custom'];
// 数据面：经宿主注入的 surface 会话访问本 App 路由，绝不自己拼 /api 路径。
async function request(path, options = {}) {
  const response = await hana.api.fetch(path, { headers:{'content-type':'application/json'}, ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) throw new Error(data.error || `请求失败 (${response.status})`);
  return data;
}
async function copyText(text) {
  try { if (hana.clipboard?.writeText) { await hana.clipboard.writeText(text); return true; } } catch {}
  try { if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return true; } } catch {}
  return false;
}
function setNotice(message, error = false) { $('notice').textContent = message || ''; $('notice').className = error ? 'notice error' : 'notice'; }
function setBusy(value) { state.busy = value; document.querySelectorAll('button').forEach((b) => { if (!b.dataset.keepEnabled) b.disabled = value || b.dataset.originalDisabled === 'true'; }); }
async function refreshStatus() {
  try {
    const { status } = await request('/status'); state.status = status;
    $('vaultMeta').textContent = `${status.vaultName} · ${status.open ? `${status.total} 条` : '已锁定'} · ${status.accessMode}`;
    $('lockPanel').hidden = status.open; $('workspace').hidden = !status.open; $('btnLock').disabled = !status.open;
    if (!status.open) { state.rows=[]; state.selected=null; $('entryList').replaceChildren(); $('detail').innerHTML='<p class="muted">解锁后显示凭证。</p>'; }
  } catch (e) { $('vaultMeta').textContent = `接口不可用：${e.message}`; setNotice(e.message,true); }
}
async function loadSettings() {
  const { settings, grants = [], authorizationStore = { ready: true } } = await request('/settings');
  $('cfgMode').value=settings.accessMode; $('cfgLock').value=settings.lockTimeoutSeconds; $('cfgName').value=settings.vaultName; $('cfgCapture').checked=settings.autoCapture; $('cfgRememberDevice').checked=Boolean(settings.rememberDevice);
  $('authStoreWarning').hidden=authorizationStore.ready; $('authStoreWarning').textContent=authorizationStore.ready?'':'授权文件损坏或不可读，Agent 凭证操作已关闭。修复会清空所有长期授权。'; $('btnRepairAuth').hidden=authorizationStore.ready;
  $('btnRepairAuth').onclick=async()=>{if(!confirm('确认清空损坏的授权文件并重建？现有长期授权将全部失效。'))return;await request('/settings',{method:'POST',body:JSON.stringify({repairAuthorizationStore:true})});await loadSettings();};
  $('agentGrants').innerHTML=grants.length?`<p class="muted">当前 ${grants.length} 条长期授权，涉及 ${new Set(grants.map(g=>g.agentId)).size} 个 Agent。<button type="button" id="openAuthFromSettings" class="ghost">查看与撤销</button></p>`:'<p class="muted">暂无长期授权</p>';
  if($('openAuthFromSettings'))$('openAuthFromSettings').onclick=()=>openAuthorization().catch((e)=>setNotice(e.message,true));
}
async function loadRows() {
  if (!state.status?.open) return;
  const params = new URLSearchParams({ q:$('search').value.trim(), kind:$('kindFilter').value, trash:state.trash?'1':'0', limit:'200' });
  const { entries } = await request(`/entries?${params}`); state.rows=entries; renderList();
}
function renderList() {
  const list=$('entryList');
  if (!state.rows.length) { list.innerHTML='<li class="empty">没有匹配的凭证</li>'; return; }
  list.innerHTML=state.rows.map((e)=>`<li data-id="${esc(e.id)}" class="${state.selected===e.id?'active':''}"><span class="t">${esc(e.title)}${e.hasOtp?'<span class="badge good">TOTP</span>':''}</span><span class="s">${esc(e.kind||'login')} · ${esc([e.username,e.host,e.url].filter(Boolean).join(' · '))}</span></li>`).join('');
  list.querySelectorAll('[data-id]').forEach((li)=>li.addEventListener('click',()=>selectEntry(li.dataset.id)));
}
function fieldMarkup(key,value) {
  if (value==null||value==='') return '';
  const label=labels[key]||key;
  if (secretKeys.includes(key)) return `<dt>${esc(label)}</dt><dd class="secret"><code data-secret="${esc(value)}" data-visible="false">••••••••</code><button data-action="reveal">显示</button><button data-action="copy">复制</button></dd>`;
  if (key==='tags'&&Array.isArray(value)) value=value.join(', ');
  return `<dt>${esc(label)}</dt><dd>${esc(value)}</dd>`;
}
async function selectEntry(id) {
  state.selected=id; renderList();
  const { entry:e }=await request(`/entries/${encodeURIComponent(id)}`);
  $('detail').innerHTML=`<h2>${esc(e.title)}</h2><div>${(e.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div><dl>${['kind','username','email','phone','password','host','port','apiKey','secret','accessToken','refreshToken','privateKey','otpSecret','cardNumber','cardExpiry','cardCvv','cardHolder','url','notes'].map((k)=>fieldMarkup(k,e[k])).join('')}</dl><div class="row"><button id="editEntry" class="ghost">编辑</button><button id="trashEntry" class="ghost">${state.trash?'永久删除':'移入回收站'}</button>${e.hasOtp?'<button id="showTotp" class="ghost">获取 TOTP</button>':''}</div><p id="totpOut" class="muted"></p>`;
  $('detail').querySelectorAll('[data-action="reveal"]').forEach((btn)=>btn.onclick=()=>{const code=btn.parentElement.querySelector('code');const visible=code.dataset.visible==='true';code.textContent=visible?'••••••••':code.dataset.secret;code.dataset.visible=String(!visible);btn.textContent=visible?'显示':'隐藏';});
  $('detail').querySelectorAll('[data-action="copy"]').forEach((btn)=>btn.onclick=async()=>{const ok=await copyText(btn.parentElement.querySelector('code').dataset.secret);if(!ok){setNotice('复制失败：此环境不允许写剪贴板。',true);return;}btn.textContent='已复制';setTimeout(()=>btn.textContent='复制',1400);});
  $('editEntry').onclick=()=>openEditor(e);
  $('trashEntry').onclick=async()=>{if(state.trash){if(!confirm('永久删除后无法恢复，确定继续？'))return;await request(`/entries/${encodeURIComponent(id)}/purge`,{method:'POST',body:JSON.stringify({confirm:true})});}else{if(!confirm(`将「${e.title}」移入回收站？`))return;await request(`/entries/${encodeURIComponent(id)}`,{method:'DELETE'});}state.selected=null;await refreshStatus();await loadRows();};
  if($('showTotp'))$('showTotp').onclick=async()=>{const r=await request(`/entries/${encodeURIComponent(id)}/totp`);$('totpOut').textContent=`验证码 ${r.code} · ${r.secondsRemaining} 秒后过期`;};
}
function openEditor(entry=null) {
  $('modalTitle').textContent=entry?'编辑凭证':'新增凭证';
  const fields=['title','kind','username','email','phone','password','host','port','privateKey','apiKey','secret','accessToken','refreshToken','otpSecret','cardNumber','cardExpiry','cardCvv','cardHolder','url','notes','tags'];
  $('modalBody').innerHTML=`<div class="form-grid">${fields.map((key)=>{const label=labels[key]||key;let value=key==='tags'?(entry?.tags||[]).join(', '):(entry?.[key]??'');if(key==='kind')return `<label>${esc(label)}<select data-key="kind">${kinds.map((k)=>`<option value="${k}" ${(entry?.kind||'login')===k?'selected':''}>${k}</option>`).join('')}</select></label>`;const type=secretKeys.includes(key)?'password':'text';const cls=['privateKey','notes'].includes(key)?'full':'';if(cls)return `<label class="${cls}">${esc(label)}<textarea data-key="${key}" autocomplete="off">${esc(value)}</textarea></label>`;return `<label>${esc(label)}<input data-key="${key}" type="${type}" autocomplete="off" value="${esc(value)}"></label>`;}).join('')}</div>`;
  $('modal').hidden=false; $('modalOk').textContent='保存'; $('modalOk').onclick=async()=>{const body={};$('modalBody').querySelectorAll('[data-key]').forEach((el)=>{let v=el.value;if(el.dataset.key==='tags')v=v.split(',').map(s=>s.trim()).filter(Boolean);if(typeof v==='string')v=v.trim();if(v!==''&&(!Array.isArray(v)||v.length))body[el.dataset.key]=v;});if(!body.title){setNotice('标题不能为空',true);return;}const url=entry?`/entries/${encodeURIComponent(entry.id)}`:'/entries';const r=await request(url,{method:entry?'PUT':'POST',body:JSON.stringify(body)});$('modal').hidden=true;await refreshStatus();await loadRows();await selectEntry(r.entry.id);setNotice('已保存凭证摘要；秘密仅写入加密库。');};
}
async function showHealth() {
  const { report:r }=await request('/health'); $('modalTitle').textContent='保险库安全体检';
  $('modalBody').innerHTML=`<p>总分 <strong>${esc(r.score)}/100</strong>（${esc(r.verdict)}）</p><p class="muted">弱口令 ${r.weak.length} · 复用组 ${r.reused.length} · 未启用 2FA ${r.no2fa.length} · HTTP 明文 ${r.httpSites.length}</p>${[['弱口令',r.weak],['复用',r.reused.flatMap(g=>g.entries)],['未启用 2FA',r.no2fa],['HTTP 明文',r.httpSites]].map(([title,rows])=>rows.length?`<h3>${title}</h3><ul>${rows.map(x=>`<li>${esc(x.title)}</li>`).join('')}</ul>`:'').join('')}`;
  $('modal').hidden=false;$('modalOk').hidden=true;$('modalCancel').textContent='关闭';
}
async function openAudit() { const {events}=await request('/audit?limit=100'); $('modalTitle').textContent='近期安全审计'; $('modalBody').innerHTML=events.length?`<ul class="audit-list">${events.map(e=>`<li><strong>${esc(e.kind)}</strong> · ${esc(e.title||e.vaultName||e.id||'')}<span>${esc(e.at)}</span></li>`).join('')}</ul>`:'<p class="muted">暂无记录</p>'; $('modal').hidden=false;$('modalOk').hidden=true;$('modalCancel').textContent='关闭'; }
const fmtTime=(t)=>{try{return new Date(t).toLocaleString('zh-CN')}catch{return String(t||'')}};
async function openAuthorization(){
  const [{grants},{events}]=await Promise.all([request('/grants'),request('/audit?limit=100')]);
  const byAgent=new Map();
  for(const g of grants){const k=g.agentId||'未知';if(!byAgent.has(k))byAgent.set(k,{name:g.agentName||g.agentId,items:[]});byAgent.get(k).items.push(g);}
  const grantBlocks=byAgent.size?[...byAgent.entries()].map(([agentId,info])=>`<div class="audit-row"><div><strong>${esc(info.name)}</strong> <span class="muted">${esc(agentId)}</span> · ${info.items.length} 条长期授权 <button type="button" data-revoke-agent="${esc(agentId)}">撤销该 Agent 全部</button></div><ul class="audit-list">${info.items.map(g=>`<li>${esc(g.credentialLabel||g.credentialId)}${g.category?`（${esc(g.category)}）`:''} · 动作 ${esc(g.action)} · 字段 ${esc((g.fields||[]).join('、')||'无')} · 授权于 ${esc(fmtTime(g.createdAt))} <button type="button" data-revoke-grant="${esc(g.id)}">撤销此条</button></li>`).join('')}</ul></div>`).join(''):'<p class="muted">当前没有任何长期授权。Agent 每次访问都会弹授权卡让你确认。</p>';
  const agentEvents=events.filter(e=>e.agentId);
  const auditBlocks=agentEvents.length?`<ul class="audit-list">${agentEvents.map(e=>`<li><strong>${esc(e.kind)}</strong> · ${esc(e.agentName||e.agentId)}${e.action?` · ${esc(e.action)}`:''}${e.credentialId&&e.credentialId!=='*'?` · ${esc(e.credentialId)}`:''}${e.persistent!==undefined?` · ${e.persistent?'长期':'单次'}`:''}<span>${esc(fmtTime(e.at))}</span></li>`).join('')}</ul>`:'<p class="muted">暂无 Agent 调用记录。</p>';
  $('modalTitle').textContent='授权与审计';
  $('modalBody').innerHTML=`<h3>当前长期授权</h3><p class="hint">长期授权绑定具体库、Agent、凭证、动作与字段；撤销后该 Agent 下次调用会重新弹卡。</p>${grantBlocks}<h3>近期 Agent 调用</h3>${auditBlocks}`;
  $('modal').hidden=false;$('modalOk').hidden=true;$('modalCancel').textContent='关闭';
  $('modalBody').querySelectorAll('[data-revoke-grant]').forEach(b=>b.onclick=async()=>{if(!confirm('撤销这条长期授权？该 Agent 以后每次调用都会重新询问。'))return;await request('/grants/revoke-grant',{method:'POST',body:JSON.stringify({grantId:b.dataset.revokeGrant})});setNotice('已撤销该长期授权。');await openAuthorization();await loadSettings().catch(()=>{});});
  $('modalBody').querySelectorAll('[data-revoke-agent]').forEach(b=>b.onclick=async()=>{if(!confirm('撤销该 Agent 的全部长期授权？'))return;await request('/grants/revoke',{method:'POST',body:JSON.stringify({agentId:b.dataset.revokeAgent})});setNotice('已撤销该 Agent 的全部长期授权。');await openAuthorization();await loadSettings().catch(()=>{});});
}
async function generatePassword() { const {value,strength}=await request('/generate-password',{method:'POST',body:JSON.stringify({length:24})}); $('modalTitle').textContent='强随机口令'; $('modalBody').innerHTML=`<label class="full">口令<textarea id="generated" readonly>${esc(value)}</textarea></label><p>强度 ${esc(strength.score)}/100（${esc(strength.verdict)}）</p>`; $('modal').hidden=false;$('modalOk').hidden=false;$('modalOk').textContent='复制并关闭';$('modalOk').onclick=async()=>{const ok=await copyText(value);$('modal').hidden=true;setNotice(ok?'已复制；口令未写入日志。':'口令未复制：此环境不允许写剪贴板。',!ok);}; }
function toBase64(text){const bytes=new TextEncoder().encode(text);let bin='';for(let i=0;i<bytes.length;i+=0x8000){bin+=String.fromCharCode(...bytes.subarray(i,i+0x8000));}return btoa(bin);}
async function exportBackup(){const password=prompt('设置独立导出密码（至少 12 个字符）。不会保存到设置或日志。');if(password===null)return;if(password.length<12){setNotice('导出密码至少 12 个字符。',true);return;}const {encryptedBackup}=await request('/export',{method:'POST',body:JSON.stringify({password})});const saved=await hana.resources.saveFile({suggestedName:`hana-vault-backup-${new Date().toISOString().slice(0,10)}.json`,mimeType:'application/json',contentBase64:toBase64(encryptedBackup)});if(saved?.kind==='saved')setNotice('加密备份已保存。请妥善保管导出密码。');else if(saved?.kind==='canceled')setNotice('已取消保存。');else setNotice(`保存未完成（${saved?.kind||'未知'}）。`,true);}
async function toggleSettings(){ $('settingsPanel').hidden=!$('settingsPanel').hidden;if(!$('settingsPanel').hidden)await loadSettings(); }
async function boot(){ try{await hana.ready();}catch{} await refreshStatus(); }
$('btnUnlock').onclick=async()=>{const password=$('unlockPwd').value;if(!password){$('unlockError').textContent='请输入主密码';return;}try{$('btnUnlock').disabled=true;const {status}=await request('/unlock',{method:'POST',body:JSON.stringify({password,vaultName:$('vaultName').value})});$('unlockPwd').value='';$('unlockError').textContent='';state.status=status;await refreshStatus();await loadRows();setNotice('已解锁。主密码未保存。');}catch(e){$('unlockError').textContent=e.message;}finally{$('btnUnlock').disabled=false;}};
$('btnLock').onclick=async()=>{await request('/lock',{method:'POST'});await refreshStatus();setNotice('保险库已锁定，内存密钥已清除。');};
$('btnSettings').onclick=toggleSettings;
$('btnSaveCfg').onclick=async()=>{const settings={accessMode:$('cfgMode').value,lockTimeoutSeconds:Number($('cfgLock').value)||900,vaultName:$('cfgName').value||'default',autoCapture:$('cfgCapture').checked,rememberDevice:$('cfgRememberDevice').checked};await request('/settings',{method:'POST',body:JSON.stringify(settings)});$('cfgMsg').textContent='策略已保存';await refreshStatus();};
$('btnAdd').onclick=()=>openEditor(); $('btnAuth').onclick=()=>openAuthorization().catch(e=>setNotice(e.message,true)); $('btnGen').onclick=()=>generatePassword().catch(e=>setNotice(e.message,true));$('btnHealth').onclick=()=>showHealth().catch(e=>setNotice(e.message,true));$('btnAudit').onclick=()=>openAudit().catch(e=>setNotice(e.message,true));$('btnExport').onclick=()=>exportBackup().catch(e=>setNotice(e.message,true));
$('btnTrash').onclick=async()=>{state.trash=!state.trash;$('btnTrash').textContent=state.trash?'退出回收站':'回收站';state.selected=null;$('detail').innerHTML='<p class="muted">选择凭证查看。</p>';await loadRows();};
$('search').oninput=()=>{clearTimeout(window.__vaultSearch);window.__vaultSearch=setTimeout(()=>loadRows().catch(e=>setNotice(e.message,true)),220);};$('kindFilter').onchange=()=>loadRows().catch(e=>setNotice(e.message,true));
$('modalCancel').onclick=()=>{$('modal').hidden=true;$('modalOk').hidden=false;$('modalOk').textContent='保存';$('modalCancel').textContent='取消';};$('modal').onclick=(e)=>{if(e.target===$('modal'))$('modalCancel').click();};
// 离开页面时尽力锁定；锁不上也不阻塞关闭（服务端仍有空闲自动锁定兼底）。
window.addEventListener('pagehide',()=>{if(state.status?.open){try{void request('/lock',{method:'POST',body:JSON.stringify({reason:'pagehide'})});}catch{}}});
boot().catch((e)=>setNotice(e.message,true));
