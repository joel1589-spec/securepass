const $ = id => document.getElementById(id);
function adminToken(){return localStorage.getItem('sp_admin_token') || ''}
function adminAuth(){return {'Content-Type':'application/json','Authorization':'Bearer '+adminToken()}}
function toast(m, type='error'){const e=document.createElement('div');e.className='toast '+type;e.textContent=m;document.body.appendChild(e);setTimeout(()=>e.remove(),3500)}
async function api(path, opts={}){const r=await fetch(path,{...opts,headers:{...(opts.headers||{}),...adminAuth()}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.message||'Erreur');return d}
function showApp(){ $('adminLogin').classList.add('hidden'); $('adminApp').classList.remove('hidden'); }
function showLogin(){ $('adminApp').classList.add('hidden'); $('adminLogin').classList.remove('hidden'); }
async function adminLogin(){
  const identifier=$('adminIdentifier').value.trim(); const password=$('adminPassword').value; const otp=$('adminOtp').value.trim();
  try{
    const r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identifier,password,otp})});
    const d=await r.json().catch(()=>({}));
    if(r.status===206){ toast(d.message||'Code 2FA requis','info'); $('adminOtp').focus(); return; }
    if(!r.ok) throw new Error(d.message||'Accès refusé');
    localStorage.setItem('sp_admin_token', d.token); toast('Connexion admin réussie','success'); await boot();
  }catch(e){toast(e.message)}
}
function adminLogout(){localStorage.removeItem('sp_admin_token'); showLogin();}
async function boot(){
  if(!adminToken()) return showLogin();
  try{const me=await api('/api/admin/me'); $('adminWho').textContent=me.username+' • '+me.email; showApp(); await loadStats();}
  catch(e){showLogin(); toast(e.message)}
}
async function loadStats(){
  try{const s=await api('/api/admin/stats'); $('adminContent').innerHTML=`
    <div class="card"><h3>Utilisateurs</h3><div class="big-number">${s.users}</div></div>
    <div class="card"><h3>Connectés récemment</h3><div class="big-number">${s.active_recent}</div></div>
    <div class="card"><h3>Premium</h3><div class="big-number">${s.premium}</div></div>
    <div class="card"><h3>Entreprises</h3><div class="big-number">${s.organizations}</div></div>
    <div class="card"><h3>Comptes bloqués</h3><div class="big-number">${s.blocked}</div></div>
    <div class="card"><h3>Revenus XOF</h3><div class="big-number">${s.revenue_xof}</div></div>`}
  catch(e){toast(e.message)}
}
async function loadUsers(){
  try{const u=await api('/api/admin/users'); $('adminContent').innerHTML=`<div class="card" style="grid-column:1/-1"><h3>Utilisateurs</h3><table class="table"><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Plan</th><th>2FA</th><th>Dernière connexion</th><th>Actions</th></tr>${u.map(x=>`<tr><td>${x.id}</td><td>${x.username}</td><td>${x.email}</td><td>${x.role}</td><td>${x.effective_plan}</td><td>${x.twofa?'Oui':'Non'}</td><td>${x.last_login_at||'-'}</td><td>${x.role==='super_admin'?'Protégé':`<button onclick="toggleUser(${x.id})">${x.active?'Suspendre':'Réactiver'}</button> <button onclick="unblockUser(${x.id})">Débloquer</button>`}</td></tr>`).join('')}</table></div>`}
  catch(e){toast(e.message)}
}
async function toggleUser(id){try{await api(`/api/admin/users/${id}/toggle-active`,{method:'POST'});toast('Statut mis à jour','success');loadUsers()}catch(e){toast(e.message)}}
async function unblockUser(id){try{await api(`/api/admin/users/${id}/unblock`,{method:'POST'});toast('Compte débloqué','success');loadUsers()}catch(e){toast(e.message)}}
async function loadPayments(){try{const p=await api('/api/admin/payments'); $('adminContent').innerHTML=`<div class="card" style="grid-column:1/-1"><h3>Paiements</h3><table class="table"><tr><th>ID</th><th>User</th><th>Plan</th><th>Montant</th><th>Status</th><th>Référence</th><th>Date</th></tr>${p.map(x=>`<tr><td>${x.id}</td><td>${x.user_id}</td><td>${x.plan}</td><td>${x.amount_xof} XOF</td><td>${x.status}</td><td>${x.reference}</td><td>${x.created_at}</td></tr>`).join('')}</table></div>`}catch(e){toast(e.message)}}
async function loadOrganizations(){try{const o=await api('/api/admin/organizations'); $('adminContent').innerHTML=`<div class="card" style="grid-column:1/-1"><h3>Organisations Enterprise</h3><table class="table"><tr><th>ID</th><th>Nom</th><th>Owner</th><th>Employés</th><th>Statut</th><th>Date</th></tr>${o.map(x=>`<tr><td>${x.id}</td><td>${x.name}</td><td>${x.owner_id}</td><td>${x.users}</td><td>${x.active?'Active':'Suspendue'}</td><td>${x.created_at}</td></tr>`).join('')}</table></div>`}catch(e){toast(e.message)}}
async function loadLogs(){try{const l=await api('/api/admin/logs'); $('adminContent').innerHTML=`<div class="card" style="grid-column:1/-1"><h3>Logs sécurité</h3>${l.map(x=>`<p><b>${x.created_at}</b> — ${x.action} <span class="muted">IP: ${x.ip||'-'} | User: ${x.user_id||'-'} | Org: ${x.org||'-'}</span></p>`).join('')}</div>`}catch(e){toast(e.message)}}
boot();
