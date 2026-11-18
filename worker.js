const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8',...headers}});
const bad = (message, status=400) => json({error:message},status);
const uuid = () => crypto.randomUUID();
const enc = new TextEncoder();
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt:enc.encode(salt), iterations:120000, hash:'SHA-256'}, key, 256);
  return [...new Uint8Array(bits)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function tokenFor(user, secret) {
  const header = b64u(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const payload = b64u(JSON.stringify({sub:user.id,email:user.email,role:user.role,exp:Math.floor(Date.now()/1000)+86400}));
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC',key,enc.encode(`${header}.${payload}`));
  return `${header}.${payload}.${b64u(new Uint8Array(sig))}`;
}
function b64u(input){const bytes=typeof input==='string'?enc.encode(input):input;let binary='';for(const b of bytes)binary+=String.fromCharCode(b);return btoa(binary).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')}
function unb64bytes(str){return Uint8Array.from(atob(str.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0))}
function unb64u(str){return new TextDecoder().decode(unb64bytes(str))}
async function auth(req, env){
  const t=(req.headers.get('cookie')||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('fust_session='))?.slice(13);
  if(!t) return null;
  try {
    const [h,p,s]=t.split('.'); const key=await crypto.subtle.importKey('raw',enc.encode(env.JWT_SECRET),{name:'HMAC',hash:'SHA-256'},false,['verify']);
    const ok=await crypto.subtle.verify('HMAC',key,unb64bytes(s),enc.encode(`${h}.${p}`));
    if(!ok) return null; const data=JSON.parse(unb64u(p)); if(data.exp<Date.now()/1000) return null;
    const user=await env.DB.prepare('SELECT id,email,username,role FROM users WHERE id=?').bind(data.sub).first(); return user||null;
  }catch{return null}
}
async function audit(env, actor, action, detail='') { await env.DB.prepare('INSERT INTO audit_log(id,actor_id,action,detail) VALUES(?,?,?,?)').bind(uuid(),actor,action,detail).run(); }
async function requireOwner(user){return user?.role==='owner'}
async function storageUsed(env,cityId){const r=await env.DB.prepare('SELECT COALESCE(SUM(size_bytes),0) AS used FROM city_files WHERE city_id=?').bind(cityId).first();return Number(r?.used||0)}
async function api(req,env){
  const url=new URL(req.url), path=url.pathname, method=req.method;
  if(!env.JWT_SECRET) return bad('Configure JWT_SECRET in Worker secrets.',503);
  if(method==='POST'&&path==='/api/setup-owner'){
    if(!env.OWNER_SETUP_SECRET) return bad('OWNER_SETUP_SECRET não configurado.',503);
    const existing=await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='owner'").first(); if(existing.n) return bad('Owner já configurado.',403);
    const b=await req.json(); if(b.setupSecret!==env.OWNER_SETUP_SECRET) return bad('Segredo de setup inválido.',403);
    if(!b.email||!b.username||!b.password||b.password.length<12) return bad('Informe email, nome e senha de no mínimo 12 caracteres.');
    const id=uuid(),salt=uuid(),ph=`${salt}:${await hashPassword(b.password,salt)}`;
    await env.DB.prepare('INSERT INTO users(id,email,username,password_hash,role) VALUES(?,?,?,?,?)').bind(id,b.email.toLowerCase(),b.username,ph,'owner').run();
    await audit(env,id,'owner_created'); return json({ok:true,message:'Owner criado. Faça login.'});
  }
  if(method==='POST'&&path==='/api/register'){
    const b=await req.json(); if(!b.email||!b.username||!b.password||b.password.length<10) return bad('Preencha email, nome e senha (mínimo 10 caracteres).');
    const id=uuid(),salt=uuid(),ph=`${salt}:${await hashPassword(b.password,salt)}`;
    try{await env.DB.prepare('INSERT INTO users(id,email,username,password_hash,role) VALUES(?,?,?,?,?)').bind(id,b.email.toLowerCase(),b.username,ph,'client').run();}catch{return bad('Email já cadastrado.');}
    return json({ok:true},201);
  }
  if(method==='POST'&&path==='/api/login'){
    const b=await req.json();const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind((b.email||'').toLowerCase()).first();
    if(!u) return bad('Email ou senha inválidos.',401); const [salt,stored]=u.password_hash.split(':'); if(await hashPassword(b.password||'',salt)!==stored) return bad('Email ou senha inválidos.',401);
    const token=await tokenFor(u,env.JWT_SECRET); return json({ok:true,user:{id:u.id,email:u.email,username:u.username,role:u.role}},200,{ 'set-cookie':`fust_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`});
  }
  if(method==='POST'&&path==='/api/logout') return json({ok:true},200,{'set-cookie':'fust_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'});
  const user=await auth(req,env); if(!user) return bad('Faça login para continuar.',401);
  if(method==='GET'&&path==='/api/me') return json({user});
  if(method==='GET'&&path==='/api/plans') return json({plans:await env.DB.prepare('SELECT id,name,storage_gb,price_label,description,enabled FROM plans WHERE enabled=1 ORDER BY storage_gb').all().then(r=>r.results)});
  if(method==='GET'&&path==='/api/cities'){
    const cities=await (requireOwner(user)?env.DB.prepare('SELECT c.*,u.email AS owner_email,p.name AS plan_name,p.storage_gb FROM cities c LEFT JOIN users u ON u.id=c.owner_id LEFT JOIN plans p ON p.id=c.plan_id ORDER BY c.created_at DESC').all():env.DB.prepare('SELECT c.*,p.name AS plan_name,p.storage_gb FROM cities c LEFT JOIN plans p ON p.id=c.plan_id WHERE c.owner_id=? ORDER BY c.created_at DESC').bind(user.id).all());
    const result=[];for(const c of cities.results){const used=await storageUsed(env,c.id);result.push({...c,used_bytes:used,used_gb:Number((used/1024**3).toFixed(3))});}return json({cities:result});
  }
  if(method==='POST'&&path==='/api/cities'){
    const b=await req.json();if(!b.name?.trim())return bad('Nome da cidade obrigatório.');
    const plan=await env.DB.prepare('SELECT * FROM plans WHERE id=? AND enabled=1').bind(b.planId||'').first();if(!plan)return bad('Plano inválido.');
    const id=uuid();await env.DB.prepare('INSERT INTO cities(id,owner_id,name,plan_id) VALUES(?,?,?,?)').bind(id,user.id,b.name.trim(),plan.id).run();await audit(env,user.id,'city_created',id);return json({ok:true,id},201);
  }
  if(method==='GET'&&path==='/api/owner/plans'){
    if(!requireOwner(user))return bad('Acesso Owner negado.',403);return json({plans:(await env.DB.prepare('SELECT * FROM plans ORDER BY storage_gb').all()).results});
  }
  if(method==='POST'&&path==='/api/owner/plans'){
    if(!requireOwner(user))return bad('Acesso Owner negado.',403);const b=await req.json();if(!b.name||!Number.isInteger(Number(b.storage_gb))||Number(b.storage_gb)<1||Number(b.storage_gb)>200)return bad('Nome e armazenamento entre 1 e 200 GB são obrigatórios.');const id=uuid();await env.DB.prepare('INSERT INTO plans(id,name,storage_gb,price_label,description,enabled) VALUES(?,?,?,?,?,1)').bind(id,b.name,Number(b.storage_gb),b.price_label||'Personalizado',b.description||'').run();await audit(env,user.id,'plan_created',id);return json({ok:true,id},201);
  }
  if(method==='DELETE'&&path.startsWith('/api/owner/plans/')){
    if(!requireOwner(user))return bad('Acesso Owner negado.',403);const id=path.split('/').pop();await env.DB.prepare('UPDATE plans SET enabled=0 WHERE id=?').bind(id).run();await audit(env,user.id,'plan_disabled',id);return json({ok:true});
  }
  if(method==='POST'&&path==='/api/owner/cities'){
    if(!requireOwner(user))return bad('Acesso Owner negado.',403);const b=await req.json();if(!b.name?.trim()||!b.owner_id)return bad('Informe cliente e nome da cidade.');const plan=await env.DB.prepare('SELECT id FROM plans WHERE id=? AND enabled=1').bind(b.planId||'').first();if(!plan)return bad('Plano inválido.');const owner=await env.DB.prepare("SELECT id FROM users WHERE id=? AND role='client'").bind(b.owner_id).first();if(!owner)return bad('Cliente inválido.');const id=uuid();await env.DB.prepare('INSERT INTO cities(id,owner_id,name,plan_id) VALUES(?,?,?,?)').bind(id,owner.id,b.name.trim(),plan.id).run();await audit(env,user.id,'owner_city_created',id);return json({ok:true,id},201);
  }
  if(method==='PATCH'&&path.startsWith('/api/owner/plans/')){
    if(!requireOwner(user))return bad('Acesso Owner negado.',403);const id=path.split('/').pop();const b=await req.json();if(!b.name||!Number.isInteger(Number(b.storage_gb))||Number(b.storage_gb)<1||Number(b.storage_gb)>200)return bad('Nome e armazenamento entre 1 e 200 GB são obrigatórios.');await env.DB.prepare('UPDATE plans SET name=?,storage_gb=?,price_label=?,description=? WHERE id=?').bind(b.name,Number(b.storage_gb),b.price_label||'Personalizado',b.description||'',id).run();await audit(env,user.id,'plan_updated',id);return json({ok:true});
  }
  if(method==='GET'&&path==='/api/owner/users'){
    if(!requireOwner(user))return bad('Acesso Owner negado.',403);return json({users:(await env.DB.prepare('SELECT id,email,username,role,created_at FROM users ORDER BY created_at DESC').all()).results});
  }
  if(method==='DELETE'&&path.startsWith('/api/owner/users/')){
    if(!requireOwner(user))return bad('Acesso Owner negado.',403);const id=path.split('/').pop();if(id===user.id)return bad('Não pode excluir a própria conta Owner.');const owned=await env.DB.prepare('SELECT id FROM cities WHERE owner_id=?').bind(id).all();for(const city of owned.results){const files=await env.DB.prepare('SELECT object_key FROM city_files WHERE city_id=?').bind(city.id).all();for(const f of files.results)await env.FILES.delete(f.object_key);await env.DB.prepare('DELETE FROM city_files WHERE city_id=?').bind(city.id).run();await env.DB.prepare('DELETE FROM cities WHERE id=?').bind(city.id).run();}await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();await audit(env,user.id,'user_deleted',id);return json({ok:true});
  }
  if(path.startsWith('/api/cities/')){
    const cityId=path.split('/')[3];const city=await env.DB.prepare('SELECT * FROM cities WHERE id=?').bind(cityId).first();if(!city)return bad('Cidade não encontrada.',404);if(city.owner_id!==user.id&&!requireOwner(user))return bad('Acesso negado.',403);
    if(method==='DELETE'&&path==='/api/cities/'+cityId){const files=await env.DB.prepare('SELECT object_key FROM city_files WHERE city_id=?').bind(cityId).all();for(const f of files.results)await env.FILES.delete(f.object_key);await env.DB.prepare('DELETE FROM city_files WHERE city_id=?').bind(cityId).run();await env.DB.prepare('DELETE FROM cities WHERE id=?').bind(cityId).run();await audit(env,user.id,'city_deleted',cityId);return json({ok:true});}
    if(method==='GET'&&path==='/api/cities/'+cityId+'/files')return json({files:(await env.DB.prepare('SELECT id,file_name,size_bytes,uploaded_at FROM city_files WHERE city_id=? ORDER BY uploaded_at DESC').bind(cityId).all()).results,used_bytes:await storageUsed(env,cityId)});
    if(method==='POST'&&path==='/api/cities/'+cityId+'/files'){
      const form=await req.formData(),file=form.get('file');if(!file||typeof file==='string')return bad('Selecione um arquivo.');const plan=await env.DB.prepare('SELECT storage_gb FROM plans WHERE id=?').bind(city.plan_id).first();const used=await storageUsed(env,cityId);const maxBytes=(plan?.storage_gb||0)*1024**3;if(used+file.size>maxBytes)return bad('Limite de armazenamento do plano excedido.',413);const globalUsed=await env.DB.prepare('SELECT COALESCE(SUM(size_bytes),0) AS total FROM city_files').first();if(Number(globalUsed?.total||0)+file.size>10*1024**3)return bad('Limite de armazenamento gratuito global (10 GB) atingido. Não é possível enviar mais arquivos no tier gratuito.',413);if(file.size>90*1024*1024)return bad('Arquivo maior que 90 MB: divida em partes menores.',413);const id=uuid(),key=`${cityId}/${id}/${file.name.replace(/[^\w.\- ]/g,'_')}`;await env.FILES.put(key,file.stream(),{httpMetadata:{contentType:file.type||'application/octet-stream'}});await env.DB.prepare('INSERT INTO city_files(id,city_id,object_key,file_name,size_bytes) VALUES(?,?,?,?,?)').bind(id,cityId,key,file.name,file.size).run();await audit(env,user.id,'file_uploaded',`${cityId}:${file.name}`);return json({ok:true},201);
    }
    if(method==='GET'&&path.startsWith('/api/cities/'+cityId+'/files/')){const fileId=path.split('/').pop();const f=await env.DB.prepare('SELECT * FROM city_files WHERE id=? AND city_id=?').bind(fileId,cityId).first();if(!f)return bad('Arquivo não encontrado.',404);const obj=await env.FILES.get(f.object_key);if(!obj)return bad('Arquivo ausente no armazenamento.',404);return new Response(obj.body,{headers:{'content-type':obj.httpMetadata?.contentType||'application/octet-stream','content-disposition':`attachment; filename*=UTF-8''${encodeURIComponent(f.file_name)}`,'cache-control':'no-store'}});}
    if(method==='DELETE'&&path.startsWith('/api/cities/'+cityId+'/files/')){const fileId=path.split('/').pop();const f=await env.DB.prepare('SELECT * FROM city_files WHERE id=? AND city_id=?').bind(fileId,cityId).first();if(!f)return bad('Arquivo não encontrado.',404);await env.FILES.delete(f.object_key);await env.DB.prepare('DELETE FROM city_files WHERE id=?').bind(fileId).run();await audit(env,user.id,'file_deleted',f.file_name);return json({ok:true});}
  }
  if(method==='GET'&&path==='/api/owner/logs'){if(!requireOwner(user))return bad('Acesso Owner negado.',403);return json({logs:(await env.DB.prepare('SELECT a.*,u.email FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 200').all()).results});}
  return bad('Rota não encontrada.',404);
}
export default {async fetch(req,env){const p=new URL(req.url).pathname;if(p.startsWith('/api/'))return api(req,env).catch(e=>{console.error(e);return bad('Erro interno da API.',500)});return env.ASSETS.fetch(req)}};
