import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker from '../src/index.js';
import { validateIdentity, roleFromClaims } from '../src/auth.js';
import { SignJWT, generateKeyPair } from 'jose';

function fixture() {
 const sql = new DatabaseSync(':memory:');
 sql.exec(`PRAGMA foreign_keys=ON;
 CREATE TABLE notes(id INTEGER PRIMARY KEY,content TEXT,files TEXT DEFAULT '[]',pics TEXT DEFAULT '[]',videos TEXT DEFAULT '[]',created_at INTEGER,updated_at INTEGER,is_pinned INTEGER DEFAULT 0,is_favorited INTEGER DEFAULT 0,is_archived INTEGER DEFAULT 0);
 CREATE TABLE tags(id INTEGER PRIMARY KEY,name TEXT UNIQUE);
 CREATE TABLE note_tags(note_id INTEGER,tag_id INTEGER);
 CREATE VIRTUAL TABLE notes_fts USING fts5(content);
 `);
 sql.exec(readFileSync(new URL('../migrations/0001_note_permissions.sql', import.meta.url),'utf8'));
 sql.exec(readFileSync(new URL('../migrations/0002_public_shares.sql', import.meta.url),'utf8'));
 sql.exec(readFileSync(new URL('../migrations/0003_user_sharing.sql', import.meta.url),'utf8'));
 for(const id of ['alice','bob','admin']) {
  sql.prepare('INSERT INTO users (id,issuer,subject,name,email) VALUES (?, ?, ?, ?, ?)').run(id,'https://idp',id,id,`${id}@example.test`);
  sql.prepare('INSERT INTO auth_sessions VALUES (?, ?, ?, ?)').run(id,id,id==='admin'?1:0,Date.now()+600000);
 }
 for (const [id,owner] of [[1,'alice'],[2,'bob'],[3,null]]) {
  sql.prepare('INSERT INTO notes(id,content,owner_id,created_at,updated_at) VALUES (?,?,?,?,?)').run(id,`private memo ${id}`,owner,Date.now(),Date.now());
  sql.prepare('INSERT INTO notes_fts(rowid,content) VALUES (?,?)').run(id,`private memo ${id}`);
  sql.prepare('INSERT INTO tags VALUES (?,?)').run(id,`tag${id}`);
  sql.prepare('INSERT INTO note_tags VALUES (?,?)').run(id,id);
 }
 const DB = { prepare(query) {
  const statement=sql.prepare(query); let bindings=[];
  return { bind(...args){bindings=args;return this}, async first(){return statement.get(...bindings)||null},async all(){return {results:statement.all(...bindings)}},async run(){return statement.run(...bindings)} };
 }, async batch(statements){sql.exec('BEGIN');try{const r=await Promise.all(statements.map(s=>s.run()));sql.exec('COMMIT');return r}catch(e){sql.exec('ROLLBACK');throw e}} };
 const deleted=[];
 const env={DB,APP_ORIGIN:'https://n.markso.ng',NOTES_KV:{get:async()=>null,put:async()=>{}},NOTES_R2_BUCKET:{list:async()=>({objects:[],truncated:false}),delete:async keys=>deleted.push(...keys),get:async()=>null,head:async()=>null}};
 async function request(path,user='alice',method='GET',body){return worker.fetch(new Request(`https://n.markso.ng${path}`,{method,headers:{Cookie:`__Host-notes_session=${user}`,Origin:env.APP_ORIGIN,...(body && !(body instanceof FormData)?{'Content-Type':'application/json'}:{})},body:body instanceof FormData?body:body?JSON.stringify(body):undefined}),env,{})}
 return {sql,env,request,deleted};
}
test('lists, search, stats, tags, timeline and direct requests enforce ownership',async()=>{
 const f=fixture();
 for(const endpoint of ['/api/notes','/api/search?q=private']) {const data=await (await f.request(endpoint)).json();assert.deepEqual(data.notes.map(n=>n.id),[1]);assert.equal(data.notes[0].can_edit,true)}
 assert.equal((await (await f.request('/api/stats')).json()).memos,1);
 assert.deepEqual((await (await f.request('/api/tags')).json()).map(t=>t.name),['tag1']);
 const timeline=await (await f.request('/api/notes/timeline?timezone=UTC')).json();assert.equal(Object.values(timeline)[0].count,1);
 assert.equal((await f.request('/api/notes/2')).status,404);
 assert.equal((await f.request('/api/files/2/file')).status,404);
 assert.equal((await f.request('/api/notes/3')).status,404);
 assert.equal((await (await f.request('/api/notes','admin')).json()).notes.length,3);
});
test('admin grants view/edit, revokes access and assigns owner',async()=>{
 const f=fixture(); const path='/api/admin/notes/2/permissions';
 assert.equal((await f.request(path)).status,403);
 for (const edit of [false,true]) {
  assert.equal((await f.request(path,'admin','PUT',{owner_id:'bob',grants:[{user_id:'alice',can_edit:edit}]})).status,200);
  const body=new FormData();body.set('content','edited');
  assert.equal((await f.request('/api/notes/2','alice','PUT',body)).status,edit?200:403);
 }
 await f.request(path,'admin','PUT',{owner_id:'bob',grants:[]});assert.equal((await f.request('/api/notes/2')).status,404);
 await f.request(path,'admin','PUT',{owner_id:'alice',grants:[]});assert.equal((await f.request('/api/notes/2')).status,200);
});
test('member deletion hides only for that member and retains data until admin purge',async()=>{
 const f=fixture();f.sql.prepare('INSERT INTO note_permissions VALUES (1,?,0)').run('bob');
 assert.equal((await f.request('/api/notes/1','alice','DELETE')).status,204);
 assert.ok(f.sql.prepare('SELECT * FROM notes WHERE id=1').get());assert.deepEqual(f.deleted,[]);
 assert.equal((await f.request('/api/notes/1')).status,404);
 assert.equal((await f.request('/api/notes/1','bob')).status,200);
 assert.equal((await f.request('/api/notes/1','admin')).status,200);
 assert.equal((await (await f.request('/api/notes')).json()).notes.length,0);
 await f.request('/api/admin/notes/1/permissions','admin','PUT',{owner_id:'alice',grants:[],restore:['alice']});
 assert.equal((await f.request('/api/notes/1')).status,200);
 assert.equal((await f.request('/api/notes/1','admin','DELETE')).status,204);
 assert.equal(f.sql.prepare('SELECT * FROM notes WHERE id=1').get(),undefined);
});
test('new notes belong to creator, emptying does not delete, old sessions rejected',async()=>{
 const f=fixture(),body=new FormData();body.set('content','new note');
 const response=await f.request('/api/notes','bob','POST',body);assert.equal(response.status,201);assert.equal((await response.json()).owner_id,'bob');
 const empty=new FormData();empty.set('content','');assert.equal((await f.request('/api/notes/1','alice','PUT',empty)).status,400);
 assert.equal((await f.request('/api/notes','missing')).status,401);
 f.sql.exec('UPDATE auth_sessions SET expires_at=0');assert.equal((await f.request('/api/notes')).status,401);
});
test('bypass paths and cross-origin writes are blocked',async()=>{
 const f=fixture();
 for(const path of ['/api/public/note/foo','/api/public/file/foo','/api/tg-media-proxy/foo']) assert.equal((await f.request(path)).status,404);
 assert.equal((await f.request('/api/notes/2/share','alice','POST',{})).status,403);
 assert.equal((await f.request('/api/docs/tree')).status,403);
 assert.equal((await f.request('/api/notes/merge','alice','POST',{})).status,409);
 const response=await worker.fetch(new Request('https://n.markso.ng/api/notes/1',{method:'DELETE',headers:{Cookie:'__Host-notes_session=alice',Origin:'https://evil.test'}}),f.env,{});assert.equal(response.status,403);
});
test('signed identity rejects forged, expired, wrong audience/issuer/nonce and missing-group tokens',async()=>{
 const {privateKey,publicKey}=await generateKeyPair('RS256');
 const base={iss:'https://idp',aud:'client',sub:'alice',nonce:'nonce',groups:['notes'],iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+60};
 const sign=claims=>new SignJWT(claims).setProtectedHeader({alg:'RS256'}).sign(privateKey);
 const verify=token=>validateIdentity(token,publicKey,{issuer:'https://idp'},'client','nonce');
 assert.equal((await verify(await sign(base))).role,'member');assert.equal(roleFromClaims({groups:['notes_admin']}),'admin');
 for(const patch of [{iss:'https://evil'},{aud:'wrong'},{nonce:'wrong'},{groups:[]},{exp:1},{groups:'notes'},{azp:'wrong'}]) await assert.rejects(verify(await sign({...base,...patch})));
 const other=await generateKeyPair('RS256');await assert.rejects(verify(await new SignJWT(base).setProtectedHeader({alg:'RS256'}).sign(other.privateKey)));
});
test('malformed note IDs cannot bypass authorization; guessed media cannot be claimed',async()=>{
 const f=fixture();
 const body=new FormData();body.set('content','attack');
 assert.equal((await f.request('/api/notes/2suffix','alice','PUT',body)).status,400);
 assert.equal((await f.request('/api/files/2suffix/file')).status,400);
 f.sql.prepare('UPDATE notes SET content = ? WHERE id=2').run('![private](/api/images/secret-image)');
 assert.equal((await f.request('/api/images/secret-image')).status,404);
 const copy=new FormData();copy.set('content','![private](/api/images/secret-image)');
 assert.equal((await f.request('/api/notes','alice','POST',copy)).status,403);
 f.sql.prepare('INSERT INTO note_permissions VALUES (2,?,0)').run('alice');
 // Verify image visibility through the policy without requiring an R2 object.
 const { imageAllowed } = await import('../src/permissions.js');
 assert.equal(await imageAllowed('secret-image',{...f.env,user:{id:'alice',isAdmin:false}}),true);
 await f.request('/api/notes/2','alice','DELETE');
 assert.equal(await imageAllowed('secret-image',{...f.env,user:{id:'alice',isAdmin:false}}),false);
});
test('attachment listing excludes other users and hidden notes',async()=>{
 const f=fixture();
 for(const id of [1,2]) f.sql.prepare('UPDATE notes SET files=? WHERE id=?').run(JSON.stringify([{id:'file',name:'file.txt',size:1}]),id);
 let res=await f.request('/api/attachments');assert.equal(res.status,200);assert.deepEqual((await res.json()).attachments.map(a=>a.noteId),[1]);
 await f.request('/api/notes/1','alice','DELETE');res=await f.request('/api/attachments');assert.deepEqual((await res.json()).attachments,[]);
});
test('OIDC login uses PKCE and single-use state, creates a session and logs out',async()=>{
 const f=fixture();
 const { exportJWK }=await import('jose');
 const keys=await generateKeyPair('RS256');const jwk=await exportJWK(keys.publicKey);jwk.kid='key';jwk.alg='RS256';
 Object.assign(f.env,{OIDC_DISCOVERY_URL:'https://idp.test/discovery',OIDC_CLIENT_ID:'client',OIDC_CLIENT_SECRET:'test-only'});
 let nonce; const originalFetch=globalThis.fetch;
 globalThis.fetch=async(url,options)=>{
  const target=String(url);
  if(target.endsWith('/discovery')) return Response.json({issuer:'https://idp.test',authorization_endpoint:'https://idp.test/authorize',token_endpoint:'https://idp.test/token',jwks_uri:'https://idp.test/jwks'});
  if(target.endsWith('/jwks')) return Response.json({keys:[jwk]});
  if(target.endsWith('/token')) {
   assert.ok(options.body.get('code_verifier'));assert.equal(options.body.get('redirect_uri'),'https://n.markso.ng/api/auth/callback');
   return Response.json({id_token:await new SignJWT({nonce,groups:['notes_admin'],name:'SSO Admin'}).setProtectedHeader({alg:'RS256',kid:'key'}).setSubject('new-admin').setIssuer('https://idp.test').setAudience('client').setIssuedAt().setExpirationTime('5m').sign(keys.privateKey)});
  }
  throw new Error('Unexpected fetch '+target);
 };
 try {
  const login=await f.request('/api/auth/login');assert.equal(login.status,302);
  const target=new URL(login.headers.get('Location'));assert.equal(target.searchParams.get('code_challenge_method'),'S256');nonce=target.searchParams.get('nonce');
  const state=target.searchParams.get('state');const callback=`https://n.markso.ng/api/auth/callback?code=code&state=${state}`;
  const wrong=await worker.fetch(new Request(callback),f.env,{});assert.equal(wrong.status,400);
  const request=()=>new Request(callback,{headers:{Cookie:`__Host-notes_oidc=${state}`}});
  const response=await worker.fetch(request(),f.env,{});assert.equal(response.status,302);
  const session=response.headers.getSetCookie().find(c=>c.startsWith('__Host-notes_session=')).split(';')[0];
  const me=await worker.fetch(new Request('https://n.markso.ng/api/me',{headers:{Cookie:session}}),f.env,{});assert.equal((await me.json()).isAdmin,true);
  assert.equal((await worker.fetch(request(),f.env,{})).status,400);
  assert.equal((await worker.fetch(new Request('https://n.markso.ng/api/auth/logout',{method:'POST',headers:{Cookie:session,Origin:f.env.APP_ORIGIN}}),f.env,{})).status,200);
  assert.equal((await worker.fetch(new Request('https://n.markso.ng/api/me',{headers:{Cookie:session}}),f.env,{})).status,401);
 } finally {globalThis.fetch=originalFetch;}
});
test('public shares allow anonymous reading but only owners/admins may publish',async()=>{
 const f=fixture();f.sql.prepare('INSERT INTO note_permissions VALUES (2,?,1)').run('alice');
 assert.equal((await f.request('/api/notes/2/share','alice','POST',{})).status,403);
 const published=await f.request('/api/notes/1/share','alice','POST',{});assert.equal(published.status,200);
 const {publicId}=await published.json();
 const path=`/api/public/note/${publicId}`;
 assert.equal((await f.request(path,'anonymous')).status,200);
 assert.equal(await (await f.request(`/api/public/note/raw/${publicId}`,'anonymous')).text(),'private memo 1');
 for (const method of ['PUT','POST','DELETE']) assert.equal((await f.request(path,'anonymous',method,{})).status,405);
 const edit=new FormData();edit.set('content','not allowed');
 assert.equal((await f.request('/api/notes/1','anonymous','PUT',edit)).status,401);
 assert.equal((await f.request('/api/notes/2/share','admin','POST',{})).status,200);
 assert.equal((await f.request('/api/notes/3/share','admin','POST',{})).status,200);
 assert.equal((await (await f.request('/api/shares','alice')).json()).noteShares.length,1);
});
test('deletion flags revoke note and attachment shares, including admin sharing',async()=>{
 const f=fixture();f.sql.prepare('UPDATE notes SET files=? WHERE id=1').run(JSON.stringify([{id:'attachment',name:'a.txt',type:'text/plain'}]));
 f.env.NOTES_R2_BUCKET.get=async()=>({body:'file body',writeHttpMetadata:()=>{}});
 const {publicId}=await (await f.request('/api/notes/1/share','alice','POST',{})).json();
 const note=await (await f.request(`/api/public/note/${publicId}`,'anonymous')).json();
 const filePath=note.files[0].public_url;
 assert.equal((await f.request(filePath,'anonymous')).status,200);
 const separate=await (await f.request('/api/notes/1/files/attachment/share','alice','POST',{})).json();
 await f.request('/api/notes/1','alice','DELETE');
 for (const path of [`/api/public/note/${publicId}`,`/api/public/note/raw/${publicId}`,filePath,new URL(separate.url).pathname]) assert.equal((await f.request(path,'anonymous')).status,404);
 assert.equal((await f.request('/api/notes/1/share','admin','POST',{})).status,409);
 await f.request('/api/admin/notes/1/permissions','admin','PUT',{owner_id:'alice',grants:[],restore:['alice']});
 assert.equal((await f.request(`/api/public/note/${publicId}`,'anonymous')).status,404);
 assert.equal((await f.request('/api/notes/1/share','alice','POST',{})).status,200);
});
test('revocation and expiry apply to derived media links',async()=>{
 const f=fixture();f.sql.prepare('UPDATE notes SET content=? WHERE id=1').run('![image](/api/images/image-one)');
 f.env.NOTES_R2_BUCKET.get=async()=>({body:'image',writeHttpMetadata:()=>{}});
 const {publicId}=await (await f.request('/api/notes/1/share','alice','POST',{})).json();
 const note=await (await f.request(`/api/public/note/${publicId}`,'anonymous')).json();
 const media=note.content.match(/\/api\/public\/file\/[a-z0-9-]+/)[0];
 assert.equal((await f.request(media,'anonymous')).status,200);
 f.sql.prepare('UPDATE public_shares SET expires_at=1 WHERE token=?').run(publicId);
 assert.equal((await f.request(media,'anonymous')).status,404);
 f.sql.prepare('UPDATE public_shares SET expires_at=NULL WHERE token=?').run(publicId);
 await f.request('/api/notes/1/share','alice','DELETE');
 assert.equal((await f.request(media,'anonymous')).status,404);
 assert.equal((await f.request(`/api/public/note/${publicId}`,'anonymous')).status,404);
});
test('admin controls sharing immediately; disabled users cannot publish or self-enable',async()=>{
 const f=fixture();
 f.sql.prepare('UPDATE notes SET files=? WHERE id=1').run(JSON.stringify([{id:'file',name:'a.txt',type:'text/plain'}]));
 const owned=await (await f.request('/api/notes/1/share','alice','POST',{})).json();
 const admin=await (await f.request('/api/notes/1/share','admin','POST',{})).json();
 const file=await (await f.request('/api/notes/1/files/file/share','alice','POST',{})).json();
 assert.notEqual(owned.publicId,admin.publicId);
 const endpoint='/api/admin/users/alice/sharing';
 assert.equal((await f.request(endpoint,'alice','PUT',{can_share:false})).status,403);
 assert.equal((await f.request(endpoint,'admin','PUT',{can_share:'false'})).status,400);
 assert.equal((await f.request(endpoint,'admin','PUT',{can_share:false})).status,200);
 assert.equal((await (await f.request('/api/me','alice')).json()).canShare,false);
 assert.equal((await (await f.request('/api/notes/1','alice')).json()).can_share,false);
 assert.equal((await f.request('/api/notes/1/share','alice','POST',{})).status,403);
 assert.equal((await f.request('/api/notes/1/files/file/share','alice','POST',{})).status,403);
 assert.equal((await f.request(`/api/public/note/${owned.publicId}`,'anonymous')).status,404);
 assert.equal((await f.request(new URL(file.url).pathname,'anonymous')).status,404);
 assert.equal((await f.request(`/api/public/note/${admin.publicId}`,'anonymous')).status,200);
 assert.equal((await f.request('/api/notes/1/share','admin','POST',{})).status,200);
 await f.request(endpoint,'admin','PUT',{can_share:true});
 assert.equal((await f.request(`/api/public/note/${owned.publicId}`,'anonymous')).status,404);
 assert.equal((await f.request('/api/notes/1/share','alice','POST',{})).status,200);
 assert.equal((await f.request('/api/notes/2/share','alice','POST',{})).status,403);
});
