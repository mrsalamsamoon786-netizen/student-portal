const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) { console.error('SESSION_SECRET must be set to a random value of at least 32 characters.'); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL must be set.'); process.exit(1); }
const app = express();
const PORT = Number(process.env.PORT || 3000);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false } });

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '5mb' }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Please try again later.' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
if (process.env.FRONTEND_ORIGIN) app.use(cors({ origin: process.env.FRONTEND_ORIGIN, credentials: true }));

app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.CROSS_SITE_COOKIES === 'true' ? 'none' : 'lax',
    secure: process.env.CROSS_SITE_COOKIES === 'true' ? true : 'auto',
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

const clone = x => JSON.parse(JSON.stringify(x));
const uid = () => 'u' + crypto.randomBytes(9).toString('base64url');
const GRADES = ['Class 1','Class 2','Class 3','Class 4','Class 5','Class 6','Class 7','Class 8','Class 9','Matric'];
const defaultSeed = () => ({
  brand:{name:'My Academy',short:'MA',logo:'',c1:'#7c2ddb',c2:'#e8399b',c3:'#ff7a1a',acc:'#f97316',dark:false,footer:'All rights reserved.'},
  menu:[
    {id:'dashboard',label:'Dashboard',icon:'dashboard',on:true},{id:'courses',label:'My Courses',icon:'book',on:true},
    {id:'create',label:'Create Practice Test',icon:'bolt',on:true},{id:'history',label:'Test History',icon:'file',on:true},
    {id:'reports',label:'My MCQ Reports',icon:'chart',on:true},{id:'leaderboard',label:'Leaderboard',icon:'trophy',on:true},
    {id:'community',label:'Community',icon:'chat',on:true},{id:'notes',label:'Notes',icon:'note',on:true},
    {id:'videos',label:'Videos',icon:'video',on:true},{id:'papers',label:'Past Papers',icon:'paper',on:true},
    {id:'messages',label:'Messages',icon:'mail',on:true}
  ],
  subjects:[],assigned:[],courses:[],folders:[],papers:[],notes:[],messages:[],board:[],posts:[],
  community:{replies:0,helpful:0},tests:[],questions:[]
});

const GLOBAL=['brand','menu','subjects','board'];
const OWNED=['assigned','courses','folders','papers','notes','messages','questions'];
let ready;
async function ensureSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,username TEXT NOT NULL UNIQUE,role TEXT NOT NULL CHECK (role IN ('admin','student')),pin_hash TEXT NOT NULL,grade TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS portal_shared (id INTEGER PRIMARY KEY CHECK (id=1),data JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS student_progress (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,data JSONB NOT NULL DEFAULT '{}'::jsonb,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  const r=await pool.query('SELECT id FROM portal_shared WHERE id=1');
  if(!r.rowCount) await pool.query('INSERT INTO portal_shared(id,data) VALUES(1,$1)',[defaultSeed()]);
}
ready=ensureSchema().catch(e=>{console.error(e);process.exit(1)});

async function getShared(){ const r=await pool.query('SELECT data FROM portal_shared WHERE id=1'); return r.rows[0]?.data || defaultSeed(); }
async function getUser(id){ const r=await pool.query('SELECT id,name,username,role,grade FROM users WHERE id=$1',[id]); return r.rows[0] || null; }
async function getProgress(id){ const r=await pool.query('SELECT data FROM student_progress WHERE user_id=$1',[id]); return r.rows[0]?.data || {}; }
function safeSharedForStudent(shared, user){
  const out={};
  for(const k of GLOBAL) out[k]=clone(shared[k]);
  out.posts=clone(shared.posts||[]);
  for(const k of OWNED){
    let list=Array.isArray(shared[k])?shared[k]:[];
    out[k]=list.filter(i=>{const to=i?.to||'all'; if(to.startsWith('grade:')) return user.grade===to.slice(6); if(to.startsWith('stu:')) return user.id===to.slice(4); return true;});
  }
  return out;
}
function publicAccounts(rows){return rows.map(a=>({id:a.id,name:a.name,username:a.username,role:a.role,grade:a.grade||''}));}

async function stateFor(user){
  const shared=await getShared();
  if(user.role==='admin'){
    const users=(await pool.query('SELECT id,name,username,role,grade FROM users ORDER BY created_at')).rows;
    const progress={};
    const ps=(await pool.query('SELECT user_id,data FROM student_progress')).rows;
    for(const p of ps) progress[p.user_id]=p.data;
    return {v:1,accounts:publicAccounts(users),shared,progress,session:user.id};
  }
  const progress=await getProgress(user.id);
  return {v:1,accounts:[{id:user.id,name:user.name,username:user.username,role:user.role,grade:user.grade||''}],shared:safeSharedForStudent(shared,user),progress:{[user.id]:progress},session:user.id};
}
function auth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:'Not signed in'}); next(); }
async function admin(req,res,next){
  try{const u=await getUser(req.session.userId); if(!u||u.role!=='admin') return res.status(403).json({error:'Admin only'}); req.user=u; next();}catch(e){next(e)}
}

app.get('/api/health', async (req,res)=>{await ready; res.json({ok:true});});
app.get('/api/state', auth, async (req,res,next)=>{try{await ready; const u=await getUser(req.session.userId); if(!u)return res.status(401).json({error:'Session expired'}); res.json(await stateFor(u));}catch(e){next(e)}});
const passwordOk = p => typeof p === 'string' && p.length >= 10 && p.length <= 128 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
const passwordError = 'Password must be 10-128 characters and include uppercase, lowercase, number, and symbol.';


app.post('/api/setup', async (req,res,next)=>{try{await ready; const count=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin'"); if(count.rows[0].n) return res.status(409).json({error:'Admin already exists'}); const {name,username,password}=req.body; if(!name||!/^[a-z0-9_.-]{3,20}$/i.test(username||'')||!passwordOk(password)) return res.status(400).json({error:passwordError}); const id=uid(); const hash=await bcrypt.hash(password,12); await pool.query('INSERT INTO users(id,name,username,role,pin_hash) VALUES($1,$2,$3,$4,$5)',[id,name,username.toLowerCase(),'admin',hash]); req.session.userId=id; res.json(await stateFor({id,name,username:username.toLowerCase(),role:'admin',grade:''}));}catch(e){next(e)}});
app.post('/api/signup', async (req,res)=>res.status(403).json({error:'Student self-registration is disabled. Ask an Admin to create your account.'}));
app.post('/api/login', loginLimiter, async (req,res,next)=>{try{await ready; const {username,password,adminOnly}=req.body; const r=await pool.query('SELECT * FROM users WHERE username=$1',[String(username||'').trim().toLowerCase()]); const u=r.rows[0]; if(!u||!(await bcrypt.compare(String(password||''),u.pin_hash))) return res.status(401).json({error:'Wrong username or password'}); if(adminOnly&&u.role!=='admin')return res.status(403).json({error:'This is not an Admin account'}); if(!adminOnly&&u.role==='admin')return res.status(403).json({error:'Admins sign in from the Admin login tab'}); req.session.userId=u.id; res.json(await stateFor(u));}catch(e){next(e)}});
app.post('/api/logout', auth, (req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.put('/api/progress', auth, async (req,res,next)=>{try{await ready; const u=await getUser(req.session.userId); if(!u||u.role!=='student')return res.status(403).json({error:'Student only'}); const data=req.body?.data||{}; await pool.query(`INSERT INTO student_progress(user_id,data,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(user_id) DO UPDATE SET data=EXCLUDED.data,updated_at=NOW()`,[u.id,data]); res.json({ok:true});}catch(e){next(e)}});
const MAX_POSTS=500, MAX_POST_LEN=2000;
app.post('/api/posts', auth, async (req,res,next)=>{try{await ready; const u=await getUser(req.session.userId); if(!u)return res.status(401).json({error:'Session expired'}); const text=String(req.body?.text||'').trim(); if(!text)return res.status(400).json({error:'Write something first'}); if(text.length>MAX_POST_LEN)return res.status(400).json({error:'Post is too long'});
  const post={name:u.name,text};
  const r=await pool.query(`UPDATE portal_shared SET data=jsonb_set(data,'{posts}',(SELECT COALESCE(jsonb_agg(e ORDER BY n),'[]'::jsonb) FROM (SELECT e,n FROM jsonb_array_elements(jsonb_build_array($1::jsonb)||COALESCE(data->'posts','[]'::jsonb)) WITH ORDINALITY AS t(e,n) ORDER BY n LIMIT ${MAX_POSTS}) q)),updated_at=NOW() WHERE id=1 RETURNING data->'posts' AS posts`,[JSON.stringify(post)]);
  res.json({ok:true,posts:r.rows[0]?.posts||[]});}catch(e){next(e)}});

app.put('/api/admin/shared', admin, async (req,res,next)=>{try{await ready; const data=req.body?.data; if(!data||typeof data!=='object')return res.status(400).json({error:'Invalid shared data'}); delete data.posts; await pool.query("UPDATE portal_shared SET data=($1::jsonb)||jsonb_build_object('posts',COALESCE(data->'posts','[]'::jsonb)),updated_at=NOW() WHERE id=1",[JSON.stringify(data)]); res.json({ok:true});}catch(e){next(e)}});
app.post('/api/admin/accounts', admin, async (req,res,next)=>{try{const {name,username,password,role,grade=''}=req.body; if(!name||!/^[a-z0-9_.-]{3,20}$/i.test(username||'')||!passwordOk(password)||!['admin','student'].includes(role))return res.status(400).json({error:'Invalid account details'}); const id=uid(),hash=await bcrypt.hash(password,12); await pool.query('INSERT INTO users(id,name,username,role,pin_hash,grade) VALUES($1,$2,$3,$4,$5,$6)',[id,name,username.toLowerCase(),role,hash,grade||'']); res.json({ok:true,id});}catch(e){if(e.code==='23505')return res.status(409).json({error:'That username is already taken'});next(e)}});
app.patch('/api/admin/accounts/:id', admin, async (req,res,next)=>{try{const {grade,password}=req.body; if(password!==undefined&&!passwordOk(password))return res.status(400).json({error:passwordError}); if(password!==undefined){const h=await bcrypt.hash(password,12);await pool.query('UPDATE users SET pin_hash=$1 WHERE id=$2',[h,req.params.id]);} if(grade!==undefined)await pool.query('UPDATE users SET grade=$1 WHERE id=$2',[grade,req.params.id]);res.json({ok:true});}catch(e){next(e)}});
app.delete('/api/admin/accounts/:id', admin, async (req,res,next)=>{try{if(req.params.id===req.user.id)return res.status(400).json({error:'You cannot delete your current account'}); const r=await pool.query('SELECT role FROM users WHERE id=$1',[req.params.id]); if(!r.rowCount)return res.status(404).json({error:'Account not found'}); if(r.rows[0].role==='admin'){const n=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin'");if(n.rows[0].n<2)return res.status(400).json({error:'Keep at least one Admin'});} await pool.query('DELETE FROM users WHERE id=$1',[req.params.id]);res.json({ok:true});}catch(e){next(e)}});

app.get('/api/admin/backup', admin, async (req,res,next)=>{try{const s=await stateFor(req.user);res.json(s);}catch(e){next(e)}});
app.post('/api/admin/restore', admin, async (req,res)=>res.status(403).json({error:'Restore is disabled in this production build. Use database backups from your hosting provider.'}));

const frontend=path.join(__dirname,'..','frontend');
app.use(express.static(frontend));
app.get('/{*splat}',(req,res)=>res.sendFile(path.join(frontend,'index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Server error'});});
app.listen(PORT,()=>console.log(`Student Portal online server listening on :${PORT}`));
