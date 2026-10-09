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

const clone = x => x === undefined ? x : JSON.parse(JSON.stringify(x));
const uid = () => 'u' + crypto.randomBytes(9).toString('base64url');
const GRADES = ['Class 1','Class 2','Class 3','Class 4','Class 5','Class 6','Class 7','Class 8','Class 9','Matric'];

/* ===== Fixed subjects and chapters (1st Year + 2nd Year). Admin can edit chapters in the panel. ===== */
const FIXED_SUBJECTS=['Biology','Physics','Chemistry','Logical Reasoning','English'];
const chs=(y,a)=>a.map(n=>({y,n}));
const defaultChapters=()=>({
  'Biology':[...chs(1,['Introduction','Biological Molecules','Enzymes','The Cell','Variety of Life','Kingdom Prokaryotae','Kingdom Protoctista','Kingdom Fungi','Kingdom Plantae','Kingdom Animalia']),
    ...chs(2,['Bioenergetics','Nutrition','Gaseous Exchange','Transport','Homeostasis','Support and Movement','Coordination and Control','Reproduction','Growth and Development','Chromosomes and DNA','Cell Cycle','Variation and Genetics','Biotechnology','Evolution','Ecosystem','Man and his Environment'])],
  'Physics':[...chs(1,['Measurements','Vectors and Equilibrium','Motion and Force','Work and Energy','Circular Motion','Fluid Dynamics','Oscillations','Waves','Physical Optics','Optical Instruments','Heat and Thermodynamics']),
    ...chs(2,['Electrostatics','Current Electricity','Electromagnetism','Electromagnetic Induction','Alternating Current','Physics of Solids','Electronics','Dawn of Modern Physics','Atomic Spectra','Nuclear Physics'])],
  'Chemistry':[...chs(1,['Basic Concepts','Experimental Techniques','Gases','Liquids','Solids','Chemical Equilibrium','Reaction Kinetics','Thermochemistry','Electrochemistry','Chemical Bonding']),
    ...chs(2,['s and p Block Elements','Transition Elements','Fundamental Principles of Organic Chemistry','Chemistry of Hydrocarbons','Alkyl Halides','Alcohols and Phenols','Aldehydes and Ketones','Carboxylic Acids','Macromolecules','Common Industrial Chemicals','Environmental Chemistry'])],
  'Logical Reasoning':[...chs(1,['Critical Thinking','Letter and Symbol Series','Logical Problems','Course of Action']),...chs(2,['Logical Deductions','Making Judgments','Cause and Effect','Assumptions and Arguments'])],
  'English':[...chs(1,['Vocabulary (Synonyms and Antonyms)','Parts of Speech','Tenses','Spelling and Punctuation','Idioms and Phrases']),...chs(2,['Sentence Structure and Error Spotting','Active and Passive Voice','Direct and Indirect Speech','Sentence Completion','Comprehension'])]
});
const defaultSeed = () => ({
  brand:{name:'My Academy',short:'MA',logo:'',c1:'#7c2ddb',c2:'#e8399b',c3:'#ff7a1a',acc:'#f97316',dark:false,footer:'All rights reserved.'},
  profile:{adminName:'',position:'',phone:'',school:'',address:'',done:false},
  menu:[
    {id:'dashboard',label:'Dashboard',icon:'dashboard',on:true},{id:'courses',label:'My Courses',icon:'book',on:true},
    {id:'create',label:'Create Practice Test',icon:'bolt',on:true},{id:'history',label:'Test History',icon:'file',on:true},
    {id:'reports',label:'My MCQ Reports',icon:'chart',on:true},{id:'leaderboard',label:'Leaderboard',icon:'trophy',on:true},
    {id:'community',label:'Community',icon:'chat',on:true},{id:'notes',label:'Notes',icon:'note',on:true},
    {id:'videos',label:'Videos',icon:'video',on:true},{id:'papers',label:'Past Papers',icon:'paper',on:true},
    {id:'messages',label:'Messages',icon:'mail',on:true}
  ],
  subjects:[...FIXED_SUBJECTS],chapters:defaultChapters(),assigned:[],courses:[],folders:[],papers:[],notes:[],messages:[],board:[],posts:[],
  community:{replies:0,helpful:0},tests:[],questions:[]
});

const GLOBAL=['brand','profile','menu','subjects','chapters','board'];
const OWNED=['assigned','courses','folders','papers','notes','messages','questions'];
let ready;
async function ensureSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,username TEXT NOT NULL UNIQUE,role TEXT NOT NULL CHECK (role IN ('admin','student')),pin_hash TEXT NOT NULL,grade TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS portal_shared (id INTEGER PRIMARY KEY CHECK (id=1),data JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS student_progress (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,data JSONB NOT NULL DEFAULT '{}'::jsonb,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS weekly_papers (id TEXT PRIMARY KEY,title TEXT NOT NULL,subject TEXT NOT NULL DEFAULT '',minutes INTEGER NOT NULL DEFAULT 0,marks_per_q NUMERIC NOT NULL DEFAULT 1,pass_pct INTEGER NOT NULL DEFAULT 50,to_whom TEXT NOT NULL DEFAULT 'all',status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','closed')),show_answers BOOLEAN NOT NULL DEFAULT FALSE,shuffle BOOLEAN NOT NULL DEFAULT TRUE,questions JSONB NOT NULL DEFAULT '[]'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS weekly_attempts (id TEXT PRIMARY KEY,paper_id TEXT NOT NULL REFERENCES weekly_papers(id) ON DELETE CASCADE,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,q_order JSONB NOT NULL DEFAULT '[]'::jsonb,answers JSONB NOT NULL DEFAULT '[]'::jsonb,started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),submitted_at TIMESTAMPTZ,score NUMERIC,correct INTEGER,total INTEGER,late BOOLEAN NOT NULL DEFAULT FALSE,UNIQUE (paper_id,user_id));`);
  await pool.query(`ALTER TABLE weekly_papers ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'objective'`);
  await pool.query(`ALTER TABLE weekly_papers ADD COLUMN IF NOT EXISTS results_published BOOLEAN NOT NULL DEFAULT TRUE`);
  await pool.query(`ALTER TABLE weekly_attempts ADD COLUMN IF NOT EXISTS graded_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE weekly_attempts ADD COLUMN IF NOT EXISTS grading JSONB`);
  await pool.query(`ALTER TABLE weekly_attempts ADD COLUMN IF NOT EXISTS feedback TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mobile TEXT NOT NULL DEFAULT ''`);
  await pool.query(`CREATE TABLE IF NOT EXISTS password_resets (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,otp_hash TEXT NOT NULL,channel TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,token_hash TEXT,token_expires_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS note_files (id TEXT PRIMARY KEY,name TEXT NOT NULL,mime TEXT NOT NULL,size INTEGER NOT NULL,data BYTEA NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS q_images (id TEXT PRIMARY KEY,mime TEXT NOT NULL,size INTEGER NOT NULL,data BYTEA NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  const r=await pool.query('SELECT id FROM portal_shared WHERE id=1');
  if(!r.rowCount) await pool.query('INSERT INTO portal_shared(id,data) VALUES(1,$1)',[defaultSeed()]);
  /* one-time upgrade: fixed 5 subjects + chapters (only runs when 'chapters' is missing) */
  await pool.query(`UPDATE portal_shared SET data=data||jsonb_build_object('subjects',$1::jsonb,'chapters',$2::jsonb),updated_at=NOW() WHERE id=1 AND NOT (data ? 'chapters')`,[JSON.stringify(FIXED_SUBJECTS),JSON.stringify(defaultChapters())]);
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

app.get('/api/health', async (req,res)=>{await ready; let hasAdmin=true; try{const c=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin'"); hasAdmin=c.rows[0].n>0}catch(e){} res.json({ok:true,hasAdmin});});
app.get('/api/brand', async (req,res,next)=>{try{await ready; const sh=await getShared(); const b=sh.brand||{}; const pr=sh.profile||{}; res.json({name:b.name||'',short:b.short||'',logo:typeof b.logo==='string'&&b.logo.length<700000?b.logo:'',c1:b.c1,c2:b.c2,c3:b.c3,acc:b.acc,done:!!pr.done});}catch(e){next(e)}});
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

app.put('/api/admin/shared', admin, async (req,res,next)=>{try{await ready; const data=req.body?.data; if(!data||typeof data!=='object')return res.status(400).json({error:'Invalid shared data'}); delete data.posts; delete data.profile; if(data.brand&&typeof data.brand.logo==='string'&&data.brand.logo.length>700000)return res.status(400).json({error:'Logo is too large. Please upload a smaller image.'}); await pool.query("UPDATE portal_shared SET data=($1::jsonb)||jsonb_build_object('posts',COALESCE(data->'posts','[]'::jsonb))||CASE WHEN data ? 'profile' THEN jsonb_build_object('profile',data->'profile') ELSE '{}'::jsonb END,updated_at=NOW() WHERE id=1",[JSON.stringify(data)]);
  try{const keep=(Array.isArray(data.notes)?data.notes:[]).flatMap(n=>Array.isArray(n&&n.files)?n.files.map(f=>f&&f.id):[]).filter(Boolean);
    await pool.query("DELETE FROM note_files WHERE created_at<NOW()-INTERVAL '1 hour' AND NOT (id=ANY($1::text[]))",[keep]);}catch(e){console.error('note file cleanup',e.message)}
  qImgCleanup();
  res.json({ok:true});}catch(e){next(e)}});

app.put('/api/admin/school', admin, async (req,res,next)=>{try{await ready;
  const b=req.body||{}, t=(v,n)=>String(v==null?'':v).trim().slice(0,n);
  const school=t(b.school,120), adminName=t(b.adminName,80);
  if(!school) return res.status(400).json({error:'Enter the School / Academy name'});
  if(!adminName) return res.status(400).json({error:'Enter your name'});
  const logo=typeof b.logo==='string'?b.logo:'';
  if(logo&&(!/^data:image\/(png|jpe?g|webp|svg\+xml);base64,[A-Za-z0-9+\/=]+$/.test(logo)||logo.length>700000)) return res.status(400).json({error:'Logo is too large or not a valid image. Please upload a smaller image.'});
  const col=(v,d)=>/^#[0-9a-f]{6}$/i.test(String(v||''))?String(v):d;
  const short=(school.split(/\s+/).map(w=>w[0]).join('').slice(0,3)||school.slice(0,2)).toUpperCase();
  const cover=typeof b.cover==='string'?b.cover:'';
  if(cover&&(!/^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+\/=]+$/.test(cover)||cover.length>900000)) return res.status(400).json({error:'Cover photo is too large or not a valid image. Please choose a smaller image.'});
  const profile={adminName,position:t(b.position,80),phone:t(b.phone,40),school,address:t(b.address,300),cover,done:true};
  const brand={name:school,short,logo,footer:t(b.footer,200)||'All rights reserved.',c1:col(b.c1,'#7c2ddb'),c2:col(b.c2,'#e8399b'),c3:col(b.c3,'#ff7a1a'),acc:col(b.acc,'#f97316')};
  await pool.query("UPDATE portal_shared SET data=jsonb_set(jsonb_set(data,'{profile}',$1::jsonb,true),'{brand}',COALESCE(data->'brand','{}'::jsonb)||$2::jsonb,true),updated_at=NOW() WHERE id=1",[JSON.stringify(profile),JSON.stringify(brand)]);
  res.json({ok:true,profile,brand});
}catch(e){next(e)}});
app.post('/api/admin/accounts', admin, async (req,res,next)=>{try{const {name,username,password,role,grade=''}=req.body; if(!name||!/^[a-z0-9_.-]{3,20}$/i.test(username||'')||!passwordOk(password)||!['admin','student'].includes(role))return res.status(400).json({error:'Invalid account details'}); const id=uid(),hash=await bcrypt.hash(password,12); await pool.query('INSERT INTO users(id,name,username,role,pin_hash,grade) VALUES($1,$2,$3,$4,$5,$6)',[id,name,username.toLowerCase(),role,hash,grade||'']); res.json({ok:true,id});}catch(e){if(e.code==='23505')return res.status(409).json({error:'That username is already taken'});next(e)}});
app.patch('/api/admin/accounts/:id', admin, async (req,res,next)=>{try{const {grade,password}=req.body; if(password!==undefined&&!passwordOk(password))return res.status(400).json({error:passwordError}); if(password!==undefined){const h=await bcrypt.hash(password,12);await pool.query('UPDATE users SET pin_hash=$1 WHERE id=$2',[h,req.params.id]);} if(grade!==undefined)await pool.query('UPDATE users SET grade=$1 WHERE id=$2',[grade,req.params.id]);res.json({ok:true});}catch(e){next(e)}});
app.delete('/api/admin/accounts/:id', admin, async (req,res,next)=>{try{if(req.params.id===req.user.id)return res.status(400).json({error:'You cannot delete your current account'}); const r=await pool.query('SELECT role FROM users WHERE id=$1',[req.params.id]); if(!r.rowCount)return res.status(404).json({error:'Account not found'}); if(r.rows[0].role==='admin'){const n=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin'");if(n.rows[0].n<2)return res.status(400).json({error:'Keep at least one Admin'});} await pool.query('DELETE FROM users WHERE id=$1',[req.params.id]);res.json({ok:true});}catch(e){next(e)}});

app.get('/api/admin/backup', admin, async (req,res,next)=>{try{const s=await stateFor(req.user);res.json(s);}catch(e){next(e)}});
app.post('/api/admin/restore', admin, async (req,res)=>res.status(403).json({error:'Restore is disabled in this production build. Use database backups from your hosting provider.'}));


/* ===== WEEKLY TESTS (separate from the practice Question bank; graded on the server) ===== */
function httpErr(status,msg){const e=new Error(msg);e.status=status;return e}
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(e=>e&&e.status?res.status(e.status).json({error:e.message}):next(e));
const wid=()=>'w'+crypto.randomBytes(8).toString('base64url');
const wint=(v,lo,hi,d)=>{v=parseInt(v);return Number.isFinite(v)?Math.min(hi,Math.max(lo,v)):d};
app.use('/api/weekly',(req,res,next)=>{res.set('Cache-Control','no-store');next()});
function wVisible(to,user){to=to||'all';if(to.startsWith('grade:'))return user.grade===to.slice(6);if(to.startsWith('stu:'))return user.id===to.slice(4);return true}
const isSubj=p=>p&&p.kind==='subjective';
const wTotalMarks=p=>isSubj(p)?+p.questions.reduce((a,q)=>a+Number(q.marks||0),0).toFixed(2):+(p.questions.length*Number(p.marks_per_q)).toFixed(2);
function wCleanText(a,n){return Array.isArray(a)?a.slice(0,n).map(x=>String(x==null?'':x).slice(0,5000)):[]}
const wImgId=v=>{v=String(v||'');return /^q[A-Za-z0-9_-]{6,30}$/.test(v)?v:''};
const wImgs=q=>{const o={};for(const k of ['qi','i1','i2','i3','i4'])if(q&&q[k])o[k]=q[k];return o};
function wClean(list,kind){
  if(!Array.isArray(list))throw httpErr(400,'Questions must be a list');
  if(list.length>300)throw httpErr(400,'A paper can have at most 300 questions');
  if(kind==='subjective')return list.map((x,i)=>{
    const q=String(x&&x.q||'').trim().slice(0,2000),qi=wImgId(x&&x.qi);
    if(!q&&!qi)throw httpErr(400,'Question '+(i+1)+' needs the question text or a picture');
    const m=Number(x&&x.marks);
    if(!(m>=0.25&&m<=100))throw httpErr(400,'Question '+(i+1)+' needs marks between 0.25 and 100');
    return{q,marks:+m.toFixed(2),key:String(x&&x.key||'').trim().slice(0,3000),...(qi?{qi}:{})};
  });
  return list.map((x,i)=>{
    const q={q:String(x&&x.q||'').trim().slice(0,2000),o1:String(x&&x.o1||'').trim().slice(0,500),o2:String(x&&x.o2||'').trim().slice(0,500),o3:String(x&&x.o3||'').trim().slice(0,500),o4:String(x&&x.o4||'').trim().slice(0,500),ans:Number(x&&x.ans)};
    for(const k of ['qi','i1','i2','i3','i4']){const v=wImgId(x&&x[k]);if(v)q[k]=v}
    if(!(q.q||q.qi)||![1,2,3,4].every(n=>q['o'+n]||q['i'+n]))throw httpErr(400,'Question '+(i+1)+' needs the question (text or picture) and all 4 options (text or picture)');
    if(![1,2,3,4].includes(q.ans))throw httpErr(400,'Question '+(i+1)+' needs a correct option (A-D)');
    return q;
  });
}
const wAdminRow=r=>({resultsPublished:r.results_published!==false,assigned:r.assigned||0,kind:r.kind||'objective',ungraded:r.ungraded||0,id:r.id,title:r.title,subject:r.subject,minutes:r.minutes,marksPerQ:Number(r.marks_per_q),passPct:r.pass_pct,to:r.to_whom,status:r.status,showAnswers:r.show_answers,shuffle:r.shuffle,questions:r.questions,attempts:r.attempts||0,submitted:r.submitted||0});
function wShuffle(n){const a=[...Array(n).keys()];for(let i=a.length-1;i>0;i--){const j=crypto.randomInt(i+1);[a[i],a[j]]=[a[j],a[i]]}return a}
function wGrade(p,order,answers){
  let correct=0;const qs=p.questions;
  (order||[]).forEach((qi,pos)=>{if(qs[qi]&&Number(answers&&answers[pos])===qs[qi].ans)correct++});
  const total=qs.length,marks=Number(p.marks_per_q);
  return{correct,total,score:+(correct*marks).toFixed(2)};
}
const wDeadline=(p,att)=>p.minutes>0?new Date(att.started_at).getTime()+p.minutes*60000:0;
async function wFinalize(p,att,answers,late){
  if(isSubj(p)){
    await pool.query('UPDATE weekly_attempts SET answers=$1,total=$2,submitted_at=NOW(),late=$3 WHERE id=$4 AND submitted_at IS NULL',[JSON.stringify(wCleanText(answers,p.questions.length)),p.questions.length,!!late,att.id]);
    return null;
  }
  const g=wGrade(p,att.q_order,answers);
  await pool.query('UPDATE weekly_attempts SET answers=$1,score=$2,correct=$3,total=$4,submitted_at=NOW(),late=$5 WHERE id=$6 AND submitted_at IS NULL',[JSON.stringify(answers||[]),g.score,g.correct,g.total,!!late,att.id]);
  return g;
}
async function wExpireIfNeeded(p,att){
  if(att.submitted_at)return att;
  const dl=wDeadline(p,att);
  if(dl&&Date.now()>dl+5000){await wFinalize(p,att,att.answers,true);const r=await pool.query('SELECT * FROM weekly_attempts WHERE id=$1',[att.id]);return r.rows[0]}
  return att;
}
function wResult(p,att,review){
  if(isSubj(p)){
    const totalMarks=wTotalMarks(p),graded=!!att.graded_at;
    const out={kind:'subjective',pending:!graded,total:p.questions.length,totalMarks,passPct:p.pass_pct,late:!!att.late,submittedAt:att.submitted_at};
    if(graded){
      const score=Number(att.score||0),percent=totalMarks?Math.round(score/totalMarks*1000)/10:0;
      Object.assign(out,{score,percent,passed:percent>=p.pass_pct,feedback:att.feedback||''});
      if(review){const g=att.grading||{};out.review=p.questions.map((q,i)=>({...wImgs(q),q:q.q,marksMax:q.marks,answer:String((att.answers||[])[i]||''),awarded:Number((g.marks||[])[i]||0),comment:String((g.comments||[])[i]||''),key:p.show_answers?(q.key||''):''}))}
    }
    return out;
  }
  const total=att.total==null?p.questions.length:att.total,correct=att.correct||0,percent=total?Math.round(correct/total*1000)/10:0;
  const out={kind:'objective',correct,total,wrong:total-correct,score:Number(att.score||0),totalMarks:+(total*Number(p.marks_per_q)).toFixed(2),percent,passed:percent>=p.pass_pct,passPct:p.pass_pct,late:!!att.late,submittedAt:att.submitted_at};
  if(review&&p.show_answers)out.review=(att.q_order||[]).map((qi,pos)=>({...p.questions[qi],chosen:Number(att.answers&&att.answers[pos])||0}));
  return out;
}
/* Student ko result tab dikhta hai jab Admin publish kare */
function wStudentResult(p,att,review){
  if(p.results_published===false)return{hidden:true,kind:p.kind||'objective',late:!!att.late,submittedAt:att.submitted_at};
  return wResult(p,att,review);
}
async function wPaper(id){const r=await pool.query('SELECT * FROM weekly_papers WHERE id=$1',[id]);return r.rows[0]||null}
async function wAttempt(pid,uid){const r=await pool.query('SELECT * FROM weekly_attempts WHERE paper_id=$1 AND user_id=$2',[pid,uid]);return r.rows[0]||null}
const studentOnly=async(req,res,next)=>{try{const u=await getUser(req.session.userId);if(!u)return res.status(401).json({error:'Session expired'});if(u.role!=='student')return res.status(403).json({error:'Students only'});req.user=u;next()}catch(e){next(e)}};

/* ---- Admin: paper maker ---- */
/* Dashboard overview: har published/closed paper ke liye kitne students ko mila, kitno ne diya, kitne reh gaye, Pass / Fail */
app.get('/api/weekly/admin/overview',admin,wrap(async(req,res)=>{await ready;
  const papers=(await pool.query("SELECT * FROM weekly_papers WHERE status IN ('published','closed') ORDER BY created_at DESC")).rows;
  const studs=(await pool.query("SELECT id,name,username,grade FROM users WHERE role='student'")).rows;
  const out=[];
  for(const p of papers){
    const assigned=studs.filter(st=>wVisible(p.to_whom,st));
    const ids=new Set(assigned.map(x=>x.id));
    const rows=(await pool.query('SELECT * FROM weekly_attempts WHERE paper_id=$1',[p.id])).rows;
    let submitted=0,inProgress=0,pass=0,fail=0,pending=0;
    for(const r of rows){
      if(!ids.has(r.user_id))continue;
      const att=await wExpireIfNeeded(p,r);
      if(!att.submitted_at){inProgress++;continue}
      submitted++;
      const x=wResult(p,att,false);
      if(x.pending)pending++;else if(x.passed)pass++;else fail++;
    }
    out.push({id:p.id,title:p.title,subject:p.subject,kind:p.kind||'objective',status:p.status,assigned:assigned.length,attempted:submitted,inProgress,remaining:Math.max(0,assigned.length-submitted),pass,fail,pending});
  }
  const sum=k=>out.reduce((a,x)=>a+x[k],0);
  res.json({students:studs.length,papers:out,totals:{papers:out.length,assigned:sum('assigned'),attempted:sum('attempted'),remaining:sum('remaining'),inProgress:sum('inProgress'),pass:sum('pass'),fail:sum('fail'),pending:sum('pending')}});
}));
app.get('/api/weekly/admin',admin,wrap(async(req,res)=>{await ready;
  const r=await pool.query('SELECT p.*,(SELECT COUNT(*)::int FROM weekly_attempts a WHERE a.paper_id=p.id) AS attempts,(SELECT COUNT(*)::int FROM weekly_attempts a WHERE a.paper_id=p.id AND a.submitted_at IS NOT NULL) AS submitted,(SELECT COUNT(*)::int FROM weekly_attempts a WHERE a.paper_id=p.id AND a.submitted_at IS NOT NULL AND a.graded_at IS NULL) AS ungraded FROM weekly_papers p ORDER BY p.created_at DESC');
  const studs=(await pool.query("SELECT id,name,username,grade FROM users WHERE role='student'")).rows;
  res.json({papers:r.rows.map(x=>wAdminRow({...x,assigned:studs.filter(st=>wVisible(x.to_whom,st)).length}))});
}));
app.post('/api/weekly/admin',admin,wrap(async(req,res)=>{await ready;
  const b=req.body||{};
  const title=String(b.title||'').trim().slice(0,120);if(!title)throw httpErr(400,'Enter a paper title');
  const subject=String(b.subject||'').trim().slice(0,60);
  const minutes=wint(b.minutes,0,600,0),pass=wint(b.passPct,0,100,50);
  const marks=Math.min(100,Math.max(0.25,Number(b.marksPerQ)||1));
  const to=String(b.to||'all').slice(0,80);
  const status=['draft','published','closed'].includes(b.status)?b.status:'draft';
  const showAnswers=!!b.showAnswers,shuffle=b.shuffle!==false;
  const kind=b.kind==='subjective'?'subjective':'objective';
  const questions=wClean(b.questions||[],kind);
  if(status==='published'&&!questions.length)throw httpErr(400,'Add at least one question before publishing');
  let id=String(b.id||'');
  if(id){
    const ex=await wPaper(id);if(!ex)throw httpErr(404,'Paper not found');
    const n=(await pool.query('SELECT COUNT(*)::int AS n FROM weekly_attempts WHERE paper_id=$1',[id])).rows[0].n;
    if(n>0&&(ex.kind||'objective')!==kind)throw httpErr(409,'Students have already started this paper, so its type cannot be changed.');
    if(n>0&&JSON.stringify(ex.questions)!==JSON.stringify(questions))throw httpErr(409,'Students have already started this paper, so its questions cannot be changed. Duplicate the paper to make a new version.');
    await pool.query('UPDATE weekly_papers SET title=$1,subject=$2,minutes=$3,marks_per_q=$4,pass_pct=$5,to_whom=$6,status=$7,show_answers=$8,shuffle=$9,questions=$10,kind=$11,updated_at=NOW() WHERE id=$12',[title,subject,minutes,marks,pass,to,status,showAnswers,shuffle,JSON.stringify(questions),kind,id]);
  }else{
    id=wid();
    await pool.query('INSERT INTO weekly_papers(id,title,subject,minutes,marks_per_q,pass_pct,to_whom,status,show_answers,shuffle,questions,kind,results_published) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,false)',[id,title,subject,minutes,marks,pass,to,status,showAnswers,shuffle,JSON.stringify(questions),kind]);
  }
  qImgCleanup();
  res.json({ok:true,id});
}));
app.patch('/api/weekly/admin/:id/status',admin,wrap(async(req,res)=>{await ready;
  const status=String(req.body&&req.body.status||'');if(!['draft','published','closed'].includes(status))throw httpErr(400,'Invalid status');
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Paper not found');
  if(status==='published'&&!p.questions.length)throw httpErr(400,'Add at least one question before publishing');
  await pool.query('UPDATE weekly_papers SET status=$1,updated_at=NOW() WHERE id=$2',[status,p.id]);
  res.json({ok:true});
}));
app.post('/api/weekly/admin/:id/results-publish',admin,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Paper not found');
  const pub=!!(req.body&&req.body.publish);
  await pool.query('UPDATE weekly_papers SET results_published=$1,updated_at=NOW() WHERE id=$2',[pub,p.id]);
  res.json({ok:true,published:pub});
}));
app.delete('/api/weekly/admin/:id',admin,wrap(async(req,res)=>{await ready;await pool.query('DELETE FROM weekly_papers WHERE id=$1',[req.params.id]);qImgCleanup();res.json({ok:true})}));
app.get('/api/weekly/admin/:id/results',admin,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Paper not found');
  const rows=(await pool.query('SELECT a.*,u.name,u.username,u.grade FROM weekly_attempts a JOIN users u ON u.id=a.user_id WHERE a.paper_id=$1',[p.id])).rows;
  const attempts=[];
  for(const r of rows){
    const att=await wExpireIfNeeded(p,r),done=!!att.submitted_at;
    const base={userId:r.user_id,name:r.name,username:r.username,grade:r.grade||'',state:done?'submitted':'in_progress'};
    if(done){const x=wResult(p,att,false);if(x.pending)Object.assign(base,{pending:true,total:x.total,totalMarks:x.totalMarks,late:x.late,submittedAt:x.submittedAt});else Object.assign(base,{score:x.score,totalMarks:x.totalMarks,correct:x.correct,total:x.total,percent:x.percent,passed:x.passed,late:x.late,submittedAt:x.submittedAt})}
    attempts.push(base);
  }
  attempts.sort((a,b)=>(b.score==null?-1:b.score)-(a.score==null?-1:a.score));
  const taken=new Set(rows.map(r=>r.user_id));
  const left=(await pool.query("SELECT id,name,username,grade FROM users WHERE role='student' ORDER BY name")).rows.filter(s=>wVisible(p.to_whom,s)&&!taken.has(s.id)).map(s=>({id:s.id,name:s.name,grade:s.grade||''}));
  res.json({paper:{id:p.id,kind:p.kind||'objective',title:p.title,subject:p.subject,questionCount:p.questions.length,totalMarks:wTotalMarks(p),passPct:p.pass_pct,status:p.status,resultsPublished:p.results_published!==false,assigned:rows.length+left.length},attempts,notAttempted:left});
}));
app.delete('/api/weekly/admin/:id/attempts/:userId',admin,wrap(async(req,res)=>{await ready;await pool.query('DELETE FROM weekly_attempts WHERE paper_id=$1 AND user_id=$2',[req.params.id,req.params.userId]);res.json({ok:true})}));


/* ---- Admin: check a subjective paper ---- */
app.get('/api/weekly/admin/:id/attempts/:userId',admin,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Paper not found');
  if(!isSubj(p))throw httpErr(400,'This is an MCQ paper. It is checked automatically.');
  let att=await wAttempt(p.id,req.params.userId);if(!att)throw httpErr(404,'Attempt not found');
  att=await wExpireIfNeeded(p,att);if(!att.submitted_at)throw httpErr(409,'This student has not submitted yet.');
  const u=(await pool.query('SELECT name,username,grade FROM users WHERE id=$1',[req.params.userId])).rows[0]||{};
  const g=att.grading||{};
  res.json({paper:{id:p.id,title:p.title,subject:p.subject,totalMarks:wTotalMarks(p),passPct:p.pass_pct},student:{userId:att.user_id,name:u.name||'',username:u.username||'',grade:u.grade||''},late:!!att.late,submittedAt:att.submitted_at,graded:!!att.graded_at,feedback:att.feedback||'',
    questions:p.questions.map((q,i)=>({...wImgs(q),q:q.q,marks:q.marks,key:q.key||'',answer:String((att.answers||[])[i]||''),awarded:g.marks&&g.marks[i]!=null?Number(g.marks[i]):'',comment:String((g.comments||[])[i]||'')}))});
}));
app.put('/api/weekly/admin/:id/attempts/:userId',admin,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Paper not found');
  if(!isSubj(p))throw httpErr(400,'This is an MCQ paper. It is checked automatically.');
  let att=await wAttempt(p.id,req.params.userId);if(!att)throw httpErr(404,'Attempt not found');
  att=await wExpireIfNeeded(p,att);if(!att.submitted_at)throw httpErr(409,'This student has not submitted yet.');
  const b=req.body||{},marks=Array.isArray(b.marks)?b.marks:[],comments=Array.isArray(b.comments)?b.comments:[];
  const outM=[],outC=[];let score=0;
  for(let i=0;i<p.questions.length;i++){
    const raw=marks[i];if(raw===''||raw==null)throw httpErr(400,'Enter marks for question '+(i+1)+' (0 if none)');
    const m=Number(raw),max=Number(p.questions[i].marks);
    if(!Number.isFinite(m)||m<0||m>max)throw httpErr(400,'Question '+(i+1)+': marks must be between 0 and '+max);
    const r=+m.toFixed(2);outM.push(r);score+=r;outC.push(String(comments[i]||'').trim().slice(0,500));
  }
  await pool.query('UPDATE weekly_attempts SET score=$1,graded_at=NOW(),grading=$2,feedback=$3 WHERE id=$4 AND submitted_at IS NOT NULL',[+score.toFixed(2),JSON.stringify({marks:outM,comments:outC}),String(b.feedback||'').trim().slice(0,1000),att.id]);
  res.json({ok:true,score:+score.toFixed(2)});
}));

/* ---- Student: take the weekly test (answers never leave the server) ---- */
app.get('/api/weekly',auth,wrap(async(req,res,next)=>{await ready;
  const u=await getUser(req.session.userId);if(!u)return res.status(401).json({error:'Session expired'});
  if(u.role!=='student')return res.json({papers:[]});
  const ps=(await pool.query("SELECT * FROM weekly_papers WHERE status IN ('published','closed') ORDER BY created_at DESC")).rows.filter(p=>wVisible(p.to_whom,u));
  const out=[];
  for(const p of ps){
    let att=await wAttempt(p.id,u.id);if(att)att=await wExpireIfNeeded(p,att);
    const item={kind:p.kind||'objective',id:p.id,title:p.title,subject:p.subject,minutes:p.minutes,questionCount:p.questions.length,marksPerQ:Number(p.marks_per_q),totalMarks:wTotalMarks(p),passPct:p.pass_pct,status:p.status,state:'none'};
    if(att&&att.submitted_at){item.state='submitted';item.result=wStudentResult(p,att,false);item.pending=!!item.result.pending;item.canReview=item.result.hidden?false:(isSubj(p)?!item.result.pending:!!p.show_answers)}
    else if(att)item.state='in_progress';
    else if(p.status==='closed')item.state='closed';
    out.push(item);
  }
  res.json({papers:out});
}));
app.post('/api/weekly/:id/start',auth,studentOnly,wrap(async(req,res)=>{await ready;
  const u=req.user,p=await wPaper(req.params.id);
  if(!p||p.status==='draft'||!wVisible(p.to_whom,u))throw httpErr(404,'Test not found');
  let att=await wAttempt(p.id,u.id);if(att)att=await wExpireIfNeeded(p,att);
  if(att&&att.submitted_at)throw httpErr(409,'You have already taken this test.');
  if(!att){
    if(p.status!=='published')throw httpErr(403,'This test is closed.');
    if(!p.questions.length)throw httpErr(400,'This test has no questions yet.');
    const order=(p.shuffle&&!isSubj(p))?wShuffle(p.questions.length):[...p.questions.keys()];
    try{const r=await pool.query('INSERT INTO weekly_attempts(id,paper_id,user_id,q_order,answers) VALUES($1,$2,$3,$4,$5) RETURNING *',[wid(),p.id,u.id,JSON.stringify(order),'[]']);att=r.rows[0]}
    catch(e){if(e.code==='23505')att=await wAttempt(p.id,u.id);else throw e}
  }
  res.json({kind:p.kind||'objective',id:p.id,title:p.title,subject:p.subject,minutes:p.minutes,serverNow:Date.now(),endsAt:wDeadline(p,att),marksPerQ:Number(p.marks_per_q),answers:att.answers||[],
    questions:att.q_order.map(qi=>{const q=p.questions[qi];return isSubj(p)?{q:q.q,marks:q.marks,...wImgs(q)}:{q:q.q,o1:q.o1,o2:q.o2,o3:q.o3,o4:q.o4,...wImgs(q)}})});
}));
const wCleanAnswers=(a,n)=>Array.isArray(a)?a.slice(0,n).map(x=>{x=Number(x);return[1,2,3,4].includes(x)?x:0}):[];
app.post('/api/weekly/:id/save',auth,studentOnly,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Test not found');
  const ans=isSubj(p)?wCleanText(req.body&&req.body.answers,p.questions.length):wCleanAnswers(req.body&&req.body.answers,p.questions.length);
  await pool.query('UPDATE weekly_attempts SET answers=$1 WHERE paper_id=$2 AND user_id=$3 AND submitted_at IS NULL',[JSON.stringify(ans),p.id,req.user.id]);
  res.json({ok:true});
}));
app.post('/api/weekly/:id/submit',auth,studentOnly,wrap(async(req,res)=>{await ready;
  const u=req.user,p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Test not found');
  let att=await wAttempt(p.id,u.id);if(!att)throw httpErr(404,'You have not started this test.');
  if(!att.submitted_at){
    const posted=req.body&&req.body.answers,ans=Array.isArray(posted)?(isSubj(p)?wCleanText(posted,p.questions.length):wCleanAnswers(posted,p.questions.length)):(att.answers||[]);
    const dl=wDeadline(p,att),late=!!(dl&&Date.now()>dl+90000);
    await wFinalize(p,att,ans,late);
    att=await wAttempt(p.id,u.id);
  }
  res.json(wStudentResult(p,att,true));
}));
app.get('/api/weekly/:id/result',auth,studentOnly,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Test not found');
  const att=await wAttempt(p.id,req.user.id);if(!att||!att.submitted_at)throw httpErr(404,'No result yet');
  res.json(wStudentResult(p,att,true));
}));



/* ===== LEADERBOARD (real students, computed from saved progress) ===== */
app.get('/api/leaderboard', auth, wrap(async(req,res)=>{ await ready;
  res.set('Cache-Control','no-store');
  const rows=(await pool.query("SELECT u.id,u.name,sp.data FROM users u LEFT JOIN student_progress sp ON sp.user_id=u.id WHERE u.role='student'")).rows;
  const list=rows.map(r=>{
    const d=r.data||{}, pts=Number(d.user&&d.user.points)||0, tests=Array.isArray(d.tests)?d.tests.filter(t=>t&&t.status!=='In Progress'):[];
    const solved=tests.reduce((a,t)=>a+(Number(t.total)||0),0), correct=tests.reduce((a,t)=>a+(Number(t.correct)||0),0);
    return {id:r.id,name:r.name,score:pts,solved,acc:solved?Math.round(correct/solved*1000)/10:0};
  }).sort((a,b)=>b.score-a.score||b.acc-a.acc||a.name.localeCompare(b.name));
  /* Student ko dusre students ka naam/score nahi bheja jata: sirf apna row, rank aur total */
  const mine=list.findIndex(x=>x.id===req.session.userId);
  res.json({list:mine>=0?[list[mine]]:[],me:req.session.userId,rank:mine>=0?mine+1:null,total:list.length});
}));

/* ===== NOTE FILES (PDF / pictures stored in the database) ===== */
const NOTE_MAX=15*1024*1024;
function sniffFile(b){
  if(b.length<12)return null;
  if(b.slice(0,5).toString('latin1')==='%PDF-')return 'application/pdf';
  if(b[0]===0x89&&b.slice(1,4).toString('latin1')==='PNG')return 'image/png';
  if(b[0]===0xFF&&b[1]===0xD8&&b[2]===0xFF)return 'image/jpeg';
  if(b.slice(0,4).toString('latin1')==='RIFF'&&b.slice(8,12).toString('latin1')==='WEBP')return 'image/webp';
  if(b.slice(0,3).toString('latin1')==='GIF')return 'image/gif';
  return null;
}
app.post('/api/admin/note-files', admin, express.raw({type:()=>true,limit:NOTE_MAX}), wrap(async(req,res)=>{ await ready;
  const buf=req.body; if(!Buffer.isBuffer(buf)||!buf.length)throw httpErr(400,'No file received');
  const mime=sniffFile(buf); if(!mime)throw httpErr(400,'Only PDF, JPG, PNG, WEBP or GIF files are allowed');
  let name='file'; try{name=decodeURIComponent(String(req.get('x-file-name')||'file'))}catch(e){}
  name=name.replace(/[\\/\r\n"]/g,'_').slice(0,120)||'file';
  const id='f'+crypto.randomBytes(9).toString('base64url');
  await pool.query('INSERT INTO note_files(id,name,mime,size,data) VALUES($1,$2,$3,$4,$5)',[id,name,mime,buf.length,buf]);
  res.json({ok:true,file:{id,name,mime,size:buf.length}});
}));
app.get('/api/note-files/:id', auth, wrap(async(req,res)=>{ await ready;
  const u=await getUser(req.session.userId); if(!u)return res.status(401).json({error:'Session expired'});
  const f=(await pool.query('SELECT * FROM note_files WHERE id=$1',[req.params.id])).rows[0]; if(!f)throw httpErr(404,'File not found');
  if(u.role!=='admin'){
    const notes=(await getShared()).notes||[];
    const ok=notes.some(n=>Array.isArray(n.files)&&n.files.some(x=>x&&x.id===f.id)&&wVisible(n.to,u));
    if(!ok)throw httpErr(403,'You do not have access to this file');
  }
  res.set({'Content-Type':f.mime,'Content-Length':f.data.length,'Cache-Control':'private, max-age=3600','X-Content-Type-Options':'nosniff','Content-Disposition':`inline; filename="${f.name.replace(/[^\x20-\x7E]/g,'_')}"`});
  res.end(f.data);
}));
/* ===== QUESTION / OPTION DIAGRAM PICTURES (stored in the database) ===== */
const QIMG_MAX=6*1024*1024;
app.post('/api/admin/q-images', admin, express.raw({type:()=>true,limit:QIMG_MAX}), wrap(async(req,res)=>{ await ready;
  const buf=req.body; if(!Buffer.isBuffer(buf)||!buf.length)throw httpErr(400,'No picture received');
  const mime=sniffFile(buf); if(!mime||mime==='application/pdf')throw httpErr(400,'Only JPG, PNG, WEBP or GIF pictures are allowed');
  const id='q'+crypto.randomBytes(9).toString('base64url');
  await pool.query('INSERT INTO q_images(id,mime,size,data) VALUES($1,$2,$3,$4)',[id,mime,buf.length,buf]);
  res.json({ok:true,id});
}));
app.get('/api/q-images/:id', auth, wrap(async(req,res)=>{ await ready;
  const f=(await pool.query('SELECT mime,data FROM q_images WHERE id=$1',[req.params.id])).rows[0]; if(!f)throw httpErr(404,'Picture not found');
  res.set({'Content-Type':f.mime,'Content-Length':f.data.length,'Cache-Control':'private, max-age=86400','X-Content-Type-Options':'nosniff'});
  res.end(f.data);
}));
/* Removes pictures that no question uses any more (older than 1 hour, so a picture you just uploaded is safe) */
async function qImgCleanup(){
  try{
    const old=(await pool.query("SELECT id FROM q_images WHERE created_at<NOW()-INTERVAL '1 hour'")).rows.map(r=>r.id);
    if(!old.length)return;
    const blob=[
      JSON.stringify((await pool.query('SELECT data FROM portal_shared WHERE id=1')).rows[0]?.data||{}),
      (await pool.query('SELECT questions::text AS t FROM weekly_papers')).rows.map(r=>r.t).join('\n'),
      (await pool.query('SELECT data::text AS t FROM student_progress')).rows.map(r=>r.t).join('\n')
    ].join('\n');
    const dead=old.filter(id=>!blob.includes(id));
    if(dead.length)await pool.query('DELETE FROM q_images WHERE id=ANY($1::text[])',[dead]);
  }catch(e){console.error('q image cleanup',e.message)}
}
/* ===== ADMIN FORGOT PASSWORD (OTP via Email or Mobile) ===== */
const forgotLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Please try again later.' } });
const OTP_TTL_MIN = 10, OTP_MAX_TRIES = 5, OTP_COOLDOWN_SEC = 60, RESET_TOKEN_MIN = 15;
const hmac = v => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(String(v)).digest('hex');
const safeEq = (a,b) => { const x=Buffer.from(String(a)),y=Buffer.from(String(b)); return x.length===y.length && crypto.timingSafeEqual(x,y); };
const emailOk = e => typeof e==='string' && e.length<=120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const normMobile = m => { m=String(m||'').replace(/[\s\-()]/g,''); return /^\+?\d{10,15}$/.test(m) ? m : ''; };
const maskEmail = e => { const [a,d]=e.split('@'); return a.slice(0,2)+'***@'+d; };
const maskMobile = m => m.slice(0,3)+'*****'+m.slice(-2);

async function sendEmailOtp(to, otp, brandName){
  if(!process.env.SMTP_HOST){ if(process.env.NODE_ENV==='production') throw new Error('Email is not configured on the server.'); console.log(`[DEV] Email OTP for ${to}: ${otp}`); return; }
  let nodemailer; try{ nodemailer=require('nodemailer'); }catch(e){ throw new Error('Email service is not installed (npm i nodemailer).'); }
  const tx = nodemailer.createTransport({ host:process.env.SMTP_HOST, port:Number(process.env.SMTP_PORT||587), secure:process.env.SMTP_SECURE==='true', auth: process.env.SMTP_USER ? { user:process.env.SMTP_USER, pass:process.env.SMTP_PASS } : undefined });
  await tx.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject: `${brandName||'Portal'} - Admin password reset code`,
    text: `Your password reset code is ${otp}. It expires in ${OTP_TTL_MIN} minutes. If you did not request this, ignore this message.` });
}
async function sendSmsOtp(to, otp, brandName){
  const sid=process.env.TWILIO_ACCOUNT_SID, tok=process.env.TWILIO_AUTH_TOKEN, from=process.env.TWILIO_FROM;
  if(!sid||!tok||!from){ if(process.env.NODE_ENV==='production') throw new Error('SMS is not configured on the server.'); console.log(`[DEV] SMS OTP for ${to}: ${otp}`); return; }
  const body = new URLSearchParams({ To: to.startsWith('+')?to:'+'+to, From: from, Body: `${brandName||'Portal'}: your admin password reset code is ${otp}. Valid ${OTP_TTL_MIN} min.` });
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, { method:'POST', headers:{ Authorization:'Basic '+Buffer.from(sid+':'+tok).toString('base64'), 'Content-Type':'application/x-www-form-urlencoded' }, body });
  if(!r.ok) throw new Error('Could not send SMS.');
}

/* Admin saves recovery email / mobile (needed before OTP can be sent) */
app.get('/api/admin/recovery', admin, wrap(async(req,res)=>{ await ready; const r=await pool.query('SELECT email,mobile FROM users WHERE id=$1',[req.user.id]); res.json(r.rows[0]||{email:'',mobile:''}); }));
app.put('/api/admin/recovery', admin, wrap(async(req,res)=>{ await ready;
  const email=String(req.body?.email||'').trim().toLowerCase(), mobile=String(req.body?.mobile||'').trim();
  if(email&&!emailOk(email)) throw httpErr(400,'Enter a valid email address');
  const m=mobile?normMobile(mobile):''; if(mobile&&!m) throw httpErr(400,'Enter a valid mobile number with country code, e.g. +923001234567');
  await pool.query('UPDATE users SET email=$1,mobile=$2 WHERE id=$3',[email,m,req.user.id]);
  res.json({ok:true,email,mobile:m});
}));

/* Step 1: request OTP. Always answers the same way so usernames cannot be guessed. */
app.post('/api/auth/forgot/request', forgotLimiter, wrap(async(req,res)=>{ await ready;
  const username=String(req.body?.username||'').trim().toLowerCase(), channel=req.body?.channel==='mobile'?'mobile':'email';
  if(!username) throw httpErr(400,'Enter your Admin username');
  const generic={ok:true,message:'If this Admin account has a recovery '+(channel==='mobile'?'mobile number':'email')+' saved, a 6-digit code has been sent.'};
  const u=(await pool.query("SELECT id,email,mobile FROM users WHERE username=$1 AND role='admin'",[username])).rows[0];
  if(!u) return res.json(generic);
  const dest = channel==='mobile'?u.mobile:u.email;
  if(!dest) return res.json({...generic,noContact:true,message:'No recovery '+(channel==='mobile'?'mobile number':'email')+' is saved for this account. Try the other option or ask another Admin to reset your password.'});
  const prev=(await pool.query('SELECT created_at FROM password_resets WHERE user_id=$1',[u.id])).rows[0];
  if(prev && Date.now()-new Date(prev.created_at).getTime() < OTP_COOLDOWN_SEC*1000) throw httpErr(429,'Please wait a minute before requesting another code.');
  const otp=String(crypto.randomInt(0,1000000)).padStart(6,'0');
  await pool.query(`INSERT INTO password_resets(user_id,otp_hash,channel,expires_at,attempts,token_hash,token_expires_at,created_at) VALUES($1,$2,$3,NOW()+($4||' minutes')::interval,0,NULL,NULL,NOW()) ON CONFLICT(user_id) DO UPDATE SET otp_hash=EXCLUDED.otp_hash,channel=EXCLUDED.channel,expires_at=EXCLUDED.expires_at,attempts=0,token_hash=NULL,token_expires_at=NULL,created_at=NOW()`,[u.id,hmac(u.id+':'+otp),channel,String(OTP_TTL_MIN)]);
  const brand=(await getShared()).brand?.name||'';
  try{ channel==='mobile'?await sendSmsOtp(dest,otp,brand):await sendEmailOtp(dest,otp,brand); }
  catch(e){ await pool.query('DELETE FROM password_resets WHERE user_id=$1',[u.id]); console.error('OTP send failed:',e.message); throw httpErr(502,'Could not send the code right now. Please try again later or use the other option.'); }
  res.json({...generic,sentTo:channel==='mobile'?maskMobile(dest):maskEmail(dest)});
}));

/* Step 2: verify OTP -> short-lived reset token */
app.post('/api/auth/forgot/verify', forgotLimiter, wrap(async(req,res)=>{ await ready;
  const username=String(req.body?.username||'').trim().toLowerCase(), otp=String(req.body?.otp||'').trim();
  if(!/^\d{6}$/.test(otp)) throw httpErr(400,'Enter the 6-digit code');
  const u=(await pool.query("SELECT id FROM users WHERE username=$1 AND role='admin'",[username])).rows[0];
  const pr=u&&(await pool.query('SELECT * FROM password_resets WHERE user_id=$1',[u.id])).rows[0];
  if(!pr||new Date(pr.expires_at).getTime()<Date.now()) throw httpErr(400,'Code expired or not found. Please request a new code.');
  if(pr.attempts>=OTP_MAX_TRIES){ await pool.query('DELETE FROM password_resets WHERE user_id=$1',[u.id]); throw httpErr(429,'Too many wrong attempts. Please request a new code.'); }
  if(!safeEq(pr.otp_hash,hmac(u.id+':'+otp))){ await pool.query('UPDATE password_resets SET attempts=attempts+1 WHERE user_id=$1',[u.id]); throw httpErr(400,'Wrong code. '+(OTP_MAX_TRIES-pr.attempts-1)+' tries left.'); }
  const token=crypto.randomBytes(24).toString('base64url');
  await pool.query("UPDATE password_resets SET otp_hash='used',token_hash=$1,token_expires_at=NOW()+($2||' minutes')::interval WHERE user_id=$3",[hmac(token),String(RESET_TOKEN_MIN),u.id]);
  res.json({ok:true,token});
}));

/* Step 3: set the new password */
app.post('/api/auth/forgot/reset', forgotLimiter, wrap(async(req,res)=>{ await ready;
  const username=String(req.body?.username||'').trim().toLowerCase(), token=String(req.body?.token||''), password=req.body?.password;
  if(!passwordOk(password)) throw httpErr(400,passwordError);
  const u=(await pool.query("SELECT id FROM users WHERE username=$1 AND role='admin'",[username])).rows[0];
  const pr=u&&(await pool.query('SELECT * FROM password_resets WHERE user_id=$1',[u.id])).rows[0];
  if(!pr||!pr.token_hash||new Date(pr.token_expires_at).getTime()<Date.now()||!safeEq(pr.token_hash,hmac(token))) throw httpErr(400,'Reset session expired. Please start again.');
  const hash=await bcrypt.hash(password,12);
  await pool.query('UPDATE users SET pin_hash=$1 WHERE id=$2',[hash,u.id]);
  await pool.query('DELETE FROM password_resets WHERE user_id=$1',[u.id]);
  await pool.query("DELETE FROM user_sessions WHERE sess->>'userId'=$1",[u.id]).catch(()=>{});
  res.json({ok:true});
}));

const frontend=path.join(__dirname,'..','frontend');
app.use(express.static(frontend));
app.get('/{*splat}',(req,res)=>res.sendFile(path.join(frontend,'index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Server error'});});
app.listen(PORT,()=>console.log(`Student Portal online server listening on :${PORT}`));
