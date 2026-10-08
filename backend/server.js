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
  subjects:[],assigned:[],courses:[],folders:[],papers:[],notes:[],messages:[],board:[],posts:[],
  community:{replies:0,helpful:0},tests:[],questions:[]
});

const GLOBAL=['brand','profile','menu','subjects','board'];
const OWNED=['assigned','courses','folders','papers','notes','messages','questions'];
let ready;
async function ensureSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,username TEXT NOT NULL UNIQUE,role TEXT NOT NULL CHECK (role IN ('admin','student')),pin_hash TEXT NOT NULL,grade TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS portal_shared (id INTEGER PRIMARY KEY CHECK (id=1),data JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS student_progress (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,data JSONB NOT NULL DEFAULT '{}'::jsonb,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS weekly_papers (id TEXT PRIMARY KEY,title TEXT NOT NULL,subject TEXT NOT NULL DEFAULT '',minutes INTEGER NOT NULL DEFAULT 0,marks_per_q NUMERIC NOT NULL DEFAULT 1,pass_pct INTEGER NOT NULL DEFAULT 50,to_whom TEXT NOT NULL DEFAULT 'all',status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','closed')),show_answers BOOLEAN NOT NULL DEFAULT FALSE,shuffle BOOLEAN NOT NULL DEFAULT TRUE,questions JSONB NOT NULL DEFAULT '[]'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await pool.query(`CREATE TABLE IF NOT EXISTS weekly_attempts (id TEXT PRIMARY KEY,paper_id TEXT NOT NULL REFERENCES weekly_papers(id) ON DELETE CASCADE,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,q_order JSONB NOT NULL DEFAULT '[]'::jsonb,answers JSONB NOT NULL DEFAULT '[]'::jsonb,started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),submitted_at TIMESTAMPTZ,score NUMERIC,correct INTEGER,total INTEGER,late BOOLEAN NOT NULL DEFAULT FALSE,UNIQUE (paper_id,user_id));`);
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

app.get('/api/health', async (req,res)=>{await ready; let hasAdmin=true; try{const c=await pool.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin'"); hasAdmin=c.rows[0].n>0}catch(e){} res.json({ok:true,hasAdmin});});
app.get('/api/brand', async (req,res,next)=>{try{await ready; const sh=await getShared(); const b=sh.brand||{}; const pr=sh.profile||{}; res.json({name:b.name||'',short:b.short||'',logo:typeof b.logo==='string'&&b.logo.length<400000?b.logo:'',c1:b.c1,c2:b.c2,c3:b.c3,acc:b.acc,done:!!pr.done});}catch(e){next(e)}});
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

app.put('/api/admin/shared', admin, async (req,res,next)=>{try{await ready; const data=req.body?.data; if(!data||typeof data!=='object')return res.status(400).json({error:'Invalid shared data'}); delete data.posts; if(data.brand&&typeof data.brand.logo==='string'&&data.brand.logo.length>400000)return res.status(400).json({error:'Logo is too large. Please upload a smaller image.'}); await pool.query("UPDATE portal_shared SET data=($1::jsonb)||jsonb_build_object('posts',COALESCE(data->'posts','[]'::jsonb)),updated_at=NOW() WHERE id=1",[JSON.stringify(data)]); res.json({ok:true});}catch(e){next(e)}});
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
function wClean(list){
  if(!Array.isArray(list))throw httpErr(400,'Questions must be a list');
  if(list.length>300)throw httpErr(400,'A paper can have at most 300 questions');
  return list.map((x,i)=>{
    const q={q:String(x&&x.q||'').trim().slice(0,2000),o1:String(x&&x.o1||'').trim().slice(0,500),o2:String(x&&x.o2||'').trim().slice(0,500),o3:String(x&&x.o3||'').trim().slice(0,500),o4:String(x&&x.o4||'').trim().slice(0,500),ans:Number(x&&x.ans)};
    if(!q.q||!q.o1||!q.o2||!q.o3||!q.o4)throw httpErr(400,'Question '+(i+1)+' needs the question text and all 4 options');
    if(![1,2,3,4].includes(q.ans))throw httpErr(400,'Question '+(i+1)+' needs a correct option (A-D)');
    return q;
  });
}
const wAdminRow=r=>({id:r.id,title:r.title,subject:r.subject,minutes:r.minutes,marksPerQ:Number(r.marks_per_q),passPct:r.pass_pct,to:r.to_whom,status:r.status,showAnswers:r.show_answers,shuffle:r.shuffle,questions:r.questions,attempts:r.attempts||0,submitted:r.submitted||0});
function wShuffle(n){const a=[...Array(n).keys()];for(let i=a.length-1;i>0;i--){const j=crypto.randomInt(i+1);[a[i],a[j]]=[a[j],a[i]]}return a}
function wGrade(p,order,answers){
  let correct=0;const qs=p.questions;
  (order||[]).forEach((qi,pos)=>{if(qs[qi]&&Number(answers&&answers[pos])===qs[qi].ans)correct++});
  const total=qs.length,marks=Number(p.marks_per_q);
  return{correct,total,score:+(correct*marks).toFixed(2)};
}
const wDeadline=(p,att)=>p.minutes>0?new Date(att.started_at).getTime()+p.minutes*60000:0;
async function wFinalize(p,att,answers,late){
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
  const total=att.total==null?p.questions.length:att.total,correct=att.correct||0,percent=total?Math.round(correct/total*1000)/10:0;
  const out={correct,total,wrong:total-correct,score:Number(att.score||0),totalMarks:+(total*Number(p.marks_per_q)).toFixed(2),percent,passed:percent>=p.pass_pct,passPct:p.pass_pct,late:!!att.late,submittedAt:att.submitted_at};
  if(review&&p.show_answers)out.review=(att.q_order||[]).map((qi,pos)=>({...p.questions[qi],chosen:Number(att.answers&&att.answers[pos])||0}));
  return out;
}
async function wPaper(id){const r=await pool.query('SELECT * FROM weekly_papers WHERE id=$1',[id]);return r.rows[0]||null}
async function wAttempt(pid,uid){const r=await pool.query('SELECT * FROM weekly_attempts WHERE paper_id=$1 AND user_id=$2',[pid,uid]);return r.rows[0]||null}
const studentOnly=async(req,res,next)=>{try{const u=await getUser(req.session.userId);if(!u)return res.status(401).json({error:'Session expired'});if(u.role!=='student')return res.status(403).json({error:'Students only'});req.user=u;next()}catch(e){next(e)}};

/* ---- Admin: paper maker ---- */
app.get('/api/weekly/admin',admin,wrap(async(req,res)=>{await ready;
  const r=await pool.query('SELECT p.*,(SELECT COUNT(*)::int FROM weekly_attempts a WHERE a.paper_id=p.id) AS attempts,(SELECT COUNT(*)::int FROM weekly_attempts a WHERE a.paper_id=p.id AND a.submitted_at IS NOT NULL) AS submitted FROM weekly_papers p ORDER BY p.created_at DESC');
  res.json({papers:r.rows.map(wAdminRow)});
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
  const questions=wClean(b.questions||[]);
  if(status==='published'&&!questions.length)throw httpErr(400,'Add at least one question before publishing');
  let id=String(b.id||'');
  if(id){
    const ex=await wPaper(id);if(!ex)throw httpErr(404,'Paper not found');
    const n=(await pool.query('SELECT COUNT(*)::int AS n FROM weekly_attempts WHERE paper_id=$1',[id])).rows[0].n;
    if(n>0&&JSON.stringify(ex.questions)!==JSON.stringify(questions))throw httpErr(409,'Students have already started this paper, so its questions cannot be changed. Duplicate the paper to make a new version.');
    await pool.query('UPDATE weekly_papers SET title=$1,subject=$2,minutes=$3,marks_per_q=$4,pass_pct=$5,to_whom=$6,status=$7,show_answers=$8,shuffle=$9,questions=$10,updated_at=NOW() WHERE id=$11',[title,subject,minutes,marks,pass,to,status,showAnswers,shuffle,JSON.stringify(questions),id]);
  }else{
    id=wid();
    await pool.query('INSERT INTO weekly_papers(id,title,subject,minutes,marks_per_q,pass_pct,to_whom,status,show_answers,shuffle,questions) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[id,title,subject,minutes,marks,pass,to,status,showAnswers,shuffle,JSON.stringify(questions)]);
  }
  res.json({ok:true,id});
}));
app.patch('/api/weekly/admin/:id/status',admin,wrap(async(req,res)=>{await ready;
  const status=String(req.body&&req.body.status||'');if(!['draft','published','closed'].includes(status))throw httpErr(400,'Invalid status');
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Paper not found');
  if(status==='published'&&!p.questions.length)throw httpErr(400,'Add at least one question before publishing');
  await pool.query('UPDATE weekly_papers SET status=$1,updated_at=NOW() WHERE id=$2',[status,p.id]);
  res.json({ok:true});
}));
app.delete('/api/weekly/admin/:id',admin,wrap(async(req,res)=>{await ready;await pool.query('DELETE FROM weekly_papers WHERE id=$1',[req.params.id]);res.json({ok:true})}));
app.get('/api/weekly/admin/:id/results',admin,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Paper not found');
  const rows=(await pool.query('SELECT a.*,u.name,u.username,u.grade FROM weekly_attempts a JOIN users u ON u.id=a.user_id WHERE a.paper_id=$1',[p.id])).rows;
  const attempts=[];
  for(const r of rows){
    const att=await wExpireIfNeeded(p,r),done=!!att.submitted_at;
    const base={userId:r.user_id,name:r.name,username:r.username,grade:r.grade||'',state:done?'submitted':'in_progress'};
    if(done){const x=wResult(p,att,false);Object.assign(base,{score:x.score,totalMarks:x.totalMarks,correct:x.correct,total:x.total,percent:x.percent,passed:x.passed,late:x.late,submittedAt:x.submittedAt})}
    attempts.push(base);
  }
  attempts.sort((a,b)=>(b.score==null?-1:b.score)-(a.score==null?-1:a.score));
  const taken=new Set(rows.map(r=>r.user_id));
  const left=(await pool.query("SELECT id,name,username,grade FROM users WHERE role='student' ORDER BY name")).rows.filter(s=>wVisible(p.to_whom,s)&&!taken.has(s.id)).map(s=>({id:s.id,name:s.name,grade:s.grade||''}));
  res.json({paper:{id:p.id,title:p.title,subject:p.subject,questionCount:p.questions.length,totalMarks:+(p.questions.length*Number(p.marks_per_q)).toFixed(2),passPct:p.pass_pct,status:p.status},attempts,notAttempted:left});
}));
app.delete('/api/weekly/admin/:id/attempts/:userId',admin,wrap(async(req,res)=>{await ready;await pool.query('DELETE FROM weekly_attempts WHERE paper_id=$1 AND user_id=$2',[req.params.id,req.params.userId]);res.json({ok:true})}));

/* ---- Student: take the weekly test (answers never leave the server) ---- */
app.get('/api/weekly',auth,wrap(async(req,res,next)=>{await ready;
  const u=await getUser(req.session.userId);if(!u)return res.status(401).json({error:'Session expired'});
  if(u.role!=='student')return res.json({papers:[]});
  const ps=(await pool.query("SELECT * FROM weekly_papers WHERE status IN ('published','closed') ORDER BY created_at DESC")).rows.filter(p=>wVisible(p.to_whom,u));
  const out=[];
  for(const p of ps){
    let att=await wAttempt(p.id,u.id);if(att)att=await wExpireIfNeeded(p,att);
    const item={id:p.id,title:p.title,subject:p.subject,minutes:p.minutes,questionCount:p.questions.length,marksPerQ:Number(p.marks_per_q),totalMarks:+(p.questions.length*Number(p.marks_per_q)).toFixed(2),passPct:p.pass_pct,status:p.status,state:'none'};
    if(att&&att.submitted_at){item.state='submitted';item.result=wResult(p,att,false);item.canReview=!!p.show_answers}
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
    const order=p.shuffle?wShuffle(p.questions.length):[...p.questions.keys()];
    try{const r=await pool.query('INSERT INTO weekly_attempts(id,paper_id,user_id,q_order,answers) VALUES($1,$2,$3,$4,$5) RETURNING *',[wid(),p.id,u.id,JSON.stringify(order),'[]']);att=r.rows[0]}
    catch(e){if(e.code==='23505')att=await wAttempt(p.id,u.id);else throw e}
  }
  res.json({id:p.id,title:p.title,subject:p.subject,minutes:p.minutes,serverNow:Date.now(),endsAt:wDeadline(p,att),marksPerQ:Number(p.marks_per_q),answers:att.answers||[],
    questions:att.q_order.map(qi=>{const q=p.questions[qi];return{q:q.q,o1:q.o1,o2:q.o2,o3:q.o3,o4:q.o4}})});
}));
const wCleanAnswers=(a,n)=>Array.isArray(a)?a.slice(0,n).map(x=>{x=Number(x);return[1,2,3,4].includes(x)?x:0}):[];
app.post('/api/weekly/:id/save',auth,studentOnly,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Test not found');
  const ans=wCleanAnswers(req.body&&req.body.answers,p.questions.length);
  await pool.query('UPDATE weekly_attempts SET answers=$1 WHERE paper_id=$2 AND user_id=$3 AND submitted_at IS NULL',[JSON.stringify(ans),p.id,req.user.id]);
  res.json({ok:true});
}));
app.post('/api/weekly/:id/submit',auth,studentOnly,wrap(async(req,res)=>{await ready;
  const u=req.user,p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Test not found');
  let att=await wAttempt(p.id,u.id);if(!att)throw httpErr(404,'You have not started this test.');
  if(!att.submitted_at){
    const posted=req.body&&req.body.answers,ans=Array.isArray(posted)?wCleanAnswers(posted,p.questions.length):(att.answers||[]);
    const dl=wDeadline(p,att),late=!!(dl&&Date.now()>dl+90000);
    await wFinalize(p,att,ans,late);
    att=await wAttempt(p.id,u.id);
  }
  res.json(wResult(p,att,true));
}));
app.get('/api/weekly/:id/result',auth,studentOnly,wrap(async(req,res)=>{await ready;
  const p=await wPaper(req.params.id);if(!p)throw httpErr(404,'Test not found');
  const att=await wAttempt(p.id,req.user.id);if(!att||!att.submitted_at)throw httpErr(404,'No result yet');
  res.json(wResult(p,att,true));
}));

const frontend=path.join(__dirname,'..','frontend');
app.use(express.static(frontend));
app.get('/{*splat}',(req,res)=>res.sendFile(path.join(frontend,'index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Server error'});});
app.listen(PORT,()=>console.log(`Student Portal online server listening on :${PORT}`));
