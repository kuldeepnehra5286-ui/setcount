// Setcount backend: no packages needed, only Node.js 18+
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,DB=path.join(__dirname,'data.json');
const KEYS=['setcount.v1','setcount.custom','setcount.food','setcount.cal'];
let db={users:{},sessions:{}};
try{db=JSON.parse(fs.readFileSync(DB,'utf8'))}catch(e){}
function persist(){fs.writeFileSync(DB+'.tmp',JSON.stringify(db));fs.renameSync(DB+'.tmp',DB)}
const hash=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
const send=(res,code,obj)=>{res.writeHead(code,{'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'});res.end(code===204?undefined:JSON.stringify(obj))};
function body(req){return new Promise((ok,no)=>{let s='';req.on('data',c=>{s+=c;if(s.length>1e6){no(new Error('Data too large'));req.destroy()}});req.on('end',()=>{try{ok(JSON.parse(s||'{}'))}catch(e){no(new Error('Bad request'))}})})}
function session(req){const t=(req.headers.authorization||'').replace('Bearer ','');const e=db.sessions[t];return e&&db.users[e]?{t,e}:null}
http.createServer(async(req,res)=>{
  try{
    const u=req.url.split('?')[0];
    if(req.method==='OPTIONS')return send(res,204);
    if(u==='/'||u==='/index.html'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(fs.readFileSync(path.join(__dirname,'index.html')))}
    if(u==='/api/register'||u==='/api/login'){
      const{email,password}=await body(req);
      const em=String(email||'').trim().toLowerCase(),pw=String(password||'');
      if(!/^\S+@\S+\.\S+$/.test(em)||pw.length<6)return send(res,400,{error:'Enter a valid email and a password of 6 or more characters.'});
      if(u==='/api/register'){
        if(db.users[em])return send(res,409,{error:'This email already has an account. Sign in instead.'});
        const salt=crypto.randomBytes(16).toString('hex');db.users[em]={salt,hash:hash(pw,salt),data:{}};
      }else{
        const us=db.users[em];
        if(!us||!crypto.timingSafeEqual(Buffer.from(us.hash,'hex'),Buffer.from(hash(pw,us.salt),'hex')))return send(res,401,{error:'Wrong email or password.'});
      }
      const token=crypto.randomBytes(32).toString('hex');db.sessions[token]=em;persist();
      return send(res,200,{token,email:em});
    }
    const s=session(req);
    if(!s)return send(res,401,{error:'Please sign in again.'});
    if(u==='/api/data'&&req.method==='GET')return send(res,200,{data:db.users[s.e].data});
    if(u==='/api/data'&&req.method==='PUT'){const d=await body(req),clean={};KEYS.forEach(k=>{if(typeof d[k]==='string')clean[k]=d[k]});db.users[s.e].data=clean;persist();return send(res,200,{ok:true})}
    if(u==='/api/logout'){delete db.sessions[s.t];persist();return send(res,200,{ok:true})}
    send(res,404,{error:'Not found'});
  }catch(e){send(res,400,{error:e.message})}
}).listen(PORT,()=>console.log('Setcount running at http://localhost:'+PORT));
