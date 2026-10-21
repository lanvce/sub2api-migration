package main

// authorizeHTML is the self-contained authorize page served at /authorize.
// It talks only to same-origin /api/* endpoints and never embeds secrets.
const authorizeHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>香港站账户授权 · 余额迁移</title>
<style>
:root{--bg:#0b1220;--card:#121a2b;--line:#243049;--text:#e8eefc;--muted:#93a0b8;--pri:#4f8cff;--pri2:#3a6fd8;--ok:#22c55e;--err:#ef4444;--warn:#f59e0b}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:radial-gradient(1200px 600px at 20% -10%,#1a2744,transparent),var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:28px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
h1{margin:0 0 6px;font-size:20px;font-weight:650}p.lead{margin:0 0 22px;color:var(--muted);font-size:14px;line-height:1.55}
label{display:block;font-size:13px;color:var(--muted);margin:0 0 6px}
input{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:#0d1524;color:var(--text);font-size:15px;outline:none}
input:focus{border-color:var(--pri);box-shadow:0 0 0 3px rgba(79,140,255,.18)}
.field{margin-bottom:14px}
.btn{width:100%;border:0;border-radius:12px;padding:13px 16px;font-size:15px;font-weight:600;cursor:pointer;background:linear-gradient(180deg,var(--pri),var(--pri2));color:#fff}
.btn:disabled{opacity:.55;cursor:not-allowed}
.btn.secondary{background:#1a2438;border:1px solid var(--line);color:var(--text);margin-top:10px}
.msg{margin-top:14px;padding:12px 14px;border-radius:12px;font-size:13px;line-height:1.5;display:none}
.msg.err{display:block;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fecaca}
.msg.ok{display:block;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35);color:#bbf7d0}
.msg.warn{display:block;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.35);color:#fde68a}
.meta{margin:16px 0 0;padding:12px 14px;border-radius:12px;background:#0d1524;border:1px solid var(--line);font-size:13px;color:var(--muted)}
.meta b{color:var(--text);font-weight:600}
.step{display:none}.step.active{display:block}
.foot{margin-top:18px;font-size:12px;color:#6b7a94;text-align:center;line-height:1.5}
</style>
</head>
<body>
<div class="card">
  <h1>授权迁移余额</h1>
  <p class="lead">请使用香港站（旧系统）账号登录并确认授权。授权后将返回新站完成余额迁移；旧账户随后会被锁定。</p>

  <div id="boot" class="step active">
    <div class="msg warn" style="display:block">正在加载授权会话…</div>
  </div>

  <div id="login" class="step">
    <form id="loginForm">
      <div class="field">
        <label for="identifier">用户名或邮箱</label>
        <input id="identifier" name="identifier" autocomplete="username" required/>
      </div>
      <div class="field">
        <label for="password">密码</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required/>
      </div>
      <button class="btn" id="loginBtn" type="submit">登录并继续</button>
    </form>
    <div id="loginMsg" class="msg"></div>
  </div>

  <div id="confirm" class="step">
    <div class="meta">即将授权以下账户迁移余额：<br/>
      用户：<b id="uName">—</b><br/>
      邮箱：<b id="uEmail">—</b>
    </div>
    <p class="lead" style="margin-top:16px">确认后将返回新站。最终入账仍需您在新站再次点击「确认迁移」。</p>
    <button class="btn" id="approveBtn" type="button">确认授权并返回新站</button>
    <button class="btn secondary" id="backBtn" type="button">换一个账户</button>
    <div id="confirmMsg" class="msg"></div>
  </div>

  <div id="done" class="step">
    <div class="msg ok" style="display:block">授权成功，正在跳转回新站…</div>
  </div>

  <div id="fatal" class="step">
    <div id="fatalMsg" class="msg err" style="display:block">授权会话无效或已过期，请回到新站重新发起迁移。</div>
  </div>

  <div class="foot">仅用于跨站余额迁移 · 不会向新站传输您的密码</div>
</div>
<script>
(function(){
  const qs = new URLSearchParams(location.search);
  const migrationId = qs.get('migration_id') || '';
  const pageToken = qs.get('page_token') || '';
  const apiBase = (location.pathname.replace(/\/authorize\/?$/, '') || '') + '/api';
  const $ = (id) => document.getElementById(id);
  function show(id){
    ['boot','login','confirm','done','fatal'].forEach(s => $(s).classList.toggle('active', s===id));
  }
  function setMsg(el, type, text){
    el.className = 'msg ' + type;
    el.textContent = text;
    el.style.display = 'block';
  }
  async function api(path, opts){
    const res = await fetch(apiBase + path, Object.assign({headers:{'Content-Type':'application/json'}}, opts||{}));
    let body = null;
    try { body = await res.json(); } catch(e) { body = {}; }
    return {res, body};
  }
  async function boot(){
    if(!migrationId || !pageToken){ show('fatal'); return; }
    const {res, body} = await api('/session?migration_id='+encodeURIComponent(migrationId)+'&page_token='+encodeURIComponent(pageToken));
    if(!res.ok){
      $('fatalMsg').textContent = body && body.error === 'session_expired'
        ? '授权会话已过期，请回到新站重新发起迁移。'
        : '授权会话无效，请回到新站重新发起迁移。';
      show('fatal'); return;
    }
    if(body.status === 'logged_in' || body.status === 'approved'){
      $('uName').textContent = body.username || '—';
      $('uEmail').textContent = body.email || '—';
      show('confirm');
    } else {
      show('login');
    }
  }
  $('loginForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const btn = $('loginBtn'); btn.disabled = true;
    const {res, body} = await api('/login', {method:'POST', body: JSON.stringify({
      migration_id: migrationId, page_token: pageToken,
      identifier: $('identifier').value.trim(),
      password: $('password').value
    })});
    btn.disabled = false;
    if(!res.ok){
      const map = {
        invalid_credentials:'用户名或密码错误',
        account_locked:'该账户已在旧站被禁用（已手动迁移），无需再次迁移',
        account_disabled:'该账户已在旧站被禁用（已手动迁移），无需再次迁移',
        rate_limited:'尝试过于频繁，请稍后再试',
        too_many_attempts:'登录失败次数过多，请重新发起迁移',
        source_already_migrating:'该账户已有进行中的迁移',
        session_expired:'授权会话已过期，请回到新站重试',
        already_bound:'该会话已绑定其他账户'
      };
      setMsg($('loginMsg'),'err', map[body.error] || ('登录失败：'+(body.error||res.status)));
      return;
    }
    $('uName').textContent = body.username || '—';
    $('uEmail').textContent = body.email || '—';
    $('password').value = '';
    show('confirm');
  });
  $('approveBtn').addEventListener('click', async ()=>{
    const btn = $('approveBtn'); btn.disabled = true;
    const {res, body} = await api('/approve', {method:'POST', body: JSON.stringify({
      migration_id: migrationId, page_token: pageToken
    })});
    if(!res.ok){
      btn.disabled = false;
      setMsg($('confirmMsg'),'err','授权失败：'+(body.error||res.status));
      return;
    }
    show('done');
    location.href = body.redirect_url;
  });
  $('backBtn').addEventListener('click', ()=>{
    show('login');
    $('loginMsg').style.display='none';
  });
  boot().catch(()=>{ show('fatal'); });
})();
</script>
</body>
</html>
`
