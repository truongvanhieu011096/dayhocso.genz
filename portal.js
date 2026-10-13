/* Máy chủ cổng học sinh cho "Lớp văn thầy Hiếu" (Vercel Serverless Function)
 * Cần: Redis (Upstash, gắn từ tab Storage của Vercel) + biến môi trường PORTAL_ADMIN_KEY.
 * Học sinh chỉ nhận được dữ liệu của CHÍNH MÌNH; đáp án câu hỏi nằm trên máy chủ, chấm điểm ở máy chủ. */
const crypto = require('crypto');
const RURL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const RTOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const ADMIN = process.env.PORTAL_ADMIN_KEY || '';
const SECRET = crypto.createHash('sha256').update('tok:' + ADMIN).digest();
const MINS = [0, 10, 25, 45, 70, 100]; // phải khớp mốc điểm KR trong index.html
const KEY = 'lvth:portal', WAIT = 600000, TTL = 30 * 86400000;

async function rc(...cmd) {
  const r = await fetch(RURL, { method: 'POST', headers: { Authorization: 'Bearer ' + RTOK, 'Content-Type': 'application/json' }, body: JSON.stringify(cmd) });
  const j = await r.json(); if (j.error) throw new Error(j.error); return j.result;
}
const load = async () => { const v = await rc('GET', KEY); return v ? JSON.parse(v) : { users: {}, st: {}, dec: {}, qs: [] }; };
const store = d => rc('SET', KEY, JSON.stringify(d));
const eq = (a, b) => { a = Buffer.from(String(a || '')); b = Buffer.from(String(b || '')); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const hashpw = (pw, salt) => crypto.pbkdf2Sync(pw, salt, 100000, 32, 'sha256').toString('hex');
const DEF = '0000'; // mật khẩu mặc định của học sinh
const setPw = (u, pw, by) => { u.salt = crypto.randomBytes(16).toString('hex'); u.h = hashpw(pw, u.salt); u.pwBy = by; u.pwAt = Date.now(); return u; }; // by: default | admin | student
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const mkTok = (u, sid) => { const p = Buffer.from(JSON.stringify({ u, sid, exp: Date.now() + TTL })).toString('base64url'); return p + '.' + sign(p); };
function vfTok(t) {
  try { const [p, s] = String(t || '').split('.'); if (!p || !s || !eq(s, sign(p))) return null; const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch (e) { return null; }
}
const vn = () => new Date(Date.now() + 7 * 3600e3).toISOString().slice(0, 10);
const shuf = a => { a = [...a]; for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
const view = (d, sid, x) => { const s = d.st[sid]; return { pwd: !!(x && x.pwBy === 'default'), n: s.n, cls: s.cls, k1: s.k1 || [], k2: s.k2 || [], goal: s.goal ?? null, cg: s.cg, att: s.att, go: s.go, gn: s.gn, kp: s.kp, kr: s.kr, kd: s.kd, dec: d.dec[s.cid] || '', today: vn(), wait: Math.max(0, (s.kf || 0) + WAIT - Date.now()) }; };
const bad = (res, code, msg) => res.status(code).json({ error: msg });

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return bad(res, 405, 'Method not allowed');
  if (!ADMIN || !RURL || !RTOK) return bad(res, 500, 'Máy chủ chưa cấu hình (thiếu PORTAL_ADMIN_KEY hoặc Redis)');
  let b; try { b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {}); } catch (e) { return bad(res, 400, 'Dữ liệu không hợp lệ'); }
  try {
    const A = b.action;
    /* ---------- Giáo viên ---------- */
    if (['push', 'setpw', 'resetpw', 'adj'].includes(A)) {
      if (!eq(b.key, ADMIN)) return bad(res, 401, 'Sai khoá quản trị');
      const d = await load();
      if (A === 'push') {
        const st = {};
        for (const [sid, v] of Object.entries(b.st || {})) {
          const o = d.st[sid];
          st[sid] = { n: String(v.n || ''), cls: String(v.cls || ''), cid: String(v.cid || ''), k1: v.k1 || [], k2: v.k2 || [], goal: v.goal ?? null, cg: +v.cg || 8, att: String(v.att || ''), go: +v.go || 0, gn: +v.gn || 0,
            kp: o ? o.kp : (+v.kp || 0), kr: o ? o.kr : Math.min(5, Math.max(0, +v.kr || 0)), kd: o ? o.kd : String(v.kd || ''), kf: o ? o.kf : (+v.kf || 0) };
        }
        const users = {};
        for (const x of b.users || []) { const o = d.users[x.u]; const n = { ...(o && o.sid === x.sid ? o : { sid: x.sid }), off: !!x.off }; if (!n.h) setPw(n, DEF, 'default'); users[x.u] = n; } // tài khoản mới tự có mật khẩu 0000
        d.st = st; d.users = users; d.dec = b.dec || {}; d.qs = Array.isArray(b.qs) ? b.qs : [];
        await store(d);
        const kv = {}; for (const [sid, v] of Object.entries(st)) kv[sid] = { kp: v.kp, kr: v.kr, kd: v.kd, kf: v.kf };
        const pw = {}; for (const [u, v] of Object.entries(users)) pw[u] = { by: v.pwBy || '', at: v.pwAt || 0 };
        return res.json({ ok: 1, kv, pw });
      }
      if (A === 'setpw') {
        const pw = String(b.pw || ''); if (!b.u || !b.sid || pw.length < 4) return bad(res, 400, 'Thiếu thông tin tài khoản');
        const salt = crypto.randomBytes(16).toString('hex');
        d.users[b.u] = { sid: b.sid, salt, h: hashpw(pw, salt), pwBy: pw === DEF ? 'default' : 'admin', pwAt: Date.now() };
        await store(d); return res.json({ ok: 1 });
      }
      if (A === 'resetpw') { // Admin đặt lại mật khẩu về 0000 (một hoặc nhiều học sinh)
        const list = (Array.isArray(b.list) ? b.list : [{ u: b.u, sid: b.sid }]).filter(i => i && i.u);
        let n = 0;
        for (const it of list) {
          const o = d.users[it.u], sid = it.sid || (o && o.sid); if (!sid) continue;
          d.users[it.u] = setPw({ sid, ...(o && o.sid === sid && o.off ? { off: true } : {}) }, DEF, 'default'); n++;
        }
        if (!n) return bad(res, 400, 'Thiếu thông tin tài khoản');
        await store(d);
        await rc('DEL', ...list.flatMap(i => ['rl:' + i.u, 'rc:' + i.u])); // gỡ khoá đăng nhập sai nếu có
        return res.json({ ok: 1, n });
      }
      const s = d.st[b.sid]; if (!s) return bad(res, 404, 'Học sinh chưa có trên máy chủ');
      if (b.dp != null) s.kp = Math.max(0, s.kp + (parseInt(b.dp) || 0));
      if (b.rank != null) s.kr = Math.min(5, Math.max(0, parseInt(b.rank) || 0));
      await store(d); return res.json({ ok: 1, kp: s.kp, kr: s.kr });
    }
    /* ---------- Đăng nhập học sinh ---------- */
    if (A === 'login') {
      const u = String(b.u || '').trim().toLowerCase(), k = 'rl:' + u;
      const n = await rc('INCR', k); if (n === 1) await rc('EXPIRE', k, 600);
      if (n > 10) return bad(res, 429, 'Sai quá nhiều lần, hãy thử lại sau 10 phút');
      const d = await load(), x = d.users[u];
      if (!x || !x.h || !eq(hashpw(String(b.p || ''), x.salt), x.h) || !d.st[x.sid]) return bad(res, 401, 'Sai tên hoặc mật khẩu');
      if (x.off) return bad(res, 403, 'Tài khoản đang bị đình chỉ, hãy liên hệ thầy Hiếu');
      await rc('DEL', k);
      return res.json({ token: mkTok(u, x.sid), u, name: d.st[x.sid].n, st: view(d, x.sid, x) });
    }
    /* ---------- Học sinh (cần token) ---------- */
    const t = vfTok(b.token); if (!t) return bad(res, 401, 'Phiên đăng nhập hết hạn, hãy đăng nhập lại');
    const d = await load(), x = d.users[t.u];
    if (!x || x.sid !== t.sid || !d.st[t.sid]) return bad(res, 401, 'Tài khoản không còn hiệu lực');
    if (x.off) return bad(res, 401, 'Tài khoản đang bị đình chỉ');
    const s = d.st[t.sid], today = vn();
    if (A === 'me') return res.json({ u: t.u, name: s.n, st: view(d, t.sid, x) });
    if (A === 'chpw') { // Học sinh tự đổi mật khẩu
      const op = String(b.op || ''), np = String(b.np || '');
      if (np.length < 4 || np.length > 64) return bad(res, 400, 'Mật khẩu mới phải từ 4 đến 64 ký tự');
      if (np === DEF) return bad(res, 400, 'Không được dùng mật khẩu mặc định 0000');
      if (np === op) return bad(res, 400, 'Mật khẩu mới phải khác mật khẩu cũ');
      const k = 'rc:' + t.u, n = await rc('INCR', k); if (n === 1) await rc('EXPIRE', k, 600);
      if (n > 5) return bad(res, 429, 'Nhập sai quá nhiều lần, hãy thử lại sau 10 phút');
      if (!x.h || !eq(hashpw(op, x.salt), x.h)) return bad(res, 400, 'Mật khẩu hiện tại không đúng');
      setPw(x, np, 'student'); await store(d); await rc('DEL', k);
      return res.json({ ok: 1, st: view(d, t.sid, x) });
    }
    if (A === 'qstart') {
      const kind = b.kind, rk = s.kr, qs = d.qs || []; let pool, n;
      if (kind === 'daily') {
        if (s.kd === today) return bad(res, 400, 'Hôm nay em đã làm thử thách rồi');
        pool = qs.filter(q => q.lv <= rk + 1); n = 3;
      } else if (kind === 'test') {
        if (rk >= 5) return bad(res, 400, 'Em đã đạt cấp cao nhất');
        if (s.kp < MINS[rk + 1]) return bad(res, 400, 'Chưa đủ điểm để thi thăng chức');
        if (Date.now() - (s.kf || 0) < WAIT) return bad(res, 400, 'Hãy chờ đủ 10 phút để thi lại');
        pool = qs.filter(q => q.lv === rk + 1); if (pool.length < 3) pool = qs; n = 5;
      } else return bad(res, 400, 'Yêu cầu không hợp lệ');
      if (!pool || !pool.length) pool = qs;
      if (!pool.length) return bad(res, 400, 'Chưa có câu hỏi nào');
      const items = shuf(pool).slice(0, n).map(q => { const o = shuf(q.o.map((tx, i) => [tx, i])); return { q: q.q, o: o.map(z => z[0]), c: o.findIndex(z => z[1] === q.a) }; });
      await rc('SET', 'pq:' + t.sid, JSON.stringify({ kind, items }), 'EX', 3600);
      return res.json({ title: kind === 'daily' ? 'Thử thách ngày' : 'Thi thăng chức', qs: items.map(i => ({ q: i.q, o: i.o })) });
    }
    if (A === 'qsubmit') {
      const raw = await rc('GETDEL', 'pq:' + t.sid); if (!raw) return bad(res, 400, 'Phiên làm bài đã hết hạn, hãy bắt đầu lại');
      const { kind, items } = JSON.parse(raw), ans = Array.isArray(b.ans) ? b.ans : [];
      const ok = items.filter((it, i) => ans[i] === it.c).length, tot = items.length, res0 = { kind, ok, t: tot };
      if (kind === 'daily') {
        if (s.kd === today) return bad(res, 400, 'Hôm nay em đã làm thử thách rồi');
        s.kd = today; s.kp += ok; res0.gain = ok;
      } else {
        const rk = s.kr; if (rk >= 5 || s.kp < MINS[rk + 1] || Date.now() - (s.kf || 0) < WAIT) return bad(res, 400, 'Hiện chưa thể thi thăng chức');
        const need = Math.ceil(tot * .8); res0.need = need;
        if (ok >= need) { s.kr = rk + 1; res0.pass = true; } else { s.kf = Date.now(); res0.pass = false; }
      }
      await store(d); return res.json({ st: view(d, t.sid, x), res: res0 });
    }
    return bad(res, 400, 'Yêu cầu không hợp lệ');
  } catch (e) { console.error('portal error', e); return bad(res, 500, 'Lỗi máy chủ'); }
};
