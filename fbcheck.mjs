#!/usr/bin/env node
/**
 * fbcheck — Firebase 公開前チェック（日本語）
 *
 * AIに作ってもらったアプリを公開する前に、実際に漏れた事例と同じ形の穴が
 * 空いていないかを、自分の目で確認できる形で出します。
 *
 * 使い方:  node fbcheck.mjs [プロジェクトのパス]
 * 依存なし。ネットワークに出ません。あなたのPCの中のファイルしか読みません。
 * 判定の本体（ENGINE の区間）は、ブラウザ版と同じ文字列です。
 */

import fs from "node:fs";
import path from "node:path";

/* ENGINE:BEGIN — fbcheck の判定本体。CLI（fbcheck.mjs）とブラウザ版で、この区間は同じ文字列を使う。 */
const FBCHECK_VERSION = "0.2";
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".nuxt", ".cache", ".vercel",
  ".firebase", "coverage", ".turbo", ".svelte-kit", "vendor",
]);
const TEXT_EXT = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
  ".json", ".env", ".html", ".rules", ".yml", ".yaml", ".txt", ".md",
]);
const MAX_BYTES = 2 * 1024 * 1024;
const BUNDLE_DIRS = ["dist", "build", "out", "public", ".output"];
// 見本として Git に入れる前提の .env（中身は本物の鍵を入れない約束のファイル）
const TEMPLATE_ENV = /^\.env\.(example|sample|template|dist|defaults)$/i;
const PUBLIC_PREFIX = "(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)";
const SECRETS = [
  { name: "Firebase サービスアカウント鍵", re: /"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "秘密鍵（PEM）", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: "Stripe 本番シークレットキー", re: /\bsk_live_[A-Za-z0-9]{16,}/ },
  { name: "Stripe テストシークレットキー", re: /\bsk_test_[A-Za-z0-9]{16,}/ },
  { name: "Anthropic APIキー", re: /\bsk-ant-[A-Za-z0-9\-_]{20,}/ },
  { name: "OpenAI APIキー", re: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}/ },
  { name: "AWS アクセスキー", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub トークン", re: /\bgh[pousr]_[A-Za-z0-9]{30,}/ },
  { name: "Slack トークン", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "SendGrid APIキー", re: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}/ },
];

const extOf = (n) => { const i = n.lastIndexOf("."); return i > 0 ? n.slice(i) : ""; };
const mask = (s) => (s.length <= 12 ? s.slice(0, 4) + "…" : s.slice(0, 6) + "…" + s.slice(-4));
const evText = (e) => (e.loc && e.code != null ? `${e.loc}  ${e.code}` : e.loc ? `${e.loc}${e.note || ""}` : e.note);

// 行番号つきで正規表現ヒットを返す
function matchLines(text, re) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(re);
    if (m) hits.push({ line: i + 1, text: lines[i].trim(), match: m[0] });
  }
  return hits;
}

// ---------- ルールの読み取り（Firestore / Storage） ----------

const READ_OPS = new Set(["read", "get", "list"]);
const WRITE_OPS = new Set(["write", "create", "update", "delete"]);
const opFamily = (ops) => {
  const r = ops.some((o) => READ_OPS.has(o)), w = ops.some((o) => WRITE_OPS.has(o));
  return r && w ? "rw" : r ? "r" : w ? "w" : "";
};
const STATE = { rw: "読み書きできる", r: "読める", w: "書き込める", "": "操作できる" };
const VERB = { rw: "読み書きできます", r: "読めます", w: "書き込めます", "": "操作できます" };
const OPS_JA = (ops) => ops.map((o) => `${o}（${READ_OPS.has(o) ? "読み取り" : WRITE_OPS.has(o) ? "書き込み" : "?"}）`).join("・");

// 各行について、その行の allow が入っている match の並び（外側から）を返す。// のコメントは無視。
function matchChains(text) {
  const lines = text.split(/\r?\n/);
  const out = new Array(lines.length);
  const stack = [];
  let depth = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\/\/.*$/, "");
    const at = line.search(/\ballow\b/);
    let recorded = null;
    const re = /\bmatch\s+(\/(?:[^\s{}]|\{[^}\s]*\})*)\s*\{|\{|\}/g;
    let m;
    while ((m = re.exec(line))) {
      if (at >= 0 && recorded === null && m.index > at) recorded = stack.map((s) => s.path);
      if (m[1] !== undefined) { depth++; stack.push({ path: m[1], depth }); }
      else if (m[0] === "{") depth++;
      else { while (stack.length && stack[stack.length - 1].depth >= depth) stack.pop(); depth = Math.max(0, depth - 1); }
    }
    out[i] = recorded !== null ? recorded : stack.map((s) => s.path);
  }
  return out;
}
// サービスの入口（/databases/{database}/documents・/b/{bucket}/o）の直下が {x=**} なら「すべて」に効く
const isWholeScope = (chain) =>
  /^\/(databases\/\{[^}]+\}\/documents|b\/\{[^}]+\}\/o)\/\{[^}=]+=\*\*\}$/.test(chain.join(""));
const ownerVar = (chain) => {
  for (const p of chain) for (const m of p.matchAll(/\{([A-Za-z_]\w*)(=\*\*)?\}/g)) if (/user|uid|owner|author|member|account/i.test(m[1])) return m[1];
  return null;
};
// 1行の中の allow 文を取り出す：[{ ops, cond }]
function allowsIn(line) {
  const out = [];
  const re = /allow\s+([a-z,\s]+?)\s*:\s*if\s+([^;}]*)/g;
  let m;
  while ((m = re.exec(line.replace(/\/\/.*$/, "")))) {
    out.push({ ops: m[1].split(",").map((s) => s.trim()).filter(Boolean), cond: m[2].trim() });
  }
  return out;
}
const COND_TRUE = /^true\s*(\|\||$)/;
const COND_AUTH = /^request\.auth\s*!=\s*null$/;
const COND_TEST = /^request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)$/;

// Realtime Database のルール JSON から、条件なしの true を探す
function rtdbTrues(node, path, out) {
  if (!node || typeof node !== "object") return out;
  for (const [k, v] of Object.entries(node)) {
    const p = path ? path + "/" + k : k;
    if ((k === ".read" || k === ".write") && (v === true || (typeof v === "string" && v.trim() === "true"))) {
      out.push({ path: p, op: k === ".read" ? "read" : "write", top: path === "rules" });
    } else if (v && typeof v === "object") rtdbTrues(v, p, out);
  }
  return out;
}

// ---------- .gitignore（プロジェクト直下の1枚だけ・分かる書き方だけ） ----------

function globToRegex(p) {
  let s = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") {
      if (p[i + 1] === "*" && (i === 0 || p[i - 1] === "/") && (p[i + 2] === "/" || i + 2 === p.length)) {
        if (p[i + 2] === "/") { s += "(?:.*/)?"; i += 2; } else { s += ".*"; i += 1; }
        continue;
      }
      if (p[i + 1] === "*") i += 1;
      s += "[^/]*";
    } else if (c === "?") s += "[^/]";
    else s += c.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return new RegExp("^" + s + "$");
}
// このファイルが除外されていると「言い切れる」時だけ covered: true。分からない時は false（安全側）。
function gitignoreCovers(gi, rel) {
  if (gi == null) return { covered: false, reason: "プロジェクト直下に .gitignore が見つからない" };
  const segs = rel.split("/");
  let ignored = false, blocked = null;
  for (const raw of gi.split(/\r?\n/)) {
    let line = raw.replace(/\s+$/, "");
    if (!line || line.startsWith("#")) continue;
    let neg = false;
    if (line.startsWith("!")) { neg = true; line = line.slice(1); }
    const dirOnly = line.endsWith("/");
    line = line.replace(/\/+$/, "");
    if (!line) continue;
    if (/[\[\]\\]/.test(line)) {
      if (/env/i.test(line)) blocked = blocked || "読み取れない書き方（[ ] や \\ を使った行）がある";
      continue;
    }
    const anchored = line.includes("/");
    const rx = globToRegex(line.replace(/^\/+/, ""));
    const upto = dirOnly ? segs.length - 1 : segs.length;
    let hit = false;
    for (let k = 0; k < upto && !hit; k++) hit = anchored ? rx.test(segs.slice(0, k + 1).join("/")) : rx.test(segs[k]);
    if (!hit) continue;
    if (neg) blocked = "! で除外を打ち消す行がある";
    else ignored = true;
  }
  if (ignored && !blocked) return { covered: true };
  return { covered: false, reason: blocked || (segs.length > 1 ? "直下の .gitignore に除外する行が見つからない（下の階層の .gitignore は見ていない）" : "除外する行が見つからない") };
}

// ---------- 判定 ----------
// P = { files: [{ rel, name }]（rel は / 区切り・並び順どおりに判定）, texts: Map(rel → 中身|null), gitignore: 直下の .gitignore の中身|null }
function runChecks(P) {
  const findings = { danger: [], warn: [], info: [], ok: [] };
  const add = (level, f) => findings[level].push({ ...f, kind: level });
  const read = (rel) => (P.texts.has(rel) ? P.texts.get(rel) : null);

  // 0. Firebase を使っているか
  const reasons = [];
  for (const f of P.files) {
    const b = f.name;
    if (b === "firebase.json") reasons.push("firebase.json");
    if (b === ".firebaserc") reasons.push(".firebaserc");
    if (b.endsWith(".rules") || b === "database.rules.json") reasons.push(f.rel);
    if (b === "package.json") {
      const t = read(f.rel);
      if (t && /"(firebase|firebase-admin|firebase-tools|@angular\/fire|react-firebase\S*)"\s*:/.test(t)) reasons.push("package.json の依存に firebase");
    }
  }
  if (!reasons.length) {
    for (const f of P.files) {
      const t = read(f.rel);
      if (!t) continue;
      if (/from\s+["']firebase\/|require\(["']firebase|firebaseConfig\s*=|FIREBASE_[A-Z_]+\s*=/.test(t)) { reasons.push(`${f.rel} に firebase の記述`); break; }
    }
  }
  const fb = [...new Set(reasons)];

  // 1. セキュリティルール
  const ruleFiles = P.files.filter((f) => f.name.endsWith(".rules") || f.name === "database.rules.json");
  const hasFirebaseJson = P.files.some((f) => f.name === "firebase.json");
  if (ruleFiles.length === 0) {
    if (fb.length) add("danger", {
      title: "セキュリティルールのファイルが見つかりません",
      why: "Firestore / Storage は「誰が何を読み書きしてよいか」をルールで決めます。ファイルが無い場合、コンソールで設定したルールがそのまま生きています。テストモードのまま公開すると、データベース全体を誰でも読める状態になります。",
      how: "Firebase コンソール →（Firestore Database / Storage）→「ルール」タブを開いて、今の中身を確かめてください。中身を AI に貼って「このルールで、誰が何を読めるか1行ずつ説明して」と聞くと、何が起きるかが分かります。",
      evidence: [{ note: hasFirebaseJson ? "firebase.json はあるのに .rules ファイルが無い＝ルールがコード管理されていない" : "プロジェクト内に *.rules / database.rules.json が1つも見つからない" }],
    });
  }
  for (const f of ruleFiles) {
    const text = read(f.rel);
    if (text == null) continue;
    if (f.name === "database.rules.json") {
      let json = null;
      try { json = JSON.parse(text); } catch (e) { json = null; }
      if (!json) continue;
      const trues = rtdbTrues(json, "", []);
      if (!trues.length) continue;
      const fam = opFamily(trues.map((t) => t.op));
      const top = trues.filter((t) => t.top);
      const ev = trues.map((t) => ({ loc: f.rel, code: `${t.path} = true` }));
      const why = `".read" / ".write" に true を書いた場所は、条件なしで許可されます（ログインも不要）。許可されている操作：${OPS_JA([...new Set(trues.map((t) => t.op))])}。`;
      if (top.length) add("danger", { title: `Realtime Database 全体を、誰でも${STATE[opFamily(top.map((t) => t.op))]}状態です（${f.rel}）`, why, how: "rules の直下の true を外し、場所ごとに認証と持ち主のチェックを入れます。", evidence: ev });
      else if (trues.some((t) => t.op === "write")) add("danger", { title: `Realtime Database に、誰でも${STATE[fam]}場所があります（${f.rel}）`, why, how: "書き込みは、認証と持ち主のチェックを入れた条件に変えます。", evidence: ev });
      else add("warn", { title: `Realtime Database に、誰でも読める場所があります（${f.rel}）`, why: why + "公開してよいデータなら、このままで問題ありません。", how: "個人のデータが入る場所なら、認証と持ち主のチェックを入れます。", evidence: ev });
      continue;
    }
    const noun = /firebase\.storage/.test(text) ? "ファイル" : "文書";
    const chains = matchChains(text);
    const lines = text.split(/\r?\n/);
    const G = { anyoneHard: [], anyoneSoft: [], authAll: [], authPart: [] };
    const tests = [];
    for (let i = 0; i < lines.length; i++) {
      for (const a of allowsIn(lines[i])) {
        const whole = isWholeScope(chains[i]);
        const ev = { loc: `${f.rel}:${i + 1}`, code: lines[i].trim(), ops: a.ops, chain: chains[i] };
        if (COND_TRUE.test(a.cond)) {
          ev.mark = "if " + a.cond.replace(/\s*\|\|.*$/, "");
          (opFamily(a.ops).includes("w") || whole ? G.anyoneHard : G.anyoneSoft).push(ev);
        } else if (COND_AUTH.test(a.cond)) {
          ev.mark = a.cond;
          (whole ? G.authAll : G.authPart).push(ev);
        } else {
          const t = a.cond.match(COND_TEST);
          if (t) { ev.mark = a.cond; tests.push({ ev, y: +t[1], m: +t[2], d: +t[3] }); }
        }
      }
    }
    const fam = (list) => opFamily(list.flatMap((e) => e.ops));
    const opsOf = (list) => OPS_JA([...new Set(list.flatMap((e) => e.ops))]);
    const strip = (list) => list.map(({ loc, code, mark }) => ({ loc, code, mark }));
    if (G.anyoneHard.length) add("danger", {
      title: `誰でも${STATE[fam(G.anyoneHard)]}状態です（${f.rel}）`,
      why: `\`if true\` は条件なしで許可するという意味です。ログインも不要で、URL さえ分かれば誰でも行えます。ブラウザの開発者ツールで接続先が見えるので、URL は隠せません。許可されている操作：${opsOf(G.anyoneHard)}。`,
      how: "この行を、そのデータの持ち主だけが触れる条件に書き換えます。AI に頼むときは「どのデータを、誰に見せたいか」を一緒に伝えてください。書き直したら、もう一度確かめてください。",
      evidence: strip(G.anyoneHard),
    });
    if (G.anyoneSoft.length) add("warn", {
      title: `誰でも読める場所があります（${f.rel}）`,
      why: `\`if true\` は条件なしで許可するという意味です。この行で許可されているのは読み取り（${[...new Set(G.anyoneSoft.flatMap((e) => e.ops))].join("・")}）だけで、ログインも不要です。公開してよいデータなら、このままで問題ありません。`,
      how: "個人のデータや、見せたくないデータが入る場所なら、認証と持ち主のチェックを入れます。",
      evidence: strip(G.anyoneSoft),
    });
    if (G.authAll.length) add("danger", {
      title: `ログインすれば、すべての${noun}を${VERB[fam(G.authAll)]}（${f.rel}）`,
      why: `\`request.auth != null\` は「ログインしていれば誰でも許可」という条件です。この行は {…=**} の下にあるので、すべての${noun}に効きます。Firebase Authentication で誰でも新規登録できる設定なら、アカウントを1つ作るだけで、ほかの人のデータにも届きます。許可されている操作：${opsOf(G.authAll)}。`,
      how: "データの種類ごとに match を分け、ユーザーごとのデータには持ち主のチェック（例：`request.auth.uid == userId`）を入れます。AI に頼むときは、コレクションの構成と「誰に何を見せたいか」を一緒に伝えてください。",
      evidence: strip(G.authAll),
    });
    if (G.authPart.length) {
      const v = G.authPart.map((e) => ownerVar(e.chain)).find(Boolean);
      add("warn", {
        title: `ログインしている人なら誰でも${STATE[fam(G.authPart)]}場所があります（${f.rel}）`,
        why: `\`request.auth != null\` は「ログインしていれば誰でも許可」という条件です。全員で共有するデータなら、これで意図どおりです。ユーザーごとのデータ（本人だけに見せたいもの）なら、持ち主のチェックが足りません。` + (v ? `この場所はパスに {${v}} があるので、ユーザーごとのデータに見えます。` : "") + `許可されている操作：${opsOf(G.authPart)}。`,
        how: `ユーザーごとのデータなら、持ち主のチェックを足します。例：\n\`allow read, write: if request.auth != null && request.auth.uid == ${v || "userId"};\`` + (v ? "" : "\n（userId の部分は、match のパスにある名前に合わせてください）"),
        evidence: strip(G.authPart),
      });
    }
    for (const t of tests) {
      const expired = new Date(t.y, t.m - 1, t.d).getTime() < Date.now();
      add(expired ? "warn" : "danger", {
        title: expired ? `テストモードのルールが残っています（期限切れ・${f.rel}）` : `テストモードのルールが有効です（${f.rel}）`,
        why: expired
          ? "Firebase がテストモードで作るルールと同じ形です。期限が過ぎているので、今は拒否されているはずです。アプリが動かない原因がこれの可能性があります。"
          : `Firebase がテストモードで作る「◯月◯日までは誰でも OK」のルールと同じ形です。期限までは、ログインも不要で誰でも行えます。許可されている操作：${OPS_JA(t.ev.ops)}。`,
        how: "本番用のルールに書き換えます。どのデータを誰に見せたいかを決めてから、AI に書き換えを頼んでください。",
        evidence: [{ loc: t.ev.loc, code: t.ev.code, mark: t.ev.mark }],
      });
    }
  }

  // 2. 配布物とソースに混ざった秘密の鍵（.env は 3. で見る。見本用の .env.example だけは読まない）
  const bundleHits = [], sourceHits = [];
  for (const f of P.files) {
    const r = f.rel;
    if (f.name === ".env.example") continue;
    if (f.name.startsWith(".env") && !TEMPLATE_ENV.test(f.name)) continue;
    const text = read(r);
    if (text == null) continue;
    const inBundle = BUNDLE_DIRS.some((d) => r === d || r.startsWith(d + "/") || r.includes("/" + d + "/"));
    for (const s of SECRETS) for (const h of matchLines(text, s.re)) (inBundle ? bundleHits : sourceHits).push({ loc: `${r}:${h.line}`, code: `${s.name}  ${mask(h.match)}` });
  }
  if (bundleHits.length) add("danger", {
    title: "配布されるファイルに秘密の鍵が入っています",
    why: "dist / build / public の中身は、サイトを開いた人全員のブラウザに配られます。開発者ツールを開けば誰でも読めます。課金の乗っ取りや、データの取得につながります。vibe coding のサービスで作られた公開 Web アプリ5,600本超を調べた調査（Escape.tech、2025年10月）では、影響の大きい脆弱性が2,000件超、露出した秘密情報（exposed secrets）が400件超見つかっています。",
    how: "1) その鍵を、発行元の管理画面で今すぐ無効にして作り直す（漏れた鍵は戻せません）\n2) 鍵を使う処理をサーバー側（Cloud Functions など）に移す\n3) ブラウザに配るファイルには置かない",
    evidence: bundleHits,
  });
  if (sourceHits.length) add("warn", {
    title: "ソースコードに秘密の鍵が直書きされています",
    why: "まだ配布物には入っていなくても、GitHub に上げた瞬間、ビルドに含めた瞬間に公開されます。git の履歴に一度入ると、あとからファイルを消しても履歴から取り出せます。",
    how: "サーバー側だけで読む環境変数に移し、その .env を Git の管理から外します。既に push 済みなら、鍵の作り直しが必要です。",
    evidence: sourceHits,
  });
  if (!bundleHits.length && !sourceHits.length) add("ok", { title: "ソースコードと配布ファイルには、分かる範囲で秘密の鍵の直書きは見つかりませんでした（.env は別の項目で見ています）" });

  // 3. .env の扱い（Git の管理から外れているか／ブラウザに配られる名前になっていないか）
  const envs = P.files.filter((f) => f.name.startsWith(".env") && !TEMPLATE_ENV.test(f.name));
  if (envs.length) {
    const notCovered = [];
    for (const f of envs) { const c = gitignoreCovers(P.gitignore, f.rel); if (!c.covered) notCovered.push({ loc: f.rel, note: `（${c.reason}）` }); }
    if (notCovered.length) add("danger", {
      title: ".gitignore で除外を確かめられない .env ファイルがあります",
      why: ".env に鍵を置いてよいのは、1) サーバー側だけで読む 2) Git の管理から外す 3) VITE_ や NEXT_PUBLIC_ などブラウザに配る接頭辞を付けない、の3つがそろう時です。ここでは 2) を見ています。Git の管理から外れていないと、GitHub に上げた時にそのまま公開されます。公開リポジトリを機械で巡回して鍵を集める行為が、日常的に行われています。このチェックはプロジェクト直下の .gitignore だけを読み、そのファイルを除外すると言い切れる行があるかを見ています（言い切れない時は、ここに出します）。",
      how: ".gitignore に `.env*` の行を足すのが確実です（見本として共有したい .env.example は、その下に `!.env.example` と書けば戻せます）。すでにコミットしたことがあるファイルは .gitignore に書いても外れないので、`git rm --cached ファイル名` で管理から外し、中の鍵は作り直してください。",
      evidence: notCovered,
    });
    for (const f of envs) {
      const text = read(f.rel);
      if (text == null) continue;
      const byName = matchLines(text, new RegExp("^\\s*" + PUBLIC_PREFIX + "\\w*(SECRET|PRIVATE|SERVICE_ROLE|_SK|PASSWORD|TOKEN)\\w*\\s*=", "i"));
      if (byName.length) add("danger", {
        title: "ブラウザに配られる環境変数に、秘密らしき名前が入っています",
        why: "NEXT_PUBLIC_ / VITE_ / REACT_APP_ などの接頭辞は「ブラウザに配ってよい」という意味です。ビルドの時にブラウザ向けのファイルへ埋め込まれるので、ここに SECRET や TOKEN を入れると、隠したつもりで全公開になります。",
        how: "接頭辞を外し、サーバー側でだけ読むようにします。",
        evidence: byName.map((h) => ({ loc: `${f.rel}:${h.line}`, code: `${h.text.split("=")[0].trim()}=…` })),
      });
      const byValue = [];
      text.split(/\r?\n/).forEach((ln, i) => {
        const m = ln.match(new RegExp("^\\s*(?:export\\s+)?(" + PUBLIC_PREFIX + "\\w*)\\s*=\\s*(.*)$", "i"));
        if (!m) return;
        const s = SECRETS.find((x) => x.re.test(m[3]));
        if (s) byValue.push({ loc: `${f.rel}:${i + 1}`, code: `${m[1]}=…（${s.name}）` });
      });
      if (byValue.length) add("danger", {
        title: "ブラウザに配られる環境変数に、秘密の鍵が入っています",
        why: "接頭辞（VITE_ / NEXT_PUBLIC_ など）がついた変数は、ビルドの時にブラウザ向けのファイルへ埋め込まれます。値が秘密の鍵だと、サイトを開いた人全員に配られます。",
        how: "1) その鍵を発行元で無効にして作り直す\n2) 接頭辞を外し、鍵を使う処理をサーバー側に移す",
        evidence: byValue,
      });
    }
  }

  // 4. よくある誤解
  let found = null;
  for (const f of P.files) {
    const text = read(f.rel);
    if (text == null) continue;
    const hits = matchLines(text, /apiKey\s*:\s*["'`]AIza[A-Za-z0-9_\-]{10,}/);
    if (hits.length) { found = `${f.rel}:${hits[0].line}`; break; }
  }
  if (found) add("info", {
    title: "Firebase の apiKey がフロントに出ているのは、正常です",
    why: "これは秘密の鍵ではなく、どのプロジェクト宛かを示す識別子です。公開前提で配られます。Firebase の公式ドキュメントにもそう書かれています。ここを隠そうとして時間を使う人が多いのですが、守っているのは apiKey ではなく「セキュリティルール」の方です。上のルールの項目を先に見てください。",
    how: "対応は要りません。ただし Google Cloud コンソールで API キーの利用制限（HTTP リファラ）を掛けておくと、無駄な課金を防げます。",
    evidence: [{ loc: found, note: "（対応不要）" }],
  });

  return { findings, fb, count: P.files.length };
}
/* ENGINE:END */

const ROOT = path.resolve(process.argv[2] || ".");

// ---------- ファイル走査 ----------

function walk(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(p, out);
    } else if (e.isFile()) {
      const isEnv = e.name.startsWith(".env");
      if (!TEXT_EXT.has(extOf(e.name)) && !isEnv) continue;
      let st;
      try {
        st = fs.statSync(p);
      } catch {
        continue;
      }
      if (st.size > MAX_BYTES) continue;
      out.push(p);
    }
  }
  return out;
}

const read = (p) => {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
};
const toRel = (p) => (path.relative(ROOT, p) || path.basename(p)).split(path.sep).join("/");

// ---------- 出力 ----------

function box(label) {
  return `\n${label}\n${"─".repeat(46)}`;
}

function printFinding(f, i) {
  console.log(`\n${i + 1}. ${f.title}`);
  if (f.evidence?.length) {
    console.log("\n   根拠（あなたのファイルの実物）:");
    for (const e of f.evidence.slice(0, 8)) console.log(`     ${evText(e)}`);
    if (f.evidence.length > 8) console.log(`     …ほか ${f.evidence.length - 8} 件`);
  }
  const whyLabel = f.kind === "info" ? "   なぜそう言えるか:" : "   なぜ危ないか:";
  const howLabel = f.kind === "info" ? "   やること:" : "   直し方:";
  if (f.why) console.log(`\n${whyLabel}\n     ${f.why.split("\n").join("\n     ")}`);
  if (f.how) console.log(`\n${howLabel}\n     ${f.how.split("\n").join("\n     ")}`);
}

function main() {
  if (!fs.existsSync(ROOT)) {
    console.error(`パスが見つかりません: ${ROOT}`);
    process.exit(2);
  }

  console.log(`🔥 Firebase 公開前チェック  fbcheck v${FBCHECK_VERSION}`);
  console.log(`対象: ${ROOT}`);
  console.log("（このツールはネットに出ません。あなたのPCの中のファイルだけを読みます）");

  const files = walk(ROOT)
    .map((p) => ({ rel: toRel(p), name: path.basename(p), abs: p }))
    .sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  console.log(`読んだファイル: ${files.length} 件`);

  const res = runChecks({
    files: files.map(({ rel, name }) => ({ rel, name })),
    texts: new Map(files.map((f) => [f.rel, read(f.abs)])),
    gitignore: read(path.join(ROOT, ".gitignore")),
  });
  if (res.fb.length) {
    console.log(`Firebase を検出: ${res.fb.slice(0, 3).join(" / ")}`);
  } else {
    console.log("Firebase は見つかりませんでした → ルールの確認は飛ばして、鍵まわりだけ見ます");
  }

  const { danger, warn, info, ok } = res.findings;

  if (danger.length) {
    console.log(box(`■ 公開前に直すもの（${danger.length}件）`));
    danger.forEach(printFinding);
  }
  if (warn.length) {
    console.log(box(`■ 見ておくもの（${warn.length}件）`));
    warn.forEach(printFinding);
  }
  if (info.length) {
    console.log(box("■ 直さなくていいもの（よくある誤解）"));
    info.forEach(printFinding);
  }
  if (ok.length) {
    console.log(box("■ 問題なし"));
    ok.forEach((f) => console.log(`  ・${f.title}`));
  }

  console.log(box("■ 結果"));
  if (danger.length === 0 && warn.length === 0) {
    console.log("  この4項目については、危ない状態は見つかりませんでした。");
  } else {
    console.log(`  公開前に直すもの: ${danger.length}件 / 見ておくもの: ${warn.length}件`);
  }
  if (!res.fb.length) {
    console.log("  ※ このプロジェクトでは Firebase が見つからなかったので、ルールの項目は判定していません。");
  }
  console.log(
    "\n  このツールが見ているのは、実際の漏洩でよく見られる4か所だけです。\n" +
    "  ここが通っても、全部が安全という意味ではありません。\n" +
    "  逆に、ここが赤い場合は、実際に漏れた事例と同じ形になっています。"
  );
  console.log("");

  process.exit(danger.length ? 1 : 0);
}

main();
