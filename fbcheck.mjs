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
import { execFileSync } from "node:child_process";

/* ENGINE:BEGIN — fbcheck の判定本体。CLI（fbcheck.mjs）とブラウザ版で、この区間は同じ文字列を使う。 */
const FBCHECK_VERSION = "0.3";
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".nuxt", ".cache", ".vercel",
  ".firebase", "coverage", ".turbo", ".svelte-kit", "vendor",
]);
const TEXT_EXT = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
  ".json", ".env", ".html", ".rules", ".yml", ".yaml", ".txt", ".md",
]);
const MAX_BYTES = 2 * 1024 * 1024;
const GEMINI_TRACE = /@google\/generative-ai|@google\/genai|generativelanguage\.googleapis\.com|GoogleGenerativeAI\(|GoogleGenAI\(/;
const AIZA_KEY = /AIza[A-Za-z0-9_\-]{10,}/;
// 痕跡の一覧（GEMINI_TRACE）と同じ呼び出しの名前。前の文字が識別子の文字（英数字・_・$）でない時だけ一致（$GoogleGenAI( は別の名前）。.GoogleGenAI(（名前空間つき）は SDK の呼び出しとして扱う（danger 側）
const GEMINI_CTOR_OPEN = /(?:^|[^\w$])(?:GoogleGenerativeAI|GoogleGenAI)\(\s*$/;
const FIREBASE_CONFIG_KEYS = new Set(["authDomain", "projectId", "storageBucket", "messagingSenderId", "appId", "measurementId", "databaseURL"]);
// 文字列・コメントを読み飛ばしながら { } の組を取り、各 { } の直下のプロパティ名と、文字列の値の範囲を集める。
// 括弧が合わない・閉じないコメントなど、読み切れない時は null（呼ぶ側は「Firebase の設定ではない」＝除外しない側に倒す）
function objectRanges(text) {
  const stack = [], out = [];
  const top0 = () => stack[stack.length - 1];
  let i = 0, prev = "", pending = null;   // prev＝直前の意味のある文字（文字列・コメントを除く）／pending＝コロンまで読んだプロパティ名
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "/" && text[i + 1] === "/") { while (i < n && text[i] !== "\n") i++; continue; }
    if (c === "/" && text[i + 1] === "*") { const e = text.indexOf("*/", i + 2); if (e < 0) return null; i = e + 2; continue; }
    // 名前と : の間の空白・コメントを飛ばして、次の文字の位置を返す（閉じないコメントは -1）
    const after = (k) => {
      for (;;) {
        while (k < n && /\s/.test(text[k])) k++;
        if (text[k] === "/" && text[k + 1] === "/") { while (k < n && text[k] !== "\n") k++; }
        else if (text[k] === "/" && text[k + 1] === "*") { const e = text.indexOf("*/", k + 2); if (e < 0) return -1; k = e + 2; }
        else return k;
      }
    };
    if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < n && text[j] !== c) { if (text[j] === "\\") j++; else if (text[j] === "\n" && c !== "`") return null; j++; }
      if (j >= n) return null;
      const top = stack[stack.length - 1], body = text.slice(i + 1, j);
      const k = after(j + 1);
      if (k < 0) return null;
      if (top && (prev === "{" || prev === ",") && text[k] === ":") { top.keys.add(body); pending = body; prev = ":"; i = k + 1; continue; }
      // 値として読めるのは「: の直後の ' か " の文字列で、その直後が , か }」だけ（連結・括弧・テンプレート・式は simple: false）。名前が取れなかった値は name: null
      if (top && prev === ":") top.props.push({ name: pending, vs: i, ve: j, simple: c !== "`" && (text[k] === "," || text[k] === "}") });
      pending = null; prev = '"'; i = j + 1; continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1; while (j < n && /[\w$]/.test(text[j])) j++;
      const top = stack[stack.length - 1], word = text.slice(i, j);
      const k = after(j);
      if (k < 0) return null;
      if (top && (prev === "{" || prev === ",") && text[k] === ":") { top.keys.add(word); pending = word; prev = ":"; i = k + 1; continue; }
      pending = null; prev = "a"; i = j; continue;
    }
    if (top0() && (prev === "{" || prev === ",") && (c === "[" || (c === "." && text.startsWith("...", i)))) top0().opaque = true;   // 計算されたキー・スプレッドで、直下のプロパティ名を取り切れない
    if (c === "{") { stack.push({ s: i, e: -1, keys: new Set(), props: [], opaque: false }); pending = null; prev = "{"; i++; continue; }
    if (c === "}") { const o = stack.pop(); if (!o) return null; o.e = i; out.push(o); pending = null; prev = "}"; i++; continue; }
    pending = null; prev = c; i++;
  }
  return stack.length ? null : out;
}
// この位置の AIza… の鍵が何か：
//   "firebase"＝囲む { } の直下のプロパティ名に authDomain・projectId などが並び、鍵がその { } の apiKey の値（Firebase の設定の apiKey）
//   "other"＝鍵が { } のプロパティの値（' か " の文字列）と読めて、その { } が Firebase の設定ではないと読めた（肯定の条件が揃った時だけ）
//   "unknown"＝それ以外の全部（{ } を読み切れない・プロパティ名が取れない・括弧・テンプレート・連結・位置引数・スプレッド・{ } の外）＝言い切らない
function classifyAiza(text, at, cache) {
  // Gemini の SDK の生成の呼び出しの第1引数に、引用符の文字列で AIza… が直接入る形（new GoogleGenerativeAI("AIza…")・new GoogleGenAI("AIza…")）は、Firebase の設定ではないと読める典型
  if (/["']/.test(text[at - 1] || "") && GEMINI_CTOR_OPEN.test(text.slice(Math.max(0, at - 80), at - 1))) {
    // 文字列の終端は、\ の次の文字を飛ばしながら探す（\" は終端ではない）。改行・ファイルの終わりまでに閉じなければ読み切れない＝下の既定（unknown）
    const q = text[at - 1];
    let e = at;
    while (e < text.length && text[e] !== q && text[e] !== "\n") e += text[e] === "\\" ? 2 : 1;
    if (e < text.length && text[e] === q && /^\s*[,)]/.test(text.slice(e + 1, e + 40))) return "other";
  }
  if (cache.ranges === undefined) cache.ranges = objectRanges(text);
  if (!cache.ranges) return "unknown";
  let best = null;
  for (const r of cache.ranges) if (r.s < at && at < r.e && (!best || r.s > best.s)) best = r;
  if (!best || best.opaque) return "unknown";
  const prop = best.props.find((p) => p.vs < at && at < p.ve);
  if (!prop || prop.name === null || !prop.simple) return "unknown";                         // プロパティの値として読めない（括弧・テンプレート・連結・位置引数・{ } の外）
  const fb = [...best.keys].some((k) => FIREBASE_CONFIG_KEYS.has(k));
  if (fb) return prop.name === "apiKey" ? "firebase" : "unknown";
  return "other";                                                                          // 肯定の条件が揃った時だけ：プロパティの値で、その { } は Firebase の設定ではない
}
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
// 1行の中の allow 文を取り出す：[{ ops, cond, bare }]。条件を書かない allow（`allow read;`）は cond が true・bare が true
// （公式：条件のない allow は、そのメソッドを常に許可する）
function allowsIn(line) {
  const out = [];
  const re = /\ballow\s+([a-z,\s]+?)\s*(?::\s*if\s+([^;}]*)|(?=[;}]))/g;
  let m;
  while ((m = re.exec(line.replace(/\/\/.*$/, "")))) {
    const ops = m[1].split(",").map((s) => s.trim()).filter(Boolean);
    if (m[2] === undefined) out.push({ ops, cond: "true", bare: true });
    else out.push({ ops, cond: m[2].trim() });
  }
  return out;
}
// 行の中の /* */ を落とす（複数行にまたがる分は inBlock で持ち回る）。allow を数える（判定できなかった行の検出）専用
function stripBlockComments(lines) {
  let inBlock = false;
  return lines.map((ln) => {
    let out = "", i = 0;
    while (i < ln.length) {
      if (inBlock) { const e = ln.indexOf("*/", i); if (e < 0) { i = ln.length; } else { inBlock = false; i = e + 2; } }
      else { const b = ln.indexOf("/*", i); if (b < 0) { out += ln.slice(i); i = ln.length; } else { out += ln.slice(i, b); inBlock = true; i = b + 2; } }
    }
    return out.replace(/\/\/.*$/, "");
  });
}
const COND_TRUE = /^true\s*(\|\||$)/;
const COND_AUTH = /^request\.auth(\.uid)?\s*!=\s*null$/;
const COND_TEST = /^request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)$/;
// 上の3つのほかに、中身を読めたと言える条件。&& でつないだ条件は、各項がすべて読める時だけ（|| があれば読めない）。
// 項の種類：true／request.auth != null／絞り込み（false・持ち主の照合・request.auth.token.x ==・送るデータの検査）／それ以外＝読めない（関数・括弧など）
const TERM_AUTH = /^request\.auth(\.uid)?\s*!=\s*null$/;
const TERM_OWNER = /^false$|^request\.auth\.uid\s*==|==\s*request\.auth\.uid$|^request\.auth\.token\.\w+\s*==/;   // 誰かに絞る項
const TERM_DATA = /^(request\.resource|resource)\.data\b/;                                                      // 送るデータの検査（誰が、には効かない）
// 条件の種類："true"（誰でも）・"auth"（ログインしていれば誰でも）・"known"（読めて、上の2つではない）・"unknown"（読めない）
function condKind(c) {
  if (/\|\|/.test(c)) return "unknown";
  const kinds = c.split("&&").map((x) => x.trim()).map((x) => (x === "true" ? "t" : TERM_AUTH.test(x) ? "a" : TERM_OWNER.test(x) ? "o" : TERM_DATA.test(x) ? "v" : "u"));
  if (kinds.includes("u")) return "unknown";
  if (kinds.includes("o")) return "known";
  if (!kinds.includes("a")) return kinds.includes("t") ? "true" : "known";   // true だけ・true とデータの検査だけ＝誰でも
  return kinds.includes("v") ? "known" : "auth";                              // auth だけ・true && auth ＝ログインしていれば誰でも
}
const COND_KNOWN = (c) => condKind(c) === "known";
const COND_TRUEISH = (c) => COND_TRUE.test(c) || condKind(c) === "true";
const COND_AUTHISH = (c) => COND_AUTH.test(c) || condKind(c) === "auth";

// コメント（// と /* */）と末尾のカンマを、文字列の外だけ落とす。コンソールのテストモードの rules や firebase init が書く形を読むため
function looseJson(text) {
  let out = "", i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') { let j = i + 1; while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1; out += text.slice(i, j + 1); i = j + 1; }
    else if (c === "/" && text[i + 1] === "/") { while (i < text.length && text[i] !== "\n") i++; }
    else if (c === "/" && text[i + 1] === "*") { const e = text.indexOf("*/", i + 2); if (e < 0) throw new Error("unterminated block comment"); i = e + 2; }
    else { out += c; i++; }
  }
  let res = "", k = 0;
  while (k < out.length) {
    const c = out[k];
    if (c === '"') { let j = k + 1; while (j < out.length && out[j] !== '"') j += out[j] === "\\" ? 2 : 1; res += out.slice(k, j + 1); k = j + 1; }
    else if (c === ",") { let j = k + 1; while (j < out.length && /\s/.test(out[j])) j++; if (out[j] === "}" || out[j] === "]") k++; else { res += c; k++; } }
    else { res += c; k++; }
  }
  return res.replace(/^\uFEFF/, "");
}
// Realtime Database の ".read" / ".write" の条件のうち、判定できる3つ（auth != null・now < ミリ秒・true）を探す
const RTDB_AUTH = /^auth(\.uid)?\s*!==?\s*null$/;
const RTDB_NOW = /^now\s*<\s*(\d{9,})$/;
function rtdbConds(node, path, out) {
  if (!node || typeof node !== "object") return out;
  for (const [k, v] of Object.entries(node)) {
    const p = path ? path + "/" + k : k;
    if ((k === ".read" || k === ".write") && typeof v === "string") {
      const c = v.trim();
      const op = k === ".read" ? "read" : "write", top = path === "rules";
      if (RTDB_AUTH.test(c)) out.push({ path: p, op, top, kind: "auth", cond: c });
      else { const m = c.match(RTDB_NOW); if (m) out.push({ path: p, op, top, kind: "time", cond: c, ms: +m[1] }); }
    } else if (v && typeof v === "object") rtdbConds(v, p, out);
  }
  return out;
}
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
// P = { files: [{ rel, name }]（rel は / 区切り・並び順どおりに判定）, texts: Map(rel → 中身|null), gitignore: 直下の .gitignore の中身|null, envStatus?: Map(rel → Git の状態) }
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
      why: "Firestore / Storage は「誰が何を読み書きしてよいか」をルールで決めます。ファイルが無い場合、コンソールで設定したルールがそのまま生きています。テストモードの期限内なら、ログインなしで誰でも全体を読み書きできます。",
      how: "Firebase コンソール →（Firestore Database / Storage）→「ルール」タブを開いて、今の中身を確かめてください。中身を AI に貼って「このルールで、誰が何を読めるか1行ずつ説明して」と聞くと、何が起きるかが分かります。",
      evidence: [{ note: hasFirebaseJson ? "firebase.json はあるのに .rules ファイルが無い＝ルールがコード管理されていない" : "プロジェクト内に *.rules / database.rules.json が1つも見つからない" }],
    });
  }
  for (const f of ruleFiles) {
    const text = read(f.rel);
    if (text == null) continue;
    if (f.name === "database.rules.json") {
      let json = null;
      try { json = JSON.parse(looseJson(text)); } catch (e) { json = null; }
      if (!json || typeof json !== "object") {
        add("warn", {
          title: `${f.rel} を読めませんでした`,
          why: "JSON として読めない書き方があったため、Realtime Database のルールは判定していません。「問題なし」という意味ではありません。",
          how: "Firebase コンソールの「ルール」タブで、今の中身を確かめてください。ファイルの書き方（カンマ・括弧・引用符）が壊れていないかも見てください。",
          evidence: [{ loc: f.rel, note: "（読めなかったので判定していません）" }],
        });
        continue;
      }
      const conds = rtdbConds(json, "", []);
      for (const grp of [{ kind: "auth", list: conds.filter((c) => c.kind === "auth") }, { kind: "time", list: conds.filter((c) => c.kind === "time") }]) {
        if (!grp.list.length) continue;
        const ev = grp.list.map((t) => ({ loc: f.rel, code: `${t.path} = "${t.cond}"` }));
        const topL = grp.list.filter((t) => t.top);
        if (grp.kind === "auth") {
          const opsL = OPS_JA([...new Set(grp.list.map((t) => t.op))]);
          const why = `".read" / ".write" の \`auth != null\` は「ログインしていれば誰でも許可」という条件です（\`firebase init\` の既定もこの形です）。Firebase Authentication で誰でも新規登録できる設定なら、アカウントを1つ作るだけで届きます。許可されている操作：${opsL}。`;
          if (topL.length) add("danger", { title: `ログインすれば、Realtime Database 全体を${VERB[opFamily(topL.map((t) => t.op))]}（${f.rel}）`, why, how: "場所ごとに、持ち主のチェック（例：`auth.uid === $uid`）を入れます。AI に頼むときは、データの構成と「誰に何を見せたいか」を一緒に伝えてください。", evidence: ev });
          else add("warn", { title: `ログインしている人なら誰でも${STATE[opFamily(grp.list.map((t) => t.op))]}場所があります（Realtime Database・${f.rel}）`, why: why + "全員で共有するデータなら、これで意図どおりです。ユーザーごとのデータなら、持ち主のチェックが足りません。", how: "ユーザーごとのデータなら、`auth.uid === $uid` のような持ち主のチェックを足します。", evidence: ev });
        } else {
          const live = grp.list.filter((t) => t.ms > Date.now());
          const dead = grp.list.filter((t) => !(t.ms > Date.now()));
          const day = (t) => { const d = new Date(t.ms); return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`; };
          const evOf = (l) => l.map((t) => ({ loc: f.rel, code: `${t.path} = "${t.cond}"` }));
          if (live.length) add("danger", {
            title: `期限まで無認証で許可するルールがあります（Firebase のテストモードと同じ形・Realtime Database・${f.rel}）`,
            why: `".read" / ".write" の \`now < …\` は、期限（${day(live[0])}）までは、ログインも不要で誰でも行えるという条件です。許可されている操作：${OPS_JA([...new Set(live.map((t) => t.op))])}。`,
            how: "本番用のルールに書き換えます。どのデータを誰に見せたいかを決めてから、AI に書き換えを頼んでください。", evidence: evOf(live),
          });
          if (dead.length) add("warn", {
            title: `期限切れの無認証許可ルールがあります（Firebase のテストモードと同じ形・Realtime Database・${f.rel}）`,
            why: `この条件は期限（${day(dead[0])}）を過ぎているので、この条件だけでは許可しません。別の場所の条件が許可していれば、アクセスは許可されます。この行で許可していた操作：${OPS_JA([...new Set(dead.map((t) => t.op))])}。`,
            how: "使っていない行なら消します。ルールを書き直すときは、どのデータを誰に見せたいかを決めてから、AI に頼んでください。", evidence: evOf(dead),
          });
        }
      }
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
    const unresolved = [];
    const bare = stripBlockComments(lines);
    for (let i = 0; i < lines.length; i++) {
      const found = allowsIn(lines[i]);
      // 判定できなかった allow：行に allow があるのに取り出せない（条件が次の行・複数行の ops など）／条件を読めない（関数・括弧・||）
      const nAllow = (bare[i].match(/\ballow\b/g) || []).length;
      const known = (a) => a.bare || COND_TRUEISH(a.cond) || COND_AUTHISH(a.cond) || COND_TEST.test(a.cond) || COND_KNOWN(a.cond);
      if (nAllow && (nAllow > found.length || !found.every(known))) unresolved.push({ loc: `${f.rel}:${i + 1}`, code: lines[i].trim() });
      for (const a of found) {
        const whole = isWholeScope(chains[i]);
        const ev = { loc: `${f.rel}:${i + 1}`, code: lines[i].trim(), ops: a.ops, chain: chains[i], bare: !!a.bare };
        if (COND_TRUEISH(a.cond)) {
          ev.mark = a.bare ? "条件なし" : "if " + a.cond.replace(/\s*\|\|.*$/, "");
          (opFamily(a.ops).includes("w") || whole ? G.anyoneHard : G.anyoneSoft).push(ev);
        } else if (COND_AUTHISH(a.cond)) {
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
    const trueIs = (list) => (list.some((e) => e.bare) ? "条件を書かない allow（`allow read;` のような形）と `if true` は、どちらも" : "`if true` は");
    if (G.anyoneHard.length) add("danger", {
      title: `誰でも${STATE[fam(G.anyoneHard)]}状態です（${f.rel}）`,
      why: `${trueIs(G.anyoneHard)}条件なしで許可するという意味です。ログインも不要で、URL さえ分かれば誰でも行えます。ブラウザの開発者ツールで接続先が見えるので、URL は隠せません。許可されている操作：${opsOf(G.anyoneHard)}。`,
      how: "この行を、そのデータの持ち主だけが触れる条件に書き換えます。AI に頼むときは「どのデータを、誰に見せたいか」を一緒に伝えてください。書き直したら、もう一度確かめてください。",
      evidence: strip(G.anyoneHard),
    });
    if (G.anyoneSoft.length) add("warn", {
      title: `誰でも読める場所があります（${f.rel}）`,
      why: `${trueIs(G.anyoneSoft)}条件なしで許可するという意味です。この行で許可されているのは読み取り（${[...new Set(G.anyoneSoft.flatMap((e) => e.ops))].join("・")}）だけで、ログインも不要です。公開してよいデータなら、このままで問題ありません。`,
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
    if (unresolved.length) add("warn", {
      title: `判定できなかった allow の行があります（${unresolved.length} 行・${f.rel}）`,
      why: "この行の条件は、ここでは読み取れませんでした。「問題なし」という意味ではありません。条件が次の行にある・関数（isSignedIn() など）を呼んでいる・括弧や || を使っている、といった書き方がこれに当たります。条件が常に true になる書き方でも、ここでは見分けられません。",
      how: "この行が、誰に何を許可しているかを自分で確かめてください。中身を AI に貼って「この条件で、誰が何を読めるか1行ずつ説明して」と聞くと、何が起きるかが分かります。",
      evidence: unresolved,
    });
    for (const t of tests) {
      const expired = new Date(t.y, t.m - 1, t.d).getTime() < Date.now();
      add(expired ? "warn" : "danger", {
        title: expired
          ? `期限切れの無認証許可ルールがあります（Firebase のテストモードと同じ形・${f.rel}）`
          : `期限まで無認証で許可するルールがあります（Firebase のテストモードと同じ形・${f.rel}）`,
        why: expired
          ? `この allow の条件は期限（${t.y}年${t.m}月${t.d}日）を過ぎているので、この条件だけでは許可しません。ただし Firestore / Storage のルールは、同じリクエストに当てはまる allow のどれか1つでも true なら許可します。別の allow が true なら、アクセスは許可されます。この行で許可していた操作：${OPS_JA(t.ev.ops)}。`
          : `期限（${t.y}年${t.m}月${t.d}日）までは、ログインも不要で誰でも行えます。許可されている操作：${OPS_JA(t.ev.ops)}。`,
        how: expired
          ? "使っていない行なら消します。ルールを書き直すときは、どのデータを誰に見せたいかを決めてから、AI に頼んでください。"
          : "本番用のルールに書き換えます。どのデータを誰に見せたいかを決めてから、AI に書き換えを頼んでください。",
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
    why: "まだ配布物には入っていなくても、ビルドに含めて配ったり、公開リポジトリに上げたりした時点で公開されます。git の履歴に一度入ると、あとからファイルを消しても履歴から取り出せます。",
    how: "サーバー側だけで読む環境変数に移し、その .env を Git の管理から外します。既に push 済みなら、鍵の作り直しが必要です。",
    evidence: sourceHits,
  });
  if (!bundleHits.length && !sourceHits.length) add("ok", { title: "ソースコードと配布ファイルには、分かる範囲で秘密の鍵の直書きは見つかりませんでした（.env は別の項目で見ています）" });

  // 3. .env の扱い（Git の管理から外れているか／ブラウザに配られる名前になっていないか）
  //    P.envStatus: Map(rel → "tracked" | "untracked_ignored" | "untracked_not_ignored" | "unknown")
  //    Node.js 版は git 自身（ls-files / check-ignore）で埋める。Git の記録を読めない時（ブラウザ版など）は unknown。
  //    unknown の時は「Git の管理外」とは言わない。直下の .gitignore に除外の行があっても「未確認」として出す。
  const envs = P.files.filter((f) => f.name.startsWith(".env") && !TEMPLATE_ENV.test(f.name));
  if (envs.length) {
    const statusOf = (rel) => (P.envStatus && P.envStatus.get(rel)) || "unknown";
    const keyNote = (rel) => {
      const t = read(rel);
      if (t == null) return "";
      const names = [...new Set(SECRETS.filter((x) => t.split(/\r?\n/).some((ln) => x.re.test(ln))).map((x) => x.name))];
      return names.length ? `・鍵らしき値あり：${names.join("、")}` : "";
    };
    const tracked = [], notIgnored = [], noPattern = [], unconfirmed = [];
    for (const f of envs) {
      const st = statusOf(f.rel);
      if (st === "untracked_ignored") continue;
      if (st === "tracked") tracked.push({ loc: f.rel, note: `（Git で追跡中${keyNote(f.rel)}）` });
      else if (st === "untracked_not_ignored") notIgnored.push({ loc: f.rel, note: `（git check-ignore で除外されていない${keyNote(f.rel)}）` });
      else {
        const c = gitignoreCovers(P.gitignore, f.rel);
        if (c.covered) unconfirmed.push({ loc: f.rel, note: `（直下の .gitignore に除外の行あり・追跡済みかは未確認${keyNote(f.rel)}）` });
        else noPattern.push({ loc: f.rel, note: `（${c.reason}${keyNote(f.rel)}）` });
      }
    }
    const THREE = ".env に鍵を置いてよいのは、1) サーバー側だけで読む 2) Git の管理から外す 3) VITE_ や NEXT_PUBLIC_ などブラウザに配る接頭辞を付けない、の3つがそろう時です。ここでは 2) を見ています。";
    if (tracked.length) add("danger", {
      title: "Git で追跡されている .env ファイルがあります",
      why: THREE + ".gitignore は、まだ Git に入っていないファイルにだけ効きます。一度コミットした .env は、あとから .gitignore に書いても追跡されたままで、公開リポジトリに push すると、そのまま公開されます。git の履歴にも残ります。",
      how: "`git rm --cached -- ファイル名` で追跡を外してコミットし、中の鍵は発行元で作り直してください（履歴に残った鍵は戻せません）。",
      evidence: tracked,
    });
    if (notIgnored.length) add("danger", {
      title: "Git の管理から外れていない .env ファイルがあります",
      why: THREE + "git 自身（git check-ignore）で確かめたところ、除外されていません。下の階層の .gitignore にある `!.env` のような行で、除外が打ち消されていることもあります。",
      how: "`git check-ignore -v -- ファイル名` でどの行が効いているかを確かめ、.gitignore に `.env*` を足すか、打ち消している行を外します。",
      evidence: notIgnored,
    });
    if (noPattern.length) add("danger", {
      title: ".gitignore に除外する行が見つからない .env ファイルがあります",
      why: THREE + "Git の管理から外れていないと、コミットして公開リポジトリに上げた時に、そのまま公開されます。公開リポジトリを機械で巡回して鍵を集める行為が、日常的に行われています。ここでは、プロジェクト直下の .gitignore だけを読んでいます。",
      how: ".gitignore に `.env*` の行を足すのが確実です（見本として共有したい .env.example は、その下に `!.env.example` と書けば戻せます）。すでにコミットしたことがあるファイルは .gitignore に書いても外れないので、`git rm --cached -- ファイル名` で管理から外し、中の鍵は作り直してください。",
      evidence: noPattern,
    });
    if (unconfirmed.length) add("warn", {
      title: ".env が Git で追跡済みかは、ここでは確かめられません",
      why: "直下の .gitignore に除外の行はあります。ただし .gitignore は、まだ Git に入っていないファイルにだけ効きます。一度コミットした .env は追跡されたままです。また、下の階層の .gitignore にある `!.env` のような行で、除外が打ち消されていることもあります。今回は Git の記録（.git の中）を読めていないので（ブラウザ版、または git リポジトリの外や git の無い環境で実行した時）、この2つは確かめられません。",
      how: "ターミナルでプロジェクトのフォルダに移動して `git ls-files -- .env` を実行します。ファイル名が表示されたら追跡済みです（`git rm --cached -- .env` で外し、鍵を作り直す）。下の階層の .gitignore まで含めて確かめるには `git check-ignore -v -- ファイル名`。Node.js 版の fbcheck を git リポジトリの中で実行すると、この2つを git 自身で確かめます。",
      evidence: unconfirmed,
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

  // 4. Gemini の API キー（Firebase の apiKey とは別物）：Gemini を使う痕跡があるプロジェクトで、AIza… の鍵がブラウザ側（ソース・配布物・接頭辞つきの .env）にある
  //    firebaseConfig の中の apiKey（authDomain などが近くにある）は Firebase のキーなので数えない
  const geminiTrace = P.files.some((f) => { const t = read(f.rel); return t != null && GEMINI_TRACE.test(t); });
  const geminiHits = [], geminiUnsure = [];
  if (geminiTrace) {
    for (const f of P.files) {
      const text = read(f.rel);
      if (text == null || f.name === ".env.example") continue;
      const isEnv = f.name.startsWith(".env");
      if (isEnv && TEMPLATE_ENV.test(f.name)) continue;
      if (isEnv) {
        text.split(/\r?\n/).forEach((ln, i) => {
          const k = ln.match(AIZA_KEY);
          if (!k) return;
          const m = ln.match(new RegExp("^\\s*(?:export\\s+)?(" + PUBLIC_PREFIX + "\\w*)\\s*="));
          if (!m || /FIREBASE/i.test(m[1])) return;
          geminiHits.push({ loc: `${f.rel}:${i + 1}`, code: `AIza で始まる鍵  ${mask(k[0])}` });
        });
        continue;
      }
      const re = new RegExp(AIZA_KEY.source, "g"), cache = {};
      let k;
      while ((k = re.exec(text))) {
        const kind = classifyAiza(text, k.index, cache);
        if (kind === "firebase") continue;
        const loc = `${f.rel}:${text.slice(0, k.index).split("\n").length}`;
        const list = kind === "other" ? geminiHits : geminiUnsure;
        if (!list.some((h) => h.loc === loc && h.code.endsWith(mask(k[0])))) list.push({ loc, code: `AIza で始まる鍵  ${mask(k[0])}` });
      }
    }
  }
  if (geminiHits.length) add("danger", {
    title: "Gemini のキーがブラウザ側に出ています",
    why: "このプロジェクトには Gemini の API を使う痕跡があり、ブラウザ側（ソース・配布されるファイル・VITE_ や NEXT_PUBLIC_ などの接頭辞がついた .env）に AIza で始まる鍵があります。Firebase の apiKey は公開してよい識別子ですが、Gemini Developer API のキーは別物で、Google の公式ドキュメントでも、コードや設定ファイルに入れてはいけない、公開されるキーの許可リストに入れてはいけない、とされています。サイトを開いた人全員に配られ、あなたの課金で使われます。",
    how: "1) その鍵を Google AI Studio / Cloud コンソールで無効にして作り直す\n2) Gemini を呼ぶ処理をサーバー側（Cloud Functions など）に移し、鍵はサーバー側だけで読む環境変数に置く\n3) ブラウザに配るファイルと、接頭辞のついた変数には置かない\n（この行が Firebase の apiKey だった場合は、対応不要です）",
    evidence: geminiHits,
  });

  if (geminiUnsure.length) add("warn", {
    title: "Firebase の設定か Gemini のキーか判定できなかった AIza… があります",
    why: "このプロジェクトには Gemini の API を使う痕跡があり、AIza で始まる鍵があります。ただし、この鍵が Firebase の設定（firebaseConfig）の apiKey なのか、Gemini のキーなのかを、ここでは読み取れませんでした（コードの書き方を読み切れない・鍵のプロパティ名が取れない）。Firebase の apiKey は公開してよい識別子ですが、Gemini Developer API のキーは別物で、ブラウザに配るファイルや設定ファイルに入れてはいけません（Google の公式ドキュメント）。",
    how: "この行を自分で確かめてください。Gemini のキーなら、1) 発行元で無効にして作り直す 2) Gemini を呼ぶ処理をサーバー側に移す。Firebase の apiKey なら対応不要です。",
    evidence: geminiUnsure,
  });

  // 5. よくある誤解
  let found = null;
  const geminiLocs = new Set([...geminiHits, ...geminiUnsure].map((h) => h.loc));
  for (const f of P.files) {
    const text = read(f.rel);
    if (text == null) continue;
    const hits = matchLines(text, /apiKey\s*:\s*["'`]AIza[A-Za-z0-9_\-]{10,}/).filter((h) => !geminiLocs.has(`${f.rel}:${h.line}`));
    if (hits.length) { found = `${f.rel}:${hits[0].line}`; break; }
  }
  if (found) add("info", {
    title: "Firebase の apiKey がフロントに出ているのは、正常です",
    why: "これは秘密の鍵ではなく、どのプロジェクト宛かを示す識別子です。Firebase の公式ドキュメントにも、Firebase のサービスだけに制限されたキーは秘密として扱う必要はない、と書かれています。ここを隠そうとして時間を使う人が多いのですが、守っているのは apiKey ではなく「セキュリティルール」の方です。上のルールの項目を先に見てください。",
    how: "隠す対応は要りません。確かめるなら、Google Cloud コンソールでこのキーの「API の制限」が Firebase 関連の API だけになっているかを見ます（2024年5月以降に Firebase が自動で作ったキーは、最初からそう制限されています。それより前に作られたキーは、Firebase 以外の API も許可に入っていることがあります）。Maps や Gemini など別の API を使うときは、このキーに足さず、別のキーを作ってその API だけに制限します。Gemini Developer API のキーは Firebase のキーとは別物で、コードや設定ファイルに入れてはいけません（Google の公式ドキュメントにそう書かれています）。",
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

// .env が Git で追跡されているか・除外されているかを、git 自身に確かめさせる。
// git が無い／git リポジトリの外なら null（＝判定は「未確認」になる）。ネットワークには出ない。
function gitEnvStatus(rels) {
  // ls-files はパスを glob として読まないよう --literal-pathspecs を付ける（check-ignore はこの指定を受け付けない）
  const git = (args, pre = []) => execFileSync("git", [...pre, "-C", ROOT, ...args], { stdio: ["ignore", "pipe", "ignore"] });
  try { if (String(git(["rev-parse", "--is-inside-work-tree"])).trim() !== "true") return null; } catch { return null; }
  const out = new Map();
  for (const rel of rels) {
    let st = "unknown";
    try { git(["ls-files", "--error-unmatch", "--", rel], ["--literal-pathspecs"]); st = "tracked"; }
    catch (e) {
      if (e.status === 1) {
        try { git(["check-ignore", "-q", "--", rel]); st = "untracked_ignored"; }
        catch (e2) { st = e2.status === 1 ? "untracked_not_ignored" : "unknown"; }
      }
    }
    out.set(rel, st);
  }
  return out;
}

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

  const envStatus = gitEnvStatus(files.filter((f) => f.name.startsWith(".env") && !TEMPLATE_ENV.test(f.name)).map((f) => f.rel));
  console.log(envStatus ? "Git：.env の追跡と除外を git 自身で確かめます" : "Git：git が無いか git リポジトリの外なので、.env が追跡済みかは確かめられません");
  const res = runChecks({
    files: files.map(({ rel, name }) => ({ rel, name })),
    texts: new Map(files.map((f) => [f.rel, read(f.abs)])),
    gitignore: read(path.join(ROOT, ".gitignore")),
    envStatus,
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
