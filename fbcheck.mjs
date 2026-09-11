#!/usr/bin/env node
/**
 * fbcheck v0.1 — Firebase 公開前チェック（日本語）
 *
 * AIに作ってもらったアプリを公開する前に、実際に漏れた事例と同じ穴が
 * 空いていないかを、自分の目で確認できる形で出します。
 *
 * 使い方:  node fbcheck.mjs [プロジェクトのパス]
 * 依存なし。ネットワークに出ません。あなたのPCの中のファイルしか読みません。
 */

import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(process.argv[2] || ".");

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".nuxt", ".cache", ".vercel",
  ".firebase", "coverage", ".turbo", ".svelte-kit", "vendor",
]);
const TEXT_EXT = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
  ".json", ".env", ".html", ".rules", ".yml", ".yaml", ".txt", ".md",
]);
const MAX_BYTES = 2 * 1024 * 1024;

const findings = { danger: [], warn: [], info: [], ok: [] };
const add = (level, f) => findings[level].push({ ...f, kind: level });

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
      const ext = path.extname(e.name);
      const isEnv = e.name.startsWith(".env");
      if (!TEXT_EXT.has(ext) && !isEnv) continue;
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
const rel = (p) => path.relative(ROOT, p) || path.basename(p);

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

const mask = (s) =>
  s.length <= 12 ? s.slice(0, 4) + "…" : s.slice(0, 6) + "…" + s.slice(-4);

// ---------- 0. そもそも Firebase を使っているか ----------

function detectFirebase(files) {
  const reasons = [];
  for (const p of files) {
    const b = path.basename(p);
    if (b === "firebase.json") reasons.push("firebase.json");
    if (b === ".firebaserc") reasons.push(".firebaserc");
    if (b.endsWith(".rules") || b === "database.rules.json") reasons.push(rel(p));
    if (b === "package.json") {
      const t = read(p);
      if (t && /"(firebase|firebase-admin|firebase-tools|@angular\/fire|react-firebase\S*)"\s*:/.test(t)) {
        reasons.push("package.json の依存に firebase");
      }
    }
  }
  if (!reasons.length) {
    for (const p of files) {
      const t = read(p);
      if (!t) continue;
      if (/from\s+["']firebase\/|require\(["']firebase|firebaseConfig\s*=|FIREBASE_[A-Z_]+\s*=/.test(t)) {
        reasons.push(`${rel(p)} に firebase の記述`);
        break;
      }
    }
  }
  return [...new Set(reasons)];
}

// ---------- 1. セキュリティルール ----------

function checkRules(files, usesFirebase) {
  const ruleFiles = files.filter((p) => {
    const b = path.basename(p);
    return (
      b.endsWith(".rules") ||
      b === "database.rules.json" ||
      /^(firestore|storage)\.rules$/.test(b)
    );
  });

  const hasFirebaseJson = files.some((p) => path.basename(p) === "firebase.json");

  if (ruleFiles.length === 0) {
    if (!usesFirebase) return;   // Firebase を使っていないなら黙る
    add("danger", {
      title: "セキュリティルールのファイルが見つかりません",
      why:
        "Firestore / Storage は「誰が何を読み書きしてよいか」をルールで決めます。\n" +
        "  ファイルが無い場合、コンソール側の設定がそのまま生きています。テストモードのまま公開すると\n" +
        "  データベース全体が誰でも読める状態になります。実際にこの形で漏れた事例が複数あります。",
      how:
        "Firebaseコンソール →（Firestore Database / Storage）→「ルール」タブを開いて、\n" +
        "  今の中身をこの画面に貼ってください。何が起きるか1行ずつ説明できます。",
      evidence: hasFirebaseJson
        ? ["firebase.json はあるのに .rules ファイルが無い＝ルールがコード管理されていない"]
        : ["プロジェクト内に *.rules / database.rules.json が1つも見つからない"],
    });
    return;
  }

  for (const p of ruleFiles) {
    const text = read(p);
    if (text == null) continue;

    // if true
    const anyone = matchLines(text, /allow[^;]*:\s*if\s+true\b/);
    if (anyone.length) {
      add("danger", {
        title: `誰でも読み書きできる状態です（${rel(p)}）`,
        why:
          "`if true` は「条件なしで許可」という意味です。ログインも不要で、\n" +
          "  URLさえ分かれば誰でも中身を取り出せます。ブラウザの開発者ツールで\n" +
          "  接続先が見えるので、URLは隠せません。",
        how:
          "この行を、そのデータの持ち主だけが触れる条件に書き換えます。\n" +
          "  どのデータを誰に見せたいかを書いてくれれば、ルールを書きます。",
        evidence: anyone.map((h) => `${rel(p)}:${h.line}  ${h.text}`),
      });
    }

    // if request.auth != null （広い match に付いている場合）
    const loose = matchLines(
      text,
      /allow[^;]*:\s*if\s+request\.auth\s*!=\s*null\s*;/
    );
    if (loose.length) {
      add("danger", {
        title: `ログインさえすれば他人のデータも読めます（${rel(p)}）`,
        why:
          "`request.auth != null` は「ログイン済みなら誰でも許可」です。\n" +
          "  自分のデータだけ、という条件が入っていません。攻撃者が自分のアカウントを1つ作れば、\n" +
          "  全ユーザーのデータを読めます。AIが最もよく出力する形で、\n" +
          "  実際の漏洩事例で最多の原因になっています。",
        how:
          "所有者チェックを足します。例：\n" +
          "  allow read, write: if request.auth != null && request.auth.uid == userId;\n" +
          "  ※ データ構造によって書き方が変わるので、コレクション構成を貼ってください。",
        evidence: loose.map((h) => `${rel(p)}:${h.line}  ${h.text}`),
      });
    }

    // テストモードの期限
    const ts = matchLines(text, /timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)/);
    for (const h of ts) {
      const m = h.match.match(/(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})/);
      if (!m) continue;
      const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
      const expired = d.getTime() < Date.now();
      add(expired ? "warn" : "danger", {
        title: expired
          ? `テストモードのルールが残っています（期限切れ・${rel(p)}）`
          : `テストモードのルールが有効です（${rel(p)}）`,
        why: expired
          ? "期限が過ぎているので今は全部拒否されているはずです。アプリが動かない原因がこれの可能性があります。"
          : "「◯月◯日までは誰でも読み書きOK」という自動生成ルールです。期限内は全公開状態です。",
        how: "本番用のルールに書き換えます。どのデータを誰に見せたいか教えてください。",
        evidence: [`${rel(p)}:${h.line}  ${h.text}`],
      });
    }

    // Realtime Database の JSON ルール
    if (path.basename(p) === "database.rules.json") {
      try {
        const j = JSON.parse(text);
        const s = JSON.stringify(j);
        if (/"\.read"\s*:\s*true/.test(s) || /"\.write"\s*:\s*true/.test(s)) {
          add("danger", {
            title: `Realtime Database が全公開です（${rel(p)}）`,
            why: '".read": true / ".write": true は無条件許可です。',
            how: "認証と所有者チェックを入れます。",
            evidence: [`${rel(p)} 内に true 指定あり`],
          });
        }
      } catch { /* JSON でなければ無視 */ }
    }
  }
}

// ---------- 2. 本当に危ない秘密 ----------

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

// バンドル（配布物）に入っていたら致命的
const BUNDLE_DIRS = ["dist", "build", "out", "public", ".output"];

function checkSecrets(files) {
  const bundleHits = [];
  const sourceHits = [];

  for (const p of files) {
    const r = rel(p);
    if (/(^|[\\/])\.env\.example$/.test(r)) continue;
    const text = read(p);
    if (text == null) continue;

    const inBundle = BUNDLE_DIRS.some(
      (d) => r === d || r.startsWith(d + path.sep) || r.includes(path.sep + d + path.sep)
    );

    for (const s of SECRETS) {
      const hits = matchLines(text, s.re);
      for (const h of hits) {
        const entry = { file: r, line: h.line, name: s.name, sample: mask(h.match) };
        (inBundle ? bundleHits : sourceHits).push(entry);
      }
    }
  }

  if (bundleHits.length) {
    add("danger", {
      title: "配布されるファイルに秘密の鍵が入っています",
      why:
        "dist / build / public の中身は、サイトを開いた人全員のブラウザに配られます。\n" +
        "  開発者ツールを開けば誰でも読めます。課金の乗っ取りや、データの全取得につながります。\n" +
        "  AI生成アプリの約4件に1件で起きている問題です。",
      how:
        "1) その鍵を発行元の管理画面で今すぐ無効化して作り直す（漏れた鍵は戻せません）\n" +
        "  2) 鍵を使う処理をサーバー側（Cloud Functions 等）に移す\n" +
        "  3) フロントには絶対に置かない",
      evidence: bundleHits.map((h) => `${h.file}:${h.line}  ${h.name}  ${h.sample}`),
    });
  }

  if (sourceHits.length) {
    add("warn", {
      title: "ソースコードに秘密の鍵が直書きされています",
      why:
        "まだ配布物には入っていなくても、GitHubに上げた瞬間・ビルドに含めた瞬間に公開されます。\n" +
        "  git の履歴に一度入ると、後からファイルを消しても履歴から取り出せます。",
      how: "環境変数に移して、.env を .gitignore に入れます。既に push 済みなら鍵の作り直しが必要です。",
      evidence: sourceHits.map((h) => `${h.file}:${h.line}  ${h.name}  ${h.sample}`),
    });
  }

  if (!bundleHits.length && !sourceHits.length) {
    add("ok", { title: "分かる範囲では、危険な秘密鍵の直書きは見つかりませんでした" });
  }
}

// ---------- 3. .env の扱い ----------

function checkEnv(files) {
  const envs = files.filter((p) => {
    const b = path.basename(p);
    return b.startsWith(".env") && b !== ".env.example";
  });
  if (!envs.length) return;

  const gi = read(path.join(ROOT, ".gitignore"));
  const ignored = gi && /^\s*\.env/m.test(gi);

  if (!ignored) {
    add("danger", {
      title: ".env が .gitignore に入っていません",
      why:
        ".env は鍵を書いておくファイルです。除外されていないと、GitHubに上げた時に\n" +
        "  そのまま公開されます。公開リポジトリを機械で巡回して鍵を集める行為が常態化しています。",
      how: ".gitignore に .env* の行を足します。既に push 済みなら、鍵の作り直しが必要です。",
      evidence: envs.map((p) => `${rel(p)} が存在（.gitignore に .env の記述なし）`),
    });
  }

  // フロントに露出する接頭辞つきで秘密っぽい名前
  for (const p of envs) {
    const text = read(p);
    if (text == null) continue;
    const bad = matchLines(
      text,
      /^\s*(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)\w*(SECRET|PRIVATE|SERVICE_ROLE|_SK|PASSWORD|TOKEN)\w*\s*=/i
    );
    if (bad.length) {
      add("danger", {
        title: "フロントに配られる環境変数に、秘密らしき名前が入っています",
        why:
          "NEXT_PUBLIC_ / VITE_ / REACT_APP_ などの接頭辞は「ブラウザに配ってよい」という意味です。\n" +
          "  ここにSECRETやTOKENを入れると、隠したつもりで全公開になります。",
        how: "接頭辞を外し、サーバー側でだけ読むようにします。",
        evidence: bad.map((h) => `${rel(p)}:${h.line}  ${h.text.split("=")[0]}=…`),
      });
    }
  }
}

// ---------- 4. よくある誤解を先に潰す ----------

function checkMisconception(files) {
  let found = null;
  for (const p of files) {
    const text = read(p);
    if (text == null) continue;
    const hits = matchLines(text, /apiKey\s*:\s*["'`]AIza[A-Za-z0-9_\-]{10,}/);
    if (hits.length) {
      found = `${rel(p)}:${hits[0].line}`;
      break;
    }
  }
  if (found) {
    add("info", {
      title: "Firebase の apiKey がフロントに出ているのは、正常です",
      why:
        "これは秘密の鍵ではなく、どのプロジェクト宛かを示す識別子です。公開前提で配られます。\n" +
        "  Firebaseの公式ドキュメントにもそう書かれています。\n" +
        "  ここを隠そうとして時間を使う人が多いのですが、守っているのは apiKey ではなく\n" +
        "  「セキュリティルール」の方です。上のルール項目を先に見てください。",
        how: "対応不要です。ただし Firebase コンソールで APIキーの利用制限（HTTPリファラ）を掛けておくと無駄な課金を防げます。",
      evidence: [`${found}（対応不要）`],
    });
  }
}

// ---------- 出力 ----------

function box(label) {
  return `\n${label}\n${"─".repeat(46)}`;
}

function printFinding(f, i) {
  console.log(`\n${i + 1}. ${f.title}`);
  if (f.evidence?.length) {
    console.log("\n   根拠（あなたのファイルの実物）:");
    for (const e of f.evidence.slice(0, 8)) console.log(`     ${e}`);
    if (f.evidence.length > 8) console.log(`     …ほか ${f.evidence.length - 8} 件`);
  }
  const whyLabel = f.kind === "info" ? "   なぜそう言えるか:" : "   なぜ危ないか:";
  const howLabel = f.kind === "info" ? "   やること:" : "   直し方:";
  if (f.why) console.log(`\n${whyLabel}\n  ${f.why.split("\n").join("\n  ")}`);
  if (f.how) console.log(`\n${howLabel}\n  ${f.how.split("\n").join("\n  ")}`);
}

function main() {
  if (!fs.existsSync(ROOT)) {
    console.error(`パスが見つかりません: ${ROOT}`);
    process.exit(2);
  }

  console.log("🔥 Firebase 公開前チェック  fbcheck v0.1");
  console.log(`対象: ${ROOT}`);
  console.log("（このツールはネットに出ません。あなたのPCの中のファイルだけを読みます）");

  const files = walk(ROOT);
  console.log(`読んだファイル: ${files.length} 件`);

  const fb = detectFirebase(files);
  if (fb.length) {
    console.log(`Firebase を検出: ${fb.slice(0, 3).join(" / ")}`);
  } else {
    console.log("Firebase は見つかりませんでした → ルールの確認は飛ばして、鍵まわりだけ見ます");
  }

  checkRules(files, fb.length > 0);
  checkSecrets(files);
  checkEnv(files);
  checkMisconception(files);

  const { danger, warn, info, ok } = findings;

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
  if (!fb.length) {
    console.log("  ※ このプロジェクトでは Firebase が見つからなかったので、ルールの項目は判定していません。");
  }
  console.log(
    "\n  このツールが見ているのは、実際の漏洩事例で最も多かった4か所だけです。\n" +
    "  ここが通っても、全部が安全という意味ではありません。\n" +
    "  逆に、ここが赤い場合は実際に漏れた事例と同じ形になっています。"
  );
  console.log("");

  process.exit(danger.length ? 1 : 0);
}

main();
