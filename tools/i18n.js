// Переводы FYZI Guard: node tools/i18n.js
// 1) извлекает строки из PHP, 2) берёт перевод из tools/ru.json,
// 3) пишет languages/fyzi-guard.pot, fyzi-guard-ru_RU.po и .mo, 4) сообщает о пропусках.
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', 'fyzi-guard');
const LANG = path.join(ROOT, 'languages');
const DOMAIN = 'fyzi-guard';
const VERSION = (fs.readFileSync(path.join(ROOT, 'fyzi-guard.php'), 'utf8').match(/Version:\s*([\d.]+)/) || [])[1];

function phpFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(d => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) return d.name === 'languages' ? [] : phpFiles(p);
    return d.name.endsWith('.php') ? [p] : [];
  });
}

const unq = s => s.replace(/\\'/g, "'").replace(/\\\\/g, '\\');
const STR = String.raw`'((?:[^'\\]|\\.)*)'`;
const SINGLE = new RegExp(String.raw`\b(?:__|_e|esc_html__|esc_html_e|esc_attr__|esc_attr_e)\(\s*` + STR + String.raw`\s*,\s*'` + DOMAIN + `'`, 'g');
const PLURAL = new RegExp(String.raw`\b_n\(\s*` + STR + String.raw`\s*,\s*` + STR + String.raw`\s*,[^;]*?'` + DOMAIN + `'`, 'g');

const entries = new Map(); // key -> {singular, plural, refs:[], comment}
for (const file of phpFiles(ROOT)) {
  const src = fs.readFileSync(file, 'utf8');
  const rel = path.relative(ROOT, file).replace(/\\/g, '/');
  const lineOf = idx => src.slice(0, idx).split('\n').length;
  const commentBefore = idx => {
    const m = src.slice(Math.max(0, idx - 400), idx).match(/\/\*\s*translators:\s*([\s\S]*?)\*\/[^/]*$/);
    return m ? m[1].trim() : '';
  };
  for (const m of src.matchAll(SINGLE)) {
    const key = unq(m[1]);
    const e = entries.get(key) || { singular: key, refs: [], comment: '' };
    e.refs.push(rel + ':' + lineOf(m.index));
    e.comment = e.comment || commentBefore(m.index);
    entries.set(key, e);
  }
  for (const m of src.matchAll(PLURAL)) {
    const key = unq(m[1]) + '\u0000' + unq(m[2]);
    const e = entries.get(key) || { singular: unq(m[1]), plural: unq(m[2]), refs: [], comment: '' };
    e.refs.push(rel + ':' + lineOf(m.index));
    e.comment = e.comment || commentBefore(m.index);
    entries.set(key, e);
  }
}

const ru = JSON.parse(fs.readFileSync(path.join(__dirname, 'ru.json'), 'utf8'));
const missing = [];
for (const [key, e] of entries) {
  const k = e.plural ? e.singular + '|' + e.plural : e.singular;
  const t = ru[k];
  if (t === undefined || (e.plural && !Array.isArray(t))) missing.push(k);
  e.ru = t;
}
const used = new Set([...entries.values()].map(e => (e.plural ? e.singular + '|' + e.plural : e.singular)));
const unused = Object.keys(ru).filter(k => !used.has(k));

const esc = s => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
const PLURAL_FORMS = 'nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);';
const date = new Date().toISOString().slice(0, 16).replace('T', ' ') + '+0000';

function po(withRu) {
  let out = `# Copyright (C) 2026 FYZI Shield\n# This file is distributed under the GPL-2.0-or-later.\nmsgid ""\nmsgstr ""\n` +
    `"Project-Id-Version: FYZI Guard ${VERSION}\\n"\n"Report-Msgid-Bugs-To: https://fyzi.ru/\\n"\n"POT-Creation-Date: ${date}\\n"\n` +
    `"MIME-Version: 1.0\\n"\n"Content-Type: text/plain; charset=UTF-8\\n"\n"Content-Transfer-Encoding: 8bit\\n"\n` +
    (withRu ? `"Language: ru_RU\\n"\n"Plural-Forms: ${PLURAL_FORMS}\\n"\n` : '') + `"X-Domain: ${DOMAIN}\\n"\n\n`;
  for (const e of entries.values()) {
    if (e.comment) out += `#. translators: ${e.comment.replace(/\n/g, ' ')}\n`;
    out += `#: ${e.refs.join(' ')}\n`;
    if (e.singular.includes('%')) out += '#, php-format\n';
    out += `msgid "${esc(e.singular)}"\n`;
    if (e.plural) {
      out += `msgid_plural "${esc(e.plural)}"\n`;
      const forms = withRu && Array.isArray(e.ru) ? e.ru : ['', '', ''];
      (withRu ? forms : ['', '']).forEach((f, i) => { out += `msgstr[${i}] "${esc(f || '')}"\n`; });
    } else {
      out += `msgstr "${withRu && typeof e.ru === 'string' ? esc(e.ru) : ''}"\n`;
    }
    out += '\n';
  }
  return out;
}

function mo() {
  const list = [[ '', `Project-Id-Version: FYZI Guard ${VERSION}\nContent-Type: text/plain; charset=UTF-8\nLanguage: ru_RU\nPlural-Forms: ${PLURAL_FORMS}\n` ]];
  for (const e of entries.values()) {
    if (e.ru === undefined) continue;
    if (e.plural) list.push([e.singular + '\u0000' + e.plural, e.ru.join('\u0000')]);
    else list.push([e.singular, e.ru]);
  }
  list.sort((a, b) => Buffer.compare(Buffer.from(a[0]), Buffer.from(b[0])));
  const n = list.length;
  const origBufs = list.map(x => Buffer.from(x[0], 'utf8'));
  const transBufs = list.map(x => Buffer.from(x[1], 'utf8'));
  const headerSize = 28;
  const origTable = headerSize, transTable = origTable + n * 8;
  let offset = transTable + n * 8;
  const header = Buffer.alloc(headerSize);
  header.writeUInt32LE(0x950412de, 0); header.writeUInt32LE(0, 4); header.writeUInt32LE(n, 8);
  header.writeUInt32LE(origTable, 12); header.writeUInt32LE(transTable, 16); header.writeUInt32LE(0, 20); header.writeUInt32LE(offset, 24);
  const ot = Buffer.alloc(n * 8), tt = Buffer.alloc(n * 8), data = [];
  origBufs.forEach((b, i) => { ot.writeUInt32LE(b.length, i * 8); ot.writeUInt32LE(offset, i * 8 + 4); data.push(b, Buffer.from([0])); offset += b.length + 1; });
  transBufs.forEach((b, i) => { tt.writeUInt32LE(b.length, i * 8); tt.writeUInt32LE(offset, i * 8 + 4); data.push(b, Buffer.from([0])); offset += b.length + 1; });
  return Buffer.concat([header, ot, tt, ...data]);
}

fs.mkdirSync(LANG, { recursive: true });
fs.writeFileSync(path.join(LANG, DOMAIN + '.pot'), po(false));
fs.writeFileSync(path.join(LANG, DOMAIN + '-ru_RU.po'), po(true));
fs.writeFileSync(path.join(LANG, DOMAIN + '-ru_RU.mo'), mo());

console.log(`strings: ${entries.size}, translated: ${entries.size - missing.length}`);
if (missing.length) console.log('MISSING:\n' + missing.map(s => '  ' + JSON.stringify(s)).join('\n'));
if (unused.length) console.log('UNUSED in ru.json:\n' + unused.map(s => '  ' + JSON.stringify(s)).join('\n'));
if (process.argv.includes('--dump')) console.log(JSON.stringify([...entries.values()].map(e => (e.plural ? e.singular + '|' + e.plural : e.singular)), null, 1));
process.exitCode = missing.length ? 1 : 0;
