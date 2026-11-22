#!/usr/bin/env python3
"""Merge the daily sales report into data.enc.json.

Input: the text of the "所有門店匯總" sheet from the UG-Salesreport-YYYYMMDD.xlsx
attachment of the daily "每日營業報表" email (tab-separated, as the Microsoft 365
connector returns it), or an .xlsx file with one sheet per direct store.

Usage:
  python3 scripts/update_from_report.py REPORT(.txt|.xlsx) PASSWORD

Rows for the 10 direct stores replace existing rows with the same store+date;
all other rows are kept. Prints a summary and any warnings; exits non-zero on
anything that should stop the update (missing stores, decrypt failure).
"""
import base64, collections, json, os, re, sys
from datetime import date, datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

STORES = ['忠孝敦化店', '信義虎林店', '信義永吉店', '站前南陽店', '羅東民權店',
          '林口長庚店', '台北大巨蛋店', '士林捷運店', '中山南西店', '宜蘭礁溪店']
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data.enc.json')
ITER = 250000


def num(v):
    if v is None or v == '':
        return 0
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0
    return int(f) if f == int(f) else f


def row_from(get, store, dt):
    return dict(
        s=store, dt=dt, w=get('天氣') or '',
        g=num(get('營業毛額')), n=num(get('營業淨額')), t=num(get('營業目標')),
        c=num(get('杯數')), tc=num(get('來客數')), h=num(get('總工時')),
        ubn=num(get('UB單數')), ubc=num(get('UB杯數')), uba=num(get('UB金額')),
        fpn=num(get('FP單數')), fpc=num(get('FP杯數')), fpa=num(get('FP金額')),
        odn=num(get('ODO單數')), odc=num(get('ODO杯數')), oda=num(get('ODO金額')),
        d=abs(num(get('總折扣金額'))), r=get('分區') or '')


def parse_date(text, year):
    m = re.match(r'(\d+)月(\d+)日', str(text or ''))
    return '%d-%02d-%02d' % (year, int(m[1]), int(m[2])) if m else None


def year_for(month, today):
    # A December report read in January belongs to the previous year.
    return today.year - 1 if month > today.month + 1 else today.year


def read_text(path, today):
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    try:
        i = next(k for k, l in enumerate(lines) if l.startswith('=== Sheet: 所有門店匯總'))
        lines = lines[i + 1:]
    except StopIteration:
        pass
    hi = next(k for k, l in enumerate(lines) if l.startswith('門店名稱\t'))
    hdr = lines[hi].split('\t')
    ix = {h: k for k, h in enumerate(hdr)}
    out = []
    for l in lines[hi + 1:]:
        if l.startswith('=== Sheet:'):
            break
        f = l.split('\t')
        if not f or f[0] not in STORES:
            continue
        m = re.match(r'(\d+)月', f[ix['日期']])
        if not m:
            continue
        dt = parse_date(f[ix['日期']], year_for(int(m[1]), today))
        get = lambda k: f[ix[k]].strip() if k in ix and ix[k] < len(f) else ''
        out.append(row_from(get, f[0], dt))
    return out


def read_xlsx(path, today):
    import openpyxl
    wb = openpyxl.load_workbook(path, data_only=True)
    out = []
    for ws in wb:
        if ws.title not in STORES:
            continue
        allr = list(ws.iter_rows(values_only=True))
        hi = next(i for i, r in enumerate(allr) if r and r[0] == '日期')
        ix = {h: i for i, h in enumerate(allr[hi]) if h}
        for r in allr[hi + 1:]:
            m = re.match(r'(\d+)月', str(r[0] or ''))
            if not m:
                continue
            get = lambda k: r[ix[k]] if k in ix else None
            out.append(row_from(get, ws.title, parse_date(r[0], year_for(int(m[1]), today))))
    return out


def key(pw, salt, it):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, it).derive(pw.encode())


def main():
    src, pw = sys.argv[1], sys.argv[2]
    today = datetime.now(timezone(timedelta(hours=8))).date()
    new = read_xlsx(src, today) if src.endswith('.xlsx') else read_text(src, today)
    new = [r for r in new if r['n']]  # a day with no sales is not reported yet
    if not new:
        sys.exit('ERROR: no direct-store rows found in report')
    present = {r['s'] for r in new}
    if present != set(STORES):
        sys.exit('ERROR: stores missing from report: %s' % sorted(set(STORES) - present))

    e = json.load(open(DATA))
    old = json.loads(AESGCM(key(pw, base64.b64decode(e['salt']), e['iter'])).decrypt(
        base64.b64decode(e['iv']), base64.b64decode(e['ct']), None))

    idx = {(r['s'], r['dt']): r for r in new}
    prev = {(r['s'], r['dt']): r for r in old['rows']}
    added = [k for k in idx if k not in prev]
    changed = [k for k in idx if k in prev and any(
        prev[k].get(f) != idx[k][f] for f in ('n', 'tc', 'c', 'uba', 'fpa', 'oda', 'h'))]

    rows = [r for r in old['rows'] if (r['s'], r['dt']) not in idx] + new
    rows.sort(key=lambda r: (r['dt'], r['s']))
    last = max(r['dt'] for r in new)
    payload = dict(rows=rows, defaultMonth=last[:7],
                   note='資料統計至 %s・更新於 %s' % (last.replace('-', '/'), today.strftime('%Y/%m/%d')))

    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(key(pw, salt, ITER)).encrypt(
        iv, json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    json.dump(dict(v=1, iter=ITER, salt=b(salt), iv=b(iv), ct=b(ct)), open(DATA, 'w'))

    # ---- summary & warnings ----
    print('report through:', last)
    print('rows added: %d, rows changed: %d' % (len(added), len(changed)))
    for k in sorted(changed):
        print('  changed', k, {f: (prev[k].get(f), idx[k][f]) for f in ('n', 'tc', 'c', 'h')
                               if prev[k].get(f) != idx[k][f]})
    mo = last[:7]
    tot = collections.Counter()
    for r in rows:
        if r['dt'][:7] == mo:
            tot[r['s']] += r['n']
    print('month-to-date net sales:', dict(tot))
    for s in STORES:
        days = sorted((r for r in rows if r['s'] == s and r['dt'][:7] == mo), key=lambda r: r['dt'])
        ds = [r['dt'] for r in days]
        if ds and ds[-1] != last:
            print('WARNING: %s has no data for %s' % (s, last))
        vals = [r['n'] for r in rows if r['s'] == s and r['dt'] < last][-28:]
        med = sorted(vals)[len(vals) // 2] if vals else 0
        for r in days:
            if (r['s'], r['dt']) in set(added) | set(changed) and med and (r['n'] > 2.5 * med or r['n'] < 0.3 * med):
                print('WARNING: %s %s net sales %s vs typical %s' % (s, r['dt'], r['n'], med))
        nohrs = [r['dt'] for r in days if not r['h']]
        if nohrs:
            print('NOTE: %s missing labor hours on %s' % (s, ', '.join(nohrs)))


if __name__ == '__main__':
    main()
