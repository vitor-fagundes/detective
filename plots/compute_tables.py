"""Computa as linhas das tabelas tab:rede e tab:seguranca para 200_attack5,
250_attack5 e 200_fr, com método único. Valida reproduzindo o baseline."""
import os, re, glob
import numpy as np, pandas as pd

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(PROJ, 'results-detective')
ATK_IP_RE = re.compile(r'ATTACKER_SELECTED: Node \d+ \((fe80[^)]+)\)')
QTGT_RE = re.compile(r'target=(fe80\S+)')

SERIES = [('200_attack5', 200), ('250_attack5', 250), ('200_fr', 200)]


def attack_times(scen):
    man = os.path.join(scen, 'attack_manifest.csv')
    if os.path.exists(man):
        df = pd.read_csv(man)
        return {int(r.run): int(r.attack_start) for r in df.itertuples()}
    times = {}
    for rd in glob.glob(os.path.join(scen, 'run_*')):
        run = int(os.path.basename(rd).split('_')[1]); t = 300
        log = os.path.join(rd, 'simulation.log')
        if os.path.exists(log):
            for line in open(log, errors='ignore'):
                m = re.search(r'in[íi]cio=(\d+)', line)
                if m: t = int(m.group(1)); break
        times[run] = t
    return times


def tp_fp(rd):
    log = os.path.join(rd, 'simulation.log'); atk, quar = set(), set()
    if os.path.exists(log):
        for line in open(log, errors='ignore'):
            m = ATK_IP_RE.search(line);  atk.add(m.group(1)) if m else None
            m = QTGT_RE.search(line);     quar.add(m.group(1)) if m else None
    return len(quar & atk), len(quar - atk), len(atk)


def analyze(scen, N):
    atk_map = attack_times(scen)
    A = {k: [] for k in ['leaders','sat','orphans','realloc','srpre','srmin']}
    adt, amt = [], []
    trec_a, trec_b, trec_c = [], [], []   # candidatos de definição
    TP = FP = ATK = 0; nruns = 0
    for rd in sorted(glob.glob(os.path.join(scen, 'run_*'))):
        f = os.path.join(rd, 'IntuitiveStats.csv')
        if not os.path.exists(f): continue
        run = int(os.path.basename(rd).split('_')[1])
        df = pd.read_csv(f)
        if df.empty: continue
        nruns += 1
        t0 = atk_map.get(run, 300)
        ts = df['timestamp'].values.astype(float)
        pre = df[df.timestamp <= t0]; post = df[df.timestamp >= t0]
        A['leaders'].append(float(pre['leadersAlive'].iloc[-1]) if len(pre) else float(df['leadersAlive'].iloc[0]))
        A['sat'].append(float(df['leadersDownThisCycle'].sum()))
        A['orphans'].append(float(df['totalOrphans'].max()))
        A['realloc'].append(float(df['actionsReallocate'].sum()))
        A['srpre'].append(float(pre['sr'].iloc[-1])*100 if len(pre) else float(df['sr'].iloc[0])*100)
        A['srmin'].append(float(post['sr'].min())*100)
        # confusão (via log, pooled)
        tp, fp, natk = tp_fp(rd); TP += tp; FP += fp; ATK += natk
        # temporais
        p = df[df.timestamp >= t0]
        det = p[p.suspectsCount > 0]
        if len(det):
            tdet = float(det.timestamp.iloc[0]); adt.append(tdet - t0)
            q = df[(df.timestamp >= tdet) & (df.actionsAttackerQuarantine > 0)]
            if len(q): amt.append(float(q.timestamp.iloc[0]) - tdet)
        loss = p[p.leadersDownThisCycle > 0]
        if len(loss):
            tloss = float(loss.timestamp.iloc[0])
            # (a) queda de líder -> orphans==0
            r = df[(df.timestamp > tloss) & (df.totalOrphans == 0)]
            if len(r): trec_a.append(float(r.timestamp.iloc[0]) - tloss)
            # (b) queda de líder -> primeira ação de recuperação (realloc/recluster)
            r = df[(df.timestamp >= tloss) & ((df.actionsReallocate > 0) | (df.actionsRecluster > 0))]
            if len(r): trec_b.append(float(r.timestamp.iloc[0]) - tloss)
        # (c) primeiro orphan>0 -> orphans==0
        orf = p[p.totalOrphans > 0]
        if len(orf):
            torf = float(orf.timestamp.iloc[0])
            r = df[(df.timestamp > torf) & (df.totalOrphans == 0)]
            if len(r): trec_c.append(float(r.timestamp.iloc[0]) - torf)
    # confusão pooled
    tot = N * nruns
    FN = ATK - TP; TN = tot - ATK - FP
    acc = 100*(TP+TN)/tot
    rec = 100*TP/ATK if ATK else 0
    pre = 100*TP/(TP+FP) if (TP+FP) else 0
    fpr = 100*FP/(FP+TN) if (FP+TN) else 0
    f1 = 2*pre*rec/(pre+rec) if (pre+rec) else 0
    return A, adt, amt, (trec_a, trec_b, trec_c), dict(acc=acc, rec=rec, pre=pre, fpr=fpr, f1=f1,
                                   TP=TP, FP=FP, FN=FN, ATK=ATK, nruns=nruns)


def ci(v):
    """mean ± 95% CI (1.96*std/sqrt(n))."""
    v = np.array(v); n = len(v)
    return np.mean(v), 1.96*np.std(v, ddof=1)/np.sqrt(n) if n > 1 else 0.0

def ms(v):
    m, c = ci(v); return f'{m:.1f}$\\pm${c:.1f}'

for scen, N in SERIES:
    d = os.path.join(RESULTS, scen)
    if not os.path.isdir(d): continue
    A, adt, amt, (ta, tb, tc), C = analyze(d, N)
    print(f'\n===== {scen}  (N={N}, {C["nruns"]} runs) =====')
    print('  TABELA 1 (rede) [mean ± 95% CI]:')
    print(f'    Leaders={ms(A["leaders"])}  Sat={ms(A["sat"])}  Orphans={ms(A["orphans"])} '
          f'Realloc={ms(A["realloc"])}  SRpre={ms(A["srpre"])}  SRmin={ms(A["srmin"])}')
    print('  TABELA 2 (segurança):')
    print(f'    ACC={C["acc"]:.2f}  DR/Recall={C["rec"]:.2f}  PRE={C["pre"]:.1f}  FPR={C["fpr"]:.2f}  F1={C["f1"]:.2f}')
    print(f'    TP={C["TP"]} FP={C["FP"]} FN={C["FN"]} attackers={C["ATK"]}')
    print(f'    ADT={np.mean(adt):.1f}s  AMT={np.mean(amt) if amt else float("nan"):.1f}s')
    print(f'    Trec(a)líder→orph0={np.mean(ta):.1f}s  Trec(b)líder→ação={np.mean(tb):.1f}s  '
          f'Trec(c)orph>0→orph0={np.mean(tc):.1f}s')
