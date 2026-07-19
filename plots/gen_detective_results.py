"""
gen_detective_results.py
Gera os resultados/figuras do DETECTIVE a partir de results-detective/<N>_<label>/run_*/.

Adapta a metodologia do synapt (agregação de N runs + curva alinhada ao evento
com média±desvio), mas para o cenário de ATAQUE. t=0 = início do ataque
(parseado de ATTACK_CONFIG, default 300s). Serve para v1 (membro→líder, 31 cols)
e v2 (líder→AP, 35 cols) — usa nomes de coluna, não índices.

Saídas:
  plots/data/summary_runs.csv, summary_by_scale.csv
  plots/figures/fig_qi_attack.{pdf,png}, fig_sr_attack.{pdf,png}
  plots/figures/fig_attacker_learning.{pdf,png}, fig_recovery_summary.{pdf,png}

Uso:
  python3 plots/gen_detective_results.py                 # auto-detecta *_attack*
  python3 plots/gen_detective_results.py --glob '*_mode2'
"""
import os
import re
import glob
import argparse
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
warnings.filterwarnings('ignore')

plt.rcParams.update({
    'font.family':      'DejaVu Sans',
    'font.size':        18,
    'axes.titlesize':   18,
    'axes.titleweight': 'bold',
    'axes.labelsize':   18,
    'axes.labelweight': 'bold',
    'xtick.labelsize':  16,
    'ytick.labelsize':  16,
    'axes.grid':        True,
    'grid.color':       '#DDDDDD',
    'grid.linestyle':   '--',
    'grid.linewidth':   0.8,
    'grid.alpha':       0.6,
    'legend.frameon':   True,
    'legend.fontsize':  15,
    'figure.facecolor': 'white',
    'axes.facecolor':   'white',
    'figure.dpi':       150,
})

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
RESULTS = os.path.join(PROJ, 'results-detective')
DATA = os.path.join(HERE, 'data')
FIGS = os.path.join(HERE, 'figures')
os.makedirs(DATA, exist_ok=True)
os.makedirs(FIGS, exist_ok=True)

WINDOW_PRE, WINDOW_POST, STEP = 30, 120, 5
REL_TIMES = np.arange(-WINDOW_PRE, WINDOW_POST + STEP, STEP)
ATTACK_RE = re.compile(r'in[íi]cio=(\d+)s')
NATT_RE = re.compile(r'_attack(\d+)')
SCALE_COLORS = {200: '#42A5F5', 250: '#66BB6A', 300: '#EF5350'}


def n_attackers_of(scen_dir):
    m = NATT_RE.search(os.path.basename(scen_dir))
    return int(m.group(1)) if m else 5


def scenario_dirs(pattern):
    out = []
    for d in sorted(glob.glob(os.path.join(RESULTS, pattern))):
        if os.path.isdir(d) and glob.glob(os.path.join(d, 'run_*', 'IntuitiveStats.csv')):
            out.append(d)
    return out


def scale_of(scen_dir):
    m = re.search(r'(\d+)', os.path.basename(scen_dir))
    return int(m.group(1)) if m else 0


def attack_time(run_dir):
    log = os.path.join(run_dir, 'simulation.log')
    if os.path.exists(log):
        with open(log, errors='ignore') as f:
            for line in f:
                m = ATTACK_RE.search(line)
                if m:
                    return int(m.group(1))
    return 300


def load_scenario(scen_dir):
    scale = scale_of(scen_dir)
    natt = n_attackers_of(scen_dir)
    run_dirs = sorted(glob.glob(os.path.join(scen_dir, 'run_*')))
    run_rows, aligned = [], []
    for rd in run_dirs:
        stats = os.path.join(rd, 'IntuitiveStats.csv')
        if not os.path.exists(stats):
            continue
        df = pd.read_csv(stats)
        if df.empty:
            continue
        run = int(os.path.basename(rd).split('_')[1])
        atk = attack_time(rd)

        pre = df[df['timestamp'] <= atk]
        post = df[df['timestamp'] >= atk]
        qi_pre = float(pre['qi'].iloc[-1]) if len(pre) else float(df['qi'].iloc[0])
        sr_pre = float(pre['sr'].iloc[-1]) if len(pre) else float(df['sr'].iloc[0])
        run_rows.append({
            'scale': scale, 'run': run, 'n_attackers': natt,
            'qi_pre': qi_pre, 'sr_pre': sr_pre,
            'qi_min': float(post['qi'].min()), 'sr_min': float(post['sr'].min()),
            'qi_final': float(df['qi'].iloc[-1]), 'sr_final': float(df['sr'].iloc[-1]),
            'leaders_down_total': int(df['leadersDownThisCycle'].sum()),
            'orphans_peak': int(df['totalOrphans'].max()),
            'reallocate_total': int(df['actionsReallocate'].sum()),
            'recluster_total': int(df['actionsRecluster'].sum()),
            'suspects_total': int(df['suspectsCount'].sum()),
            'atk_quar_total': int(df['actionsAttackerQuarantine'].sum()),
            'atk_qquar': max(float(df['qAtkQuarHigh'].iloc[-1]), float(df['qAtkQuarLow'].iloc[-1])),
            'atk_epsilon': float(df['atkEpsilon'].iloc[-1]),
        })

        idx = df.set_index('timestamp')
        for rel in REL_TIMES:
            t = atk + rel
            if t in idx.index:
                aligned.append({'scale': scale, 'rel_time': rel,
                                'qi': float(idx.loc[t, 'qi']), 'sr': float(idx.loc[t, 'sr'])})
    return pd.DataFrame(run_rows), pd.DataFrame(aligned)


def plot_aligned(aligned_all, metric, ylabel, fname):
    fig, ax = plt.subplots(figsize=(8, 5))
    for scale in sorted(aligned_all['scale'].unique()):
        sub = aligned_all[aligned_all['scale'] == scale]
        agg = sub.groupby('rel_time')[metric].agg(['mean', 'std']).reset_index()
        c = SCALE_COLORS.get(scale, '#888888')
        ax.plot(agg['rel_time'], agg['mean'], color=c, linewidth=2.2, label=f'N={scale}')
        ax.fill_between(agg['rel_time'], agg['mean'] - agg['std'], agg['mean'] + agg['std'],
                        alpha=0.15, color=c)
    ax.axvline(0, color='red', linewidth=2, linestyle='--', alpha=0.75, label='Attack (t=0)')
    ax.set_xlabel('Time relative to attack (s)')
    ax.set_ylabel(ylabel)
    ax.set_ylim(0.0, 1.03)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v*100:.0f}%'))
    ax.set_xlim(-WINDOW_PRE, WINDOW_POST)
    ax.legend(loc='lower right')
    plt.tight_layout()
    base = os.path.join(FIGS, fname)
    plt.savefig(base + '.pdf', bbox_inches='tight')
    plt.savefig(base + '.png', bbox_inches='tight')
    plt.close()
    print(f'  saved {fname}.pdf/.png')


def plot_attacker_learning(summary, fname):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    for scale in sorted(summary['scale'].unique()):
        sub = summary[summary['scale'] == scale].sort_values('run')
        c = SCALE_COLORS.get(scale, '#888888')
        ax1.plot(sub['run'], sub['atk_qquar'], color=c, linewidth=2, marker='o',
                 markersize=3, label=f'N={scale}')
        ax2.plot(sub['run'], sub['atk_epsilon'], color=c, linewidth=2, marker='o',
                 markersize=3, label=f'N={scale}')
    ax1.set_title('(A) Attacker Q(QUARANTINE)')
    ax1.set_xlabel('Cumulative run'); ax1.set_ylabel('Q-value'); ax1.legend(loc='lower right')
    ax2.set_title('(B) Attacker exploration (ε)')
    ax2.set_xlabel('Cumulative run'); ax2.set_ylabel('ε'); ax2.legend(loc='upper right')
    plt.tight_layout()
    base = os.path.join(FIGS, fname)
    plt.savefig(base + '.pdf', bbox_inches='tight')
    plt.savefig(base + '.png', bbox_inches='tight')
    plt.close()
    print(f'  saved {fname}.pdf/.png')


def plot_recovery_summary(summary, fname):
    scales = sorted(summary['scale'].unique())
    pre = [summary[summary.scale == s]['sr_pre'].mean() for s in scales]
    mn = [summary[summary.scale == s]['sr_min'].mean() for s in scales]
    fin = [summary[summary.scale == s]['sr_final'].mean() for s in scales]
    x = np.arange(len(scales)); w = 0.26
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - w, pre, w, label='Pre-attack', color='#90CAF9')
    ax.bar(x,     mn,  w, label='Peak impact', color='#EF9A9A')
    ax.bar(x + w, fin, w, label='Post-recovery', color='#A5D6A7')
    ax.set_xticks(x); ax.set_xticklabels([f'N={s}' for s in scales])
    ax.set_ylabel('Service Reachability'); ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v*100:.0f}%'))
    ax.legend(loc='lower center', ncol=3, fontsize=12)
    plt.tight_layout()
    base = os.path.join(FIGS, fname)
    plt.savefig(base + '.pdf', bbox_inches='tight')
    plt.savefig(base + '.png', bbox_inches='tight')
    plt.close()
    print(f'  saved {fname}.pdf/.png')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--glob', default='*_attack*', help='padrão dos dirs em results-detective/')
    args = ap.parse_args()

    dirs = scenario_dirs(args.glob)
    if not dirs:
        print(f'Nenhum cenário casando "{args.glob}" em {RESULTS}')
        return
    print('Cenários:', [os.path.basename(d) for d in dirs])

    all_runs, all_aligned = [], []
    for d in dirs:
        rl, al = load_scenario(d)
        all_runs.append(rl); all_aligned.append(al)
        print(f'  {os.path.basename(d)}: {len(rl)} runs, {len(al)} amostras alinhadas')
    summary = pd.concat(all_runs, ignore_index=True)
    aligned = pd.concat(all_aligned, ignore_index=True)

    summary.to_csv(os.path.join(DATA, 'summary_runs.csv'), index=False)
    print(f'\nsummary_runs.csv salvo ({len(summary)} runs)')

    print('\nGerando figuras...')
    plot_aligned(aligned, 'qi', 'Quality Index', 'fig_qi_attack')
    plot_aligned(aligned, 'sr', 'Service Reachability', 'fig_sr_attack')
    plot_attacker_learning(summary, 'fig_attacker_learning')
    plot_recovery_summary(summary, 'fig_recovery_summary')

    print('\n=== RESUMO POR ESCALA ===')
    rows = []
    for s in sorted(summary['scale'].unique()):
        g = summary[summary.scale == s]
        total_quar = g.atk_quar_total.sum(); total_att = g.n_attackers.sum()
        rows.append({
            'scale': s, 'runs': len(g),
            'sr_pre': g.sr_pre.mean(), 'sr_min': g.sr_min.mean(), 'sr_final': g.sr_final.mean(),
            'qi_final': g.qi_final.mean(),
            'orphans_peak': g.orphans_peak.mean(),
            'realloc_run': g.reallocate_total.mean(),
            'reclust_run': g.recluster_total.mean(),
            'recall': (total_quar / total_att) if total_att else 0.0,
        })
    tab = pd.DataFrame(rows)
    tab.to_csv(os.path.join(DATA, 'summary_by_scale.csv'), index=False)
    with pd.option_context('display.float_format', lambda v: f'{v:.3f}'):
        print(tab.to_string(index=False))
    print(f'\nFiguras em: {FIGS}')


if __name__ == '__main__':
    main()
