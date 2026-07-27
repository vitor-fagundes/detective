"""
gen_results2.py — mesmas 4 figuras do plots/gen_detective_results.py, porém
ADICIONANDO o cenário FR (Full Random, N=200) como uma série a mais.

Séries plotadas (results-detective/):
  200_attack5  → "N=200"        baseline v1 (5 atacantes fixos @ t=300s)
  250_attack5  → "N=250"        baseline v1
  200_fr      → "FR (N=200)"  ataque com tempo+quantidade aleatórios por run

Diferença técnica vs o script original: o início do ataque varia por run no FR
(lido de attack_manifest.csv), então o alinhamento ao evento é feito por
INTERPOLAÇÃO (np.interp) em vez de match exato de timestamp. Para os baselines
(início fixo em 300s, parseado do log) o resultado é idêntico ao original.

Saídas em plots2/:
  data/summary_runs.csv
  data/summary_by_scenario.csv
  figures/fig_qi_attack.{pdf,png}
  figures/fig_sr_attack.{pdf,png}
  figures/fig_attacker_qquar.{pdf,png}
  figures/fig_attacker_epsilon.{pdf,png}
  figures/fig_recovery_summary.{pdf,png}

Uso:
  python3 plots2/gen_results2.py
"""
import os
import re
import glob
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
warnings.filterwarnings('ignore')

# rcParams estilo synapt, com fontes AUMENTADAS (4 painéis lado a lado no paper)
plt.rcParams.update({
    'font.family':        'DejaVu Sans',
    'font.size':          26,
    'axes.titlesize':     28,
    'axes.titleweight':   'bold',
    'axes.labelsize':     26,
    'axes.labelweight':   'bold',
    'xtick.labelsize':    24,
    'ytick.labelsize':    24,
    'axes.spines.top':    True,
    'axes.spines.right':  True,
    'axes.edgecolor':     'black',
    'axes.linewidth':     1.0,
    'axes.grid':          True,
    'grid.color':         '#DDDDDD',
    'grid.linestyle':     '--',
    'grid.linewidth':     0.8,
    'grid.alpha':         0.6,
    'legend.frameon':     True,
    'legend.fontsize':    20,
    'legend.framealpha':  0.95,
    'figure.facecolor':   'white',
    'axes.facecolor':     'white',
    'figure.dpi':         150,
})

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)                       # scratch/detective
RESULTS = os.path.join(PROJ, 'results-detective')
DATA = os.path.join(HERE, 'data')
FIGS = os.path.join(HERE, 'figures')
os.makedirs(DATA, exist_ok=True)
os.makedirs(FIGS, exist_ok=True)

WINDOW_PRE, WINDOW_POST, STEP = 30, 120, 5
REL_TIMES = np.arange(-WINDOW_PRE, WINDOW_POST + STEP, STEP)
ATTACK_RE = re.compile(r'in[íi]cio=(\d+)')

# Ordem, rótulo e cor de cada série (scenario dir basename → config)
SERIES = [
    ('200_attack5', 'N=200',       '#42A5F5'),
    ('250_attack5', 'N=250',       '#F9A825'),
    ('200_fr',     'FR (N=200)', '#AB47BC'),
]


def attack_times(scen_dir):
    """run → tempo de início do ataque. Usa attack_manifest.csv se existir
    (FR, início variável), senão parseia do simulation.log (baseline fixo)."""
    man = os.path.join(scen_dir, 'attack_manifest.csv')
    if os.path.exists(man):
        df = pd.read_csv(man)
        return {int(r.run): int(r.attack_start) for r in df.itertuples()}
    times = {}
    for rd in glob.glob(os.path.join(scen_dir, 'run_*')):
        run = int(os.path.basename(rd).split('_')[1])
        log = os.path.join(rd, 'simulation.log')
        t = 300
        if os.path.exists(log):
            with open(log, errors='ignore') as f:
                for line in f:
                    m = ATTACK_RE.search(line)
                    if m:
                        t = int(m.group(1)); break
        times[run] = t
    return times


def load_scenario(scen_dir, label):
    atk_map = attack_times(scen_dir)
    run_rows, aligned = [], []
    for rd in sorted(glob.glob(os.path.join(scen_dir, 'run_*'))):
        stats = os.path.join(rd, 'IntuitiveStats.csv')
        if not os.path.exists(stats):
            continue
        run = int(os.path.basename(rd).split('_')[1])
        df = pd.read_csv(stats)
        if df.empty:
            continue
        atk = atk_map.get(run, 300)
        ts = df['timestamp'].values.astype(float)
        sr = df['sr'].values.astype(float)
        qi = df['qi'].values.astype(float)

        pre = df[df['timestamp'] <= atk]
        post = df[df['timestamp'] >= atk]
        qi_pre = float(pre['qi'].iloc[-1]) if len(pre) else float(df['qi'].iloc[0])
        sr_pre = float(pre['sr'].iloc[-1]) if len(pre) else float(df['sr'].iloc[0])
        run_rows.append({
            'series': label, 'run': run,
            'qi_pre': qi_pre, 'sr_pre': sr_pre,
            'qi_min': float(post['qi'].min()), 'sr_min': float(post['sr'].min()),
            'qi_final': float(df['qi'].iloc[-1]), 'sr_final': float(df['sr'].iloc[-1]),
            'leaders_down_total': int(df['leadersDownThisCycle'].sum()),
            'orphans_peak': int(df['totalOrphans'].max()),
            'reallocate_final': int(df['actionsReallocate'].iloc[-1]),
            'suspects_total': int(df['suspectsCount'].sum()),
            'atk_quar_total': int(df['actionsAttackerQuarantine'].sum()),
            'atk_qquar': max(float(df['qAtkQuarHigh'].iloc[-1]), float(df['qAtkQuarLow'].iloc[-1])),
            'atk_epsilon': float(df['atkEpsilon'].iloc[-1]),
            'net_learning': float(df['netLearning'].iloc[-1]),
        })
        # alinhamento por interpolação (início do ataque = t=0)
        for rel in REL_TIMES:
            t = atk + rel
            if ts.min() <= t <= ts.max():
                aligned.append({'series': label, 'rel_time': rel,
                                'qi': float(np.interp(t, ts, qi)),
                                'sr': float(np.interp(t, ts, sr))})
    return pd.DataFrame(run_rows), pd.DataFrame(aligned)


def plot_aligned(aligned_all, order_colors, metric, ylabel, fname, title=None):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    if title:
        ax.set_title(title)
    for label, color in order_colors:
        sub = aligned_all[aligned_all['series'] == label]
        if sub.empty:
            continue
        agg = sub.groupby('rel_time')[metric].agg(['mean', 'std']).reset_index()
        ax.plot(agg['rel_time'], agg['mean'], color=color, linewidth=2.2, label=label)
        ax.fill_between(agg['rel_time'], agg['mean'] - agg['std'], agg['mean'] + agg['std'],
                        alpha=0.15, color=color)
    ax.axvline(0, color='red', linewidth=2, linestyle='--', alpha=0.75, label='Attack (t=0)')
    ax.set_xlabel('Time relative to attack (s)')
    ax.set_ylabel(ylabel)
    ax.set_ylim(0.0, 1.03)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v*100:.0f}%'))
    ax.set_xlim(-WINDOW_PRE, WINDOW_POST)
    ax.legend(loc='lower right')
    _save(fig, fname)


def plot_attacker_qquar(summary, order_colors, fname, title=None):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    if title:
        ax.set_title(title)
    for label, color in order_colors:
        sub = summary[summary['series'] == label].sort_values('run')
        if sub.empty:
            continue
        ax.plot(sub['run'], sub['atk_qquar'], color=color, linewidth=2, marker='o',
                markersize=3, label=label)
    ax.set_xlabel('Cumulative run'); ax.set_ylabel('Atk Q(QUARANTINE)')
    ax.legend(loc='lower right')
    _save(fig, fname)


def plot_attacker_epsilon(summary, order_colors, fname, title=None):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    if title:
        ax.set_title(title)
    for label, color in order_colors:
        sub = summary[summary['series'] == label].sort_values('run')
        if sub.empty:
            continue
        ax.plot(sub['run'], sub['atk_epsilon'], color=color, linewidth=2, marker='o',
                markersize=3, label=label)
    ax.set_xlabel('Cumulative run'); ax.set_ylabel('Atk exploration (ε)')
    ax.legend(loc='upper right')
    _save(fig, fname)


def plot_recovery_summary(summary, order_colors, fname):
    labels = [l for l, _ in order_colors if not summary[summary.series == l].empty]
    pre = [summary[summary.series == l]['sr_pre'].mean() for l in labels]
    mn = [summary[summary.series == l]['sr_min'].mean() for l in labels]
    fin = [summary[summary.series == l]['sr_final'].mean() for l in labels]
    x = np.arange(len(labels)); w = 0.26
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - w, pre, w, label='Pre-attack', color='#90CAF9', edgecolor='black', linewidth=0.6)
    ax.bar(x,     mn,  w, label='Peak impact', color='#EF9A9A', edgecolor='black', linewidth=0.6)
    ax.bar(x + w, fin, w, label='Post-recovery', color='#A5D6A7', edgecolor='black', linewidth=0.6)
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=14)
    ax.set_ylabel('Service Reachability'); ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v*100:.0f}%'))
    ax.legend(loc='lower center', ncol=3, fontsize=12)
    _save(fig, fname)


def _save(fig, fname):
    plt.tight_layout()
    base = os.path.join(FIGS, fname)
    fig.savefig(base + '.pdf', bbox_inches='tight')
    fig.savefig(base + '.png', bbox_inches='tight')
    plt.close(fig)
    print(f'  saved {fname}.pdf/.png')


def main():
    all_runs, all_aligned, order_colors = [], [], []
    for basename, label, color in SERIES:
        scen = os.path.join(RESULTS, basename)
        if not os.path.isdir(scen) or not glob.glob(os.path.join(scen, 'run_*', 'IntuitiveStats.csv')):
            print(f'  (pulando {basename}: sem dados)')
            continue
        rl, al = load_scenario(scen, label)
        all_runs.append(rl); all_aligned.append(al)
        order_colors.append((label, color))
        print(f'  {basename} → "{label}": {len(rl)} runs, {len(al)} amostras alinhadas')

    if not all_runs:
        print('Nenhum cenário encontrado.')
        return
    summary = pd.concat(all_runs, ignore_index=True)
    aligned = pd.concat(all_aligned, ignore_index=True)
    summary.to_csv(os.path.join(DATA, 'summary_runs.csv'), index=False)

    print('\nGerando figuras...')
    plot_aligned(aligned, order_colors, 'qi', 'Quality Index', 'fig_qi_attack', title='(A)')
    plot_aligned(aligned, order_colors, 'sr', 'Service Reachability', 'fig_sr_attack', title='(B)')
    plot_attacker_epsilon(summary, order_colors, 'fig_attacker_epsilon', title='(C)')
    plot_attacker_qquar(summary, order_colors, 'fig_attacker_qquar', title='(D)')
    plot_recovery_summary(summary, order_colors, 'fig_recovery_summary')

    print('\n=== RESUMO POR SÉRIE ===')
    rows = []
    for label, _ in order_colors:
        g = summary[summary.series == label]
        rows.append({
            'series': label, 'runs': len(g),
            'sr_pre': g.sr_pre.mean(), 'sr_min': g.sr_min.mean(), 'sr_final': g.sr_final.mean(),
            'qi_final': g.qi_final.mean(),
            'leaders_down': g.leaders_down_total.mean(),
            'orphans_peak': g.orphans_peak.mean(),
            'quar_per_run': g.atk_quar_total.mean(),
        })
    tab = pd.DataFrame(rows)
    tab.to_csv(os.path.join(DATA, 'summary_by_scenario.csv'), index=False)
    with pd.option_context('display.float_format', lambda v: f'{v:.3f}'):
        print(tab.to_string(index=False))
    print(f'\nFiguras em: {FIGS}')


if __name__ == '__main__':
    main()
