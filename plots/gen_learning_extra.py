"""
gen_learning_extra.py — 2 figuras extras no estilo do sectional:
  1) fig_decision_margin : Q-QUARANTINE vs Q-DoNothing (agente atacante, estado HIGH)
     ao longo dos runs cumulativos, com a "margem de decisão" preenchida.
     Análogo ao Q-ALOCAR/Q-IGNORAR do sectional.
  2) fig_radar           : radar de 3 eixos (Efficacy / Convergence / Preference)
     comparando as faixas de intensidade do FR (leve/médio/pesado),
     análogo ao radar de intensidades do sectional.

Cenário: 200_fr (Full Random, N=200, v1).
Saídas em plots2/figures/.
"""
import os, glob
import numpy as np, pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

plt.rcParams.update({
    'font.family': 'DejaVu Sans', 'font.size': 20,
    'axes.titlesize': 20, 'axes.titleweight': 'bold',
    'axes.labelsize': 20, 'axes.labelweight': 'bold',
    'xtick.labelsize': 20, 'ytick.labelsize': 20,
    'axes.spines.top': True, 'axes.spines.right': True,
    'axes.edgecolor': 'black', 'axes.linewidth': 1.0,
    'axes.grid': True, 'grid.color': '#DDDDDD', 'grid.linestyle': '--',
    'grid.linewidth': 0.8, 'grid.alpha': 0.6,
    'legend.frameon': True, 'legend.fontsize': 18, 'legend.framealpha': 0.95,
    'figure.facecolor': 'white', 'axes.facecolor': 'white', 'figure.dpi': 150,
})

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
SCEN = os.path.join(PROJ, 'results-detective', '200_fr')
FIGS = os.path.join(HERE, 'figures')
os.makedirs(FIGS, exist_ok=True)


def bucket_of(n):
    return 'Light (5-8)' if n <= 8 else ('Medium (9-14)' if n <= 14 else 'Heavy (15-20)')

BUCKETS = ['Light (5-8)', 'Medium (9-14)', 'Heavy (15-20)']
BCOLORS = {'Light (5-8)': '#66BB6A', 'Medium (9-14)': '#F9A825', 'Heavy (15-20)': '#EF5350'}


def load():
    man = pd.read_csv(os.path.join(SCEN, 'attack_manifest.csv'))
    natk = {int(r.run): int(r.n_attackers) for r in man.itertuples()}
    rows = []
    for rd in sorted(glob.glob(os.path.join(SCEN, 'run_*'))):
        f = os.path.join(rd, 'IntuitiveStats.csv')
        if not os.path.exists(f):
            continue
        run = int(os.path.basename(rd).split('_')[1])
        df = pd.read_csv(f)
        if df.empty or run not in natk:
            continue
        qq = float(df['qAtkQuarHigh'].iloc[-1]); qd = float(df['qAtkDNHigh'].iloc[-1])
        # recall do run (via colunas de quarentena — aprox. do log)
        rows.append({'run': run, 'natk': natk[run], 'bucket': bucket_of(natk[run]),
                     'qquar': qq, 'qdn': qd, 'dq': qq - qd,
                     'quar_total': int(df['actionsAttackerQuarantine'].sum())})
    return pd.DataFrame(rows).sort_values('run')


def _save(fig, name):
    plt.tight_layout()
    fig.savefig(os.path.join(FIGS, name + '.pdf'), bbox_inches='tight')
    fig.savefig(os.path.join(FIGS, name + '.png'), bbox_inches='tight')
    plt.close(fig)
    print('  saved', name)


def plot_decision_margin(d, name='fig_decision_margin'):
    d = d.sort_values('run')
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(d['run'], d['qquar'], color='#2E7D32', linewidth=2.5, marker='o',
            markersize=4, label='Q-QUARANTINE')
    ax.plot(d['run'], d['qdn'], color='#D32F2F', linewidth=2.5, marker='s',
            markersize=4, label='Q-DoNothing')
    ax.fill_between(d['run'], d['qdn'], d['qquar'], color='#C8E6C9', alpha=0.7,
                    label='Decision margin')
    ax.set_xlabel('Cumulative run'); ax.set_ylabel('Q-value')
    ax.set_xlim(d['run'].min(), d['run'].max())
    ax.legend(loc='center right')
    _save(fig, name)


def plot_radar(d, name='fig_radar'):
    # métricas por faixa
    metrics = {}
    for b in BUCKETS:
        g = d[d.bucket == b]
        if g.empty:
            continue
        recall = 100 * g.quar_total.sum() / g.natk.sum() if g.natk.sum() else 0
        metrics[b] = {'eff': recall, 'conv': g.qquar.mean(), 'pref': g.dq.mean()}
    # normalização relativa (máx entre faixas = 100) para Convergência e Preferência
    maxc = max(m['conv'] for m in metrics.values())
    maxp = max(m['pref'] for m in metrics.values())
    axes_lbl = ['Efficacy (%)', 'Convergence (Q)', 'Preference (ΔQ)']
    angles = np.linspace(0, 2*np.pi, len(axes_lbl), endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 7), subplot_kw=dict(polar=True))
    ax.set_theta_offset(np.pi/2); ax.set_theta_direction(-1)
    for b in BUCKETS:
        if b not in metrics:
            continue
        m = metrics[b]
        vals = [m['eff'], 100*m['conv']/maxc, 100*m['pref']/maxp]
        vals += vals[:1]
        ax.plot(angles, vals, color=BCOLORS[b], linewidth=2.5, marker='o', label=b)
        ax.fill(angles, vals, color=BCOLORS[b], alpha=0.12)
    ax.set_xticks(angles[:-1]); ax.set_xticklabels(axes_lbl, fontsize=17)
    ax.set_ylim(0, 100); ax.set_yticks([25, 50, 75, 100])
    ax.set_yticklabels(['25', '50', '75', '100'], fontsize=13, color='gray')
    ax.set_title('Attacker learning vs attack intensity  ·  FR (N=200)',
                 fontsize=17, fontweight='bold', pad=30)
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.08), ncol=2, fontsize=16)
    _save(fig, name)
    return metrics


d = load()
print(f'{len(d)} runs')
plot_decision_margin(d)
m = plot_radar(d)
print('\nMétricas do radar (Efficacy% | Convergence Q | Preference ΔQ):')
for b, v in m.items():
    print(f'  {b:15s} eff={v["eff"]:5.1f}  conv={v["conv"]:5.2f}  pref={v["pref"]:5.2f}')
