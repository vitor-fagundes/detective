"""
gen_compare.py — MESMAS figuras do plots/gen_results2.py, mas separando cada
combinação ENGINE × ESCALA como uma série:
  D(200) D(250) D(FR) ...  (Detective / intuitivo → .results-detective)
  Q(200) Q(250) Q(FR) ...  (Q-learning baseline    → results-qlearning)

Codificação: COR = escala (200 azul, 250 âmbar, FR roxo); ESTILO = engine
(D sólido/○, Q tracejado/□). Mesma formatação/fontes (synapt) e painéis A/B/C/D.

Determinístico: ataque @ t=300s. FR: t de ataque por run (attack_manifest.csv).
Painel (D) Q(QUARANTINE): baseline Q não tem quarentena → fica em 0.
"""
import os, glob
import numpy as np, pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

plt.rcParams.update({
    'font.family':'DejaVu Sans','font.size':26,'axes.titlesize':28,'axes.titleweight':'bold',
    'axes.labelsize':26,'axes.labelweight':'bold','xtick.labelsize':24,'ytick.labelsize':24,
    'axes.spines.top':True,'axes.spines.right':True,'axes.edgecolor':'black','axes.linewidth':1.0,
    'axes.grid':True,'grid.color':'#DDDDDD','grid.linestyle':'--','grid.linewidth':0.8,'grid.alpha':0.6,
    'legend.frameon':True,'legend.fontsize':18,'legend.framealpha':0.95,
    'figure.facecolor':'white','axes.facecolor':'white','figure.dpi':150,
})

HERE = os.path.dirname(os.path.abspath(__file__)); PROJ = os.path.dirname(HERE)
DATA = os.path.join(HERE,'data'); FIGS = os.path.join(HERE,'figures')
os.makedirs(DATA, exist_ok=True); os.makedirs(FIGS, exist_ok=True)

WINDOW_PRE, WINDOW_POST, STEP = 30, 120, 5
REL_TIMES = np.arange(-WINDOW_PRE, WINDOW_POST + STEP, STEP)

# escala → (subdir, modo, cor)
# Paleta "Waiting for the Past" (schemecolor.com/waiting-for-the-past.php)
SCALES = [
    ('200', '200_attack5', 'det', '#3D7180'),  # Unique Blue
    ('250', '250_attack5', 'det', '#F07944'),  # Luxury Orange
    ('FR',  '200_fr',      'fr',  '#6B4242'),  # Dallas
]
# engine → (base, linestyle, marker)
ENGINES = [
    ('DET', os.path.join(PROJ, '.results-detective'), '-', 'o'),
    ('QL',  os.path.join(PROJ, 'results-qlearning'),  '-', 's'),
]
QL_COLOR = '#AB47BC'  # cor fixa do QL (roxo), sem depender da escala — mais contraste, sem pontilhado


def attack_times(scen_dir, mode):
    if mode == 'fr':
        man = os.path.join(scen_dir, 'attack_manifest.csv')
        if os.path.exists(man):
            df = pd.read_csv(man)
            return {int(r.run): int(r.attack_start) for r in df.itertuples()}
        return {}
    return None  # determinístico → 300


def load_one(base, subdir, mode, label):
    scen_dir = os.path.join(base, subdir)
    atk_map = attack_times(scen_dir, mode)
    run_rows, aligned = [], []
    for rd in sorted(glob.glob(os.path.join(scen_dir, 'run_*'))):
        f = os.path.join(rd, 'IntuitiveStats.csv')
        if not os.path.exists(f):
            continue
        run = int(os.path.basename(rd).split('_')[1])
        df = pd.read_csv(f)
        if df.empty:
            continue
        t0 = 300 if atk_map is None else atk_map.get(run, 300)
        ts = df['timestamp'].values.astype(float)
        sr = df['sr'].values.astype(float); qi = df['qi'].values.astype(float)
        pre = df[df.timestamp <= t0]; post = df[df.timestamp >= t0]
        run_rows.append({'series': label, 'run': run,
            'sr_pre': float(pre.sr.iloc[-1]) if len(pre) else float(sr[0]),
            'sr_min': float(post.sr.min()), 'sr_final': float(sr[-1]),
            'qi_final': float(df.qi.iloc[-1]),
            'atk_qquar': max(float(df['qAtkQuarHigh'].iloc[-1]), float(df['qAtkQuarLow'].iloc[-1])),
            'atk_epsilon': float(df['atkEpsilon'].iloc[-1])})
        for rel in REL_TIMES:
            t = t0 + rel
            if ts.min() <= t <= ts.max():
                aligned.append({'series': label, 'rel_time': rel,
                                'qi': float(np.interp(t, ts, qi)), 'sr': float(np.interp(t, ts, sr))})
    return pd.DataFrame(run_rows), pd.DataFrame(aligned)


def _save(fig, name):
    plt.tight_layout()
    fig.savefig(os.path.join(FIGS, name + '.pdf'), bbox_inches='tight')
    fig.savefig(os.path.join(FIGS, name + '.png'), bbox_inches='tight')
    plt.close(fig); print('  saved', name)


def plot_aligned(aligned, styles, metric, ylabel, fname, title=None):
    # formatação IDÊNTICA ao plots/gen_results2.py (só muda linestyle por engine)
    fig, ax = plt.subplots(figsize=(8, 5.5))
    if title: ax.set_title(title)
    for label, color, ls, mk in styles:
        sub = aligned[aligned.series == label]
        if sub.empty: continue
        agg = sub.groupby('rel_time')[metric].agg(['mean', 'std']).reset_index()
        ax.plot(agg['rel_time'], agg['mean'], color=color, linewidth=2.2, linestyle=ls, label=label)
        ax.fill_between(agg['rel_time'], agg['mean'] - agg['std'], agg['mean'] + agg['std'],
                        alpha=0.12, color=color)
    ax.axvline(0, color='red', linewidth=2, linestyle='--', alpha=0.75, label='Attack (t=0)')
    ax.set_xlabel('Time relative to attack (s)'); ax.set_ylabel(ylabel)
    ax.set_ylim(0.0, 1.03); ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v*100:.0f}%'))
    ax.set_xlim(-WINDOW_PRE, WINDOW_POST)
    ax.legend(loc='lower right', fontsize=18, ncol=1)
    _save(fig, fname)


def plot_run_metric(summary, styles, col, ylabel, fname, title, loc, ylim=None, yticks=None):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    if title: ax.set_title(title)
    for label, color, ls, mk in styles:
        sub = summary[summary.series == label].groupby('run')[col].mean().reset_index()
        if sub.empty: continue
        ax.plot(sub['run'], sub[col], color=color, linewidth=2, linestyle=ls,
                marker='o', markersize=3, label=label)
    ax.set_xlabel('Cumulative run'); ax.set_ylabel(ylabel)
    if ylim: ax.set_ylim(*ylim)
    if yticks: ax.set_yticks(yticks)
    ax.set_xlim(1, 35); ax.set_xticks([1, 5, 10, 15, 20, 25, 30, 35])
    ax.legend(loc=loc, fontsize=18, ncol=1)
    _save(fig, fname)


def plot_recovery(summary, styles, fname):
    labels = [s[0] for s in styles if not summary[summary.series == s[0]].empty]
    pre = [summary[summary.series == l]['sr_pre'].mean() for l in labels]
    mn  = [summary[summary.series == l]['sr_min'].mean() for l in labels]
    fin = [summary[summary.series == l]['sr_final'].mean() for l in labels]
    x = np.arange(len(labels)); w = 0.26
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w, pre, w, label='Pre-attack', color='#90CAF9', edgecolor='black', linewidth=0.6)
    ax.bar(x,     mn,  w, label='Peak impact', color='#EF9A9A', edgecolor='black', linewidth=0.6)
    ax.bar(x + w, fin, w, label='Post-recovery', color='#A5D6A7', edgecolor='black', linewidth=0.6)
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=14)
    ax.set_ylabel('Service Reachability'); ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v*100:.0f}%'))
    ax.legend(loc='lower center', ncol=1, fontsize=16)
    _save(fig, fname)


def main():
    styles, runs, aligns = [], [], []
    for eng, base, ls, mk in ENGINES:
        if not os.path.isdir(base):
            print(f'  (base {base} não existe)'); continue
        for scale, subdir, mode, color in SCALES:
            if eng == 'QL' and scale != '250':
                continue  # baseline Q-learning: comparativos só com escala 250
            label = f'{eng}({scale})'
            rr, al = load_one(base, subdir, mode, label)
            if rr.empty:
                print(f'  (sem dados p/ {label})'); continue
            eng_color = QL_COLOR if eng == 'QL' else color
            styles.append((label, eng_color, ls, mk)); runs.append(rr); aligns.append(al)
            print(f'  {label}: {len(rr)} runs')
    summary = pd.concat(runs, ignore_index=True)
    aligned = pd.concat(aligns, ignore_index=True)
    summary.to_csv(os.path.join(DATA, 'compare_summary_runs.csv'), index=False)

    print('\nGerando figuras...')
    plot_aligned(aligned, styles, 'qi', 'QI', 'fig_qi_attack', '(A)')
    plot_aligned(aligned, styles, 'sr', 'SR', 'fig_sr_attack', '(B)')
    plot_run_metric(summary, styles, 'atk_epsilon', 'Exploration (ε)', 'fig_attacker_epsilon',
                    '(C)', 'upper right', ylim=(None, 0.16), yticks=[0.05, 0.10, 0.15])
    # QL nunca quarentena (baseline sem detecção) -> a série fica sempre em 0, sem sentido no painel
    styles_no_ql = [s for s in styles if not s[0].startswith('QL')]
    plot_run_metric(summary, styles_no_ql, 'atk_qquar', 'Q(QUARANTINE)', 'fig_attacker_qquar',
                    '(D)', 'lower right', ylim=(0, 21), yticks=[0, 5, 10, 15, 20])
    plot_recovery(summary, styles, 'fig_recovery_summary')
    print('\nFiguras em:', FIGS)


if __name__ == '__main__':
    main()
