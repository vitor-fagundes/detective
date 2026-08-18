# DETECTIVE — Baseline Q-learning

> Branch **`detective-qlearning`**: adiciona um **baseline de Q-learning reativo** ao
> DETECTIVE para comparar contra o motor de aprendizado **intuitivo** (Dual-System).
> O baseline trata a **mesma falha** (UDP flood → saturação de líder → órfãos), mas
> **sem detecção/quarentena** — apenas recupera os órfãos com Q-learning puro.
>
> Projeto acadêmico — Vítor Fagundes · Orientadores: Prof. Aldri Santos (UFMG), Prof. Carlos Pedroso (UFPR)

---

## Visão Geral

O DETECTIVE é um IDS online baseado em aprendizado intuitivo para **ataques DoS internos** (UDP flood membro→líder) em redes IIoT clusterizadas. Ele detecta flooders (Z-score intra-cluster + threshold absoluto), quarentena os atacantes (Q-learning ε-greedy) e, quando um líder cai por saturação, recupera os órfãos com um agente **Dual-System** (System 1 intuitivo + System 2 deliberativo).

Esta branch adiciona um **modo alternativo por flag** — `--recoveryEngine=qlearning` — que **substitui todo esse maquinário** por um **Q-learning puro** portado do [sectional](https://github.com/vitor-fagundes/sectional), servindo de **baseline de ablação**: mostra o que a camada intuitiva agrega.

O modo intuitivo (default) permanece **byte-idêntico** — o `if` só desvia quando a flag está ligada.

---

## O baseline Q-learning (`--recoveryEngine=qlearning`)

**Escopo:** o ataque acontece, os líderes saturam (a falha), e o **Q-learning só recupera os órfãos**. Não há detecção nem quarentena.

### O que é DESLIGADO no modo QL
- **Detecção/quarentena inteira** (bloco `processAttackersIntuitively`, pulado):
  - `AnomalyDetector::detectFlooders()` (detector de flooder)
  - `AttackerDualSystem` (Q-table 3×2 do atacante)
  - `sendQuarantineOrder`, `globallyQuarantined`, smart-quarantine (doador de capability)
- **Dual-System intuitivo da recuperação** (desviado):
  - System 1 (recall intuitivo, `bestIntuitiveAction`)
  - System 2 com bias de `netLearning`
  - rede de conhecimento `R_int` (`updateIntuitive`)
  - gate `pThreat > θ₁`

### O que é USADO (maquinário compartilhado)
- `FloodAttack` + modelo de saturação (500 pkts → líder cai) — **a falha**
- Coleta de órfãos + similaridade (`simExisting`, `simOrphans`) + execução REALLOCATE/RECLUSTER
- Cálculo de QI/SR (telemetria)
- **`QLearningAgent`** — o cérebro do baseline

### O agente (`QLearningAgent.{cc,h}`)
Q-learning tabular puro **4×3**, ε-greedy, portado do sectional (isolado em `namespace qlbaseline`):

| Estados (2 similaridades) | Ações | Mapeamento no detective |
|---|---|---|
| `SIM_BOTH_HIGH` | `DO_NOT_ALLOCATE` | DO_NOTHING |
| `SIM_EXISTING_HIGH` | `REALLOCATE_EXISTING` | REALLOCATE |
| `SIM_ORPHAN_HIGH` | `FORM_NEW_CLUSTER` | RECLUSTER |
| `SIM_BOTH_MEDIUM` | | |

- Update: `Q(s,a) ← Q(s,a) + α[r + γ·maxQ(s') − Q(s,a)]`
- **Paridade com o intuitivo:** α=0.2, γ=0.9, ε inicial 0.15 → decai 0.97 → piso 0.02 (por ciclo com órfãos), **cumulativo entre runs** (persistido em `<knowledge>.qltable`).
- Recompensa proporcional à similaridade (estilo sectional-rl3): `+REWARD_BASE·sim` no acerto, −5 (órfão), −10 (inviável).

---

## Como Rodar

```bash
# na raiz do ns-3-dev
./ns3 build

# baseline QL — todos os cenários (det 200/250/300 + FR 200), 35 runs cumulativos cada
./scratch/detective/run_qlearning.sh

# por partes
./scratch/detective/run_qlearning.sh det    # só 200/250/300 determinístico
./scratch/detective/run_qlearning.sh fr      # só FR
./scratch/detective/run_qlearning.sh all quick  # smoke (3 runs)

# uma run manual
./ns3 run "scratch/detective/contaski --nNodes=200 --run=1 --nAttackers=10 \
  --attackMode=1 --attackStartTime=300 --recoveryEngine=qlearning \
  --knowledgePath=<dir>/knowledge.dat"
# → Q-table cumulativa salva em <dir>/knowledge.dat.qltable
```

### Estrutura de saída
```
results-qlearning/
├── 200_attack5/  250_attack5/  300_attack5/   (determinístico, 5 atk @ t=300)
│   ├── knowledge.dat.qltable                   (Q-table cumulativa do baseline)
│   └── run_001/ ... run_035/
│       ├── IntuitiveStats.csv                  (telemetria; atkEpsilon = ε do baseline)
│       └── qltable_snapshot.dat                (Q-table ao fim da run)
└── 200_fr/                                     (FR: início+qtd aleatórios; attack_manifest.csv)
```
> Os arquivos `Intuitive*`/`knowledge_snapshot.dat` aparecem por nome fixo no código; no modo QL a telemetria (QI/SR) é válida, mas os Q-values intuitivos ficam zerados. A Q-table real do baseline está em `qltable_snapshot.dat`.

---

## Comparação (pasta `plot/`)

| Arquivo | Gera |
|---|---|
| `plot/gen_compare.py` | figuras **DET vs QL** (QI/SR alinhados, ε, Q(QUARANTINE), recovery) — DET(200/250/FR) + **QL só em N=250** |
| `plot/compute_tables.py` | tabela de rede (Leaders/Sat/Orphans/Realloc/Recluster/SR) incl. o bloco **QL(250)** |

```bash
python3 plot/gen_compare.py       # figuras em plot/figures/
python3 plot/compute_tables.py    # tabelas (texto)
```
Lê de `.results-detective/` (intuitivo) e `results-qlearning/` (baseline).

---

## Resultados — Intuitivo vs Q-learning (N=250, 35 runs)

O baseline compara em **N=250** (o maior contraste). Sem detecção/quarentena, o QL sofre muito mais dano:

| Métrica | **Intuitivo** | **Q-learning** |
|---|---|---|
| Líderes saturados | 1.9 | **4.1** (2.2×) |
| Órfãos (pico) | 34.0 | **75.5** (2.2×) |
| **SR mínimo** (pior momento) | 83.5% | **66.8%** (−17 pts) |
| Realloc / Recluster | 48.8 / **0** | 35.9 / **74.1** |
| Recovery time (T_rec) | 7.7 s | **13.4 s** (~2×) |
| SR final | ~97% | ~97% |

**Leitura:** a camada intuitiva agrega **prevenção** — detecta e isola antes da saturação, preservando os líderes. Sem ela, o Q-learning **só reage**: perde ~2× mais líderes, mergulha 17 pontos mais fundo no SR, e precisa **reconstruir** clusters (recluster-pesado) em vez de **absorver** órfãos (realloc). Ambos recuperam o serviço no final, mas o baseline o faz de forma mais lenta e disruptiva. Segurança (recall/DR/precision) **não se aplica** ao baseline — ele não quarentena.

---

## Parâmetros do baseline

| Parâmetro | Valor | Origem |
|---|---|---|
| `--recoveryEngine` | `qlearning` (default `intuitive`) | flag nova |
| α (learning rate) | 0.20 | paridade `ALPHA_Q` |
| γ (discount) | 0.90 | paridade `GAMMA_Q` |
| ε (exploração) | 0.15 → 0.02 (decay 0.97) | paridade intuitivo |
| Q-table | 4 estados × 3 ações | sectional-rl3 |
| Falha (compartilhada) | flood 50 pkts/s, saturação 500 pkts | — |

---

## Arquivos desta branch

```
QLearningAgent.{cc,h}    novo: Q-learning puro 4×3 (namespace qlbaseline)
contaski.cc              + flag --recoveryEngine
NodeAPApplication.{cc,h} + instanciação do qlAgent, gate da quarentena (modo QL),
                           branch na recuperação (qlAgent vs Dual-System), persistência .qltable
run_qlearning.sh         novo: script de execução do baseline (todos os cenários)
plot/                    gen_compare.py (DET vs QL) + compute_tables.py + figuras/dados
```
