# DETECTIVE

> Framework de defesa contra ataques UDP DoS/DDoS internos em redes IIoT, combinando
> detecção precoce via aprendizado intuitivo dual-system e recuperação reativa de
> topologia quando a prevenção falha.
>
> Projeto acadêmico — Vítor Fagundes
> Orientadores: Prof. Aldri Santos (UFMG) e Prof. Carlos Pedroso (UFPR)

---

## Visão Geral

O DETECTIVE é uma extensão do framework [SYNAPT](https://github.com/vitor-fagundes/synapt) com foco em **detecção e contenção de ataques de saturação intra-rede**. Enquanto SYNAPT modela resiliência da topologia frente a falhas de líder, o DETECTIVE substitui esse cenário por **ataques UDP flood originados de nós comprometidos (insider threat)**.

A arquitetura mantém o motor de aprendizado intuitivo do SYNAPT (Dual-System S1/S2, aprendizado distribuído, detecção de anomalias) e adiciona três engrenagens novas:

1. **Detecção dual de fluxo anômalo** — Z-score intra-cluster + threshold absoluto
2. **AttackerDualSystem** — Q-table 3×2 paralela ao motor de órfãos, com ações `DO_NOTHING` e `QUARANTINE`
3. **Modelo de saturação de líder** — simula o efeito kinético do DDoS: quando um líder recebe mais que `FLOOD_SATURATION_THRESHOLD` pacotes acumulados, ele cai (`alive=false`)

Quando a quarentena é rápida o suficiente, o líder sobrevive. Quando o atacante satura antes da detecção, o líder cai e o pipeline de órfãos do SYNAPT entra em ação para reabsorver os membros saudáveis em clusters vizinhos.

**Cenários avaliados no paper**: dois determinísticos (**N=200** e **N=250**, 5 atacantes fixos em `t=300s`) e um **FR (Full Random, N=200)** em que início, quantidade e escolha dos atacantes são aleatórios por rodada. Ver [Cenário FR](#cenário-fr-full-random). *(N=300 existe no código — `THRESHOLD_S1_300`, `ξ` para N≥300 — mas foi retirado do paper.)*

---

## Arquitetura

```
contaski.cc              — Entrada principal: configura rede, seleciona atacantes, agenda ataque
NodeApplication.cc/h     — Aplicação de cada nó: clustering, beacon, similaridade, eleição,
                           contador de flood recebido, modelo de saturação
NodeAPApplication.cc/h   — Orquestrador AP: ciclo intuitivo, pipelines de defesa e recuperação,
                           smart-quarantine, telemetria CSV
IntuitiveLearning.cc/h   — Motor: DistributedLearning, DualSystemResponse (órfão 3×3),
                           AttackerDualSystem (atacante 3×2), KnowledgeNetworks
AnomalyDetector.cc/h     — Detecção: Z-score multivariado (líderes) + detectFlooders
                           (Z relativo + threshold absoluto, intra-cluster)
FloodAttack.cc/h         — Módulo isolado de ataque UDP flood; target fixo após startFlood
capabilities.cc/h        — Vetores de capacidades e similaridade (Eq. 1 do CONTASKI)
task.cc/h                — Modelo de tarefas com capacidades requeridas e quorum
constants.h              — Enum de tipos de mensagem (inclui FloodPacket, QuarantineOrder)
MyTag.cc/h               — Tag NS-3 para identificação de tipo de mensagem UDP
run_detective.sh         — Script de execução cumulativa determinística (scales × 35 runs)
run_detective_fr.sh      — Script do cenário FR (Full Random): tudo aleatório por run, N=200
plots/                   — Scripts de geração das figuras + tabelas do paper:
                           gen_results2.py, gen_learning_extra.py, compute_tables.py
```

---

## Fluxo de Simulação

| Instante | Evento |
|---|---|
| `t = 0–60 s` | Beaconing: nós descobrem vizinhos |
| `t = 60–90 s` | Disseminação de capacidades |
| `t = 90,5 s` | Clusterização + eleição de líder (idêntico a sectional/synapt) |
| `t = 150 s` | AP inicia despacho de tarefas |
| `t = 160 s` | **Primeiro ciclo intuitivo** (após estabilização pós-clustering) |
| `t = 165, 170, ...` | Ciclos a cada 5 s até fim da simulação |
| `t = 200 s` | **Seleção de atacantes** (operator-side, via `std::random_device`) |
| `t = 300 s` | **Ataque começa** — atacantes enviam UDP flood ao alvo |
| `t = 900 s` | Fim da simulação |

---

## Pipeline de Defesa (a cada 5 s, dentro de `intuitiveDecisionCycle`)

O AP executa **8 etapas em sequência**:

### [0] TTL cleanup do `globallyQuarantined`
Remove IPs cuja quarentena expirou (`QUARANTINE_TTL = 60s`). Permite reavaliação de nós que voltaram a ser observados após o intervalo.

### [1] Atualização dos clusters
Recontabiliza membros reais via `myLeader` de cada nó vivo. Atualiza `initialMemberCount` na alta.

### [2] Detecção de anomalias em líderes
Para cada líder, computa três features: `taskAcceptRate`, `timeSinceContact`, `clusterHealthRatio`. AnomalyDetector aplica ensemble Z-score global + temporal (voto duplo). Nós anômalos recebem penalidade no Li.

### [3] Detecção de fluxo anômalo intra-cluster (`detectFlooders`)
Para cada cluster, computa Z-score dos contadores de pacotes por origem reportados via heartbeat estendido. Detecção dual:
- **Z-score relativo**: outliers no baseline do próprio cluster (sensível a anomalias contextuais)
- **Threshold absoluto** (`>= 100 pkts/janela`): captura atacantes mesmo quando o Z colapsa por alta proporção de atacantes no cluster

União dos dois conjuntos. Score reportado = `max(z_relativo, z_absoluto)`.

### [4] Aprendizado distribuído
Difusão de capacidade de aprendizado `L_i` entre vizinhos (mesma equação do SYNAPT):
```
ΔLi = Σj β · (Lj − Li) + ξi
Li(t+1) = clip(Li(t) + α · ΔLi, 0, 1)
```

### [5] AttackerDualSystem (Q-table 3×2 paralela)
Para cada suspeito detectado:
1. **Recompensa observacional** da decisão anterior (sem ground-truth):
   - `QUARANTINE` → +10 se cluster ficou limpo, −2 se outros suspeitos persistem
   - `DO_NOTHING` → +1 se suspeito sumiu, −2 se persistiu em SUSPECT_LOW, −5 se escalou para SUSPECT_HIGH
2. **Decisão atual** via ε-greedy sobre Q[state, action]:
   - Estados: `CLEAR` (z<2), `SUSPECT_LOW` (2≤z<4), `SUSPECT_HIGH` (z≥4)
   - Ações: `DO_NOTHING`, `QUARANTINE`

### [6] Smart-quarantine (capability-aware)
Antes de emitir `QuarantineOrder`:
- Verifica se a remoção do suspeito quebra alguma capability única do cluster (`capsLostIfRemoved`)
- Se sim, procura **doador compatível** em outro cluster (`findCapabilityDonor`):
  - Tem a cap faltante
  - Sua remoção do cluster doador NÃO quebra redundância
  - Maior score por cobertura, desempate por similaridade
- Transfere via `removeClusterMember` + `addClusterMember` + `setMyLeader`
- Emite `QuarantineOrder` ao líder afetado

Sob `SIMILARITY_THRESHOLD=0.95` (padrão), o caminho de transferência raramente dispara — clusters por construção têm capabilities virtualmente idênticas, e a remoção de qualquer membro preserva todas as caps. O código fica como rede de segurança defensiva, validado em runtime sob threshold relaxado.

### [7] Processamento de órfãos (synapt motor, reativo)
Quando líderes caem por saturação, seus membros saudáveis viram órfãos. O pipeline herdado do SYNAPT processa cada órfão via Q-table 3×3:
- **Filtros aplicados** (específicos do DETECTIVE):
  - Líderes mortos não entram (são filtrados por `alive=false`)
  - Atacantes detectados (em `globallyQuarantined`) não entram (preserva quarentena)
- Estados: `EXISTING_VIABLE`, `ORPHAN_ONLY`, `NO_MATCH`
- Ações: `DO_NOTHING`, `REALLOCATE_TO_EXISTING`, `RECLUSTER_ORPHANS`
- Recompensa: `REWARD_BASE × similaridade` (proporcional à qualidade do match)

### [8] Persistência e decaimento
- ε do AttackerDualSystem decai em ciclos com suspeitos (`× 0.97`, piso 0.02)
- `knowledge.dat` salvo ao fim da rodada com Q-tables, ε, R_int e contadores
- Carregado no início da próxima rodada (transferência cumulativa de conhecimento)

---

## Modelo de Saturação do Líder

NS-3 não modela exaustão de recurso por padrão. Para simular o efeito kinético do DDoS, cada nó mantém um contador `totalFloodReceived` que cresce a cada `FloodPacket` recebido enquanto for líder. Quando atinge `FLOOD_SATURATION_THRESHOLD`:

```cpp
this->alive = false;
if (this->floodAttack) this->floodAttack->stop();
```

A partir desse momento:
- Líder não envia heartbeats
- Não processa nem dispatcha tarefas
- AP detecta morte no próximo ciclo via `isNodeAlive()` polling
- Membros do cluster viram órfãos → pipeline de recuperação

**Calibração de `FLOOD_SATURATION_THRESHOLD`** com `attackRate=50pkts/s`:

| Threshold | Tempo até saturar (1 atacante) | 3 atacantes/cluster | Sweet spot |
|---|---|---|---|
| 250 | 5s | 1.7s | saturação dominante |
| **500** (padrão) | **10s** | **3.3s** | **mix interessante** |
| 1000 | 20s | 6.7s | framework quase sempre vence |

---

## Threat Model — Atacante Consciente

A seleção dos atacantes é feita pelo "operador do experimento" em `contaski.cc` (não pelo AP), usando entropia do SO (`std::random_device`). Isso desacopla o setup adversário do componente defensivo (AP), respeitando a separação de papéis.

Cada nó comprometido faz **verificação local pré-ataque** em `startFlood()`:
- Só ataca se `myLeader != Any && myLeader != self` (sanity check)
- Não exige tasks recebidas: clusters reais podem estar idle (mesmo fenômeno presente em sectional/synapt) e ainda assim ser alvos válidos

Modela um adversário insider com **consciência mínima da topologia local**, sem oráculo do simulador. O ataque tem **target fixo** após `startFlood()` — uma vez configurado o alvo (líder atual), o atacante não se redireciona.

---

## Parâmetros

### Aprendizado Distribuído (herdado do SYNAPT)

| Parâmetro | Valor | Descrição |
|---|---|---|
| `ALPHA_LEARN` (α) | 0.20 | Taxa de atualização do Li |
| `BETA_INFLUENCE` (β) | 0.10 | Peso da influência de vizinhos em ΔLi |
| `ξ_anomalous` | −0.05 (N≤250) / −0.033 (N≥300) | Penalidade ambiental para anômalos |

### Q-Learning (Sistema 2 — órfão e atacante)

| Parâmetro | Valor | Descrição |
|---|---|---|
| `ALPHA_Q` | 0.20 | Taxa de aprendizado da Q-table |
| `GAMMA_Q` | 0.90 | Fator de desconto |
| `ε` inicial | 0.15 | Exploração na rodada 1 |
| `ε_decay` | 0.97 | Fator de decaimento por ciclo com suspeitos/órfãos |
| `ε_min` | 0.02 | Piso de exploração garantido |

### Dual-System (Limiares)

| Parâmetro | Valor | Descrição |
|---|---|---|
| `THRESHOLD_S1` | 0.20 (N≤250) / 0.245 (N≥300) | pThreat acima → System 1 |
| `THRESHOLD_S2` | 0.60 | QI ou SR abaixo → S2 prevalece |
| `REALLOCATION_THRESHOLD` | 0.85 | Similaridade mínima para REALLOCATE |
| `CLUSTERING_THRESHOLD` | 0.85 | Similaridade mínima para RECLUSTER |

### AttackerDualSystem (novo no DETECTIVE)

| Parâmetro | Valor | Descrição |
|---|---|---|
| `ATTACKER_Z_LOW` | 2.0 | Z mínimo para SUSPECT_LOW |
| `ATTACKER_Z_HIGH` | 4.0 | Z mínimo para SUSPECT_HIGH |
| `ABSOLUTE_FLOOD_THRESHOLD` | 100 pkts/janela | Detector de fallback absoluto |
| `QUARANTINE_TTL` | 60.0 s | Tempo até IP poder ser re-quarentenado |
| `FLOOD_SATURATION_THRESHOLD` | 500 pkts | Saturação do líder por flood acumulado |

### Recompensas (atacante — observacional)

| Situação | Reward |
|---|---|
| QUARANTINE, cluster fica sem suspeitos | +10 |
| QUARANTINE, outros suspeitos persistem | −2 |
| DO_NOTHING, suspeito sumiu | +1 |
| DO_NOTHING, suspeito persiste em SUSPECT_LOW | −2 |
| DO_NOTHING, suspeito escalou para SUSPECT_HIGH | −5 |

### Recompensas (órfão — herdado SYNAPT)

| Situação | Reward |
|---|---|
| REALLOCATE viável | `REWARD_BASE × bestSimExisting` |
| RECLUSTER viável | `REWARD_BASE × simOrphans` |
| Ação inviável | `−10.0` |
| DO_NOTHING com órfão | `−5.0` |

### Simulação

| Parâmetro | Valor |
|---|---|
| `decisionInterval` | 5.0 s |
| Primeiro ciclo intuitivo | t = 160 s |
| Início do ataque | t = 300 s (CLI: `--attackStartTime`) |
| `attackRate` | 50.0 pkts/s |
| `attackPayloadSize` | 64 bytes |
| `nAttackers` | 5 (padrão; `--nAttackers`) |
| `MAX_INTUITIVE_HISTORY` | 100 (janela deslizante do R_int) |
| `SIMTIME` | 900 s |

---

## CLI

```bash
# Execução básica (5 atacantes, threshold 500)
./ns3 run "scratch/detective/contaski --nNodes=200 --run=1 --nAttackers=5"

# Calibração custom
./ns3 run "scratch/detective/contaski \
  --nNodes=300 --run=1 \
  --nAttackers=10 \
  --attackMode=1 \
  --attackStartTime=300 \
  --attackRate=50 \
  --attackPayloadSize=64 \
  --floodSaturationThreshold=750 \
  --knowledgePath=results-detective/300_attack10/knowledge.dat"

# Desabilitar modelo de saturação (--floodSaturationThreshold=0)
./ns3 run "scratch/detective/contaski --nNodes=200 --floodSaturationThreshold=0 --nAttackers=5"
```

| Flag | Default | Descrição |
|---|---|---|
| `--nNodes` | 3 | Tamanho da rede |
| `--run` | 0 | Seed do NS-3 RngSeedManager (mantenha fixo entre rodadas) |
| `--decisionInterval` | 5.0 | Intervalo entre ciclos intuitivos (s) |
| `--knowledgePath` | "" | Path do knowledge.dat (carrega/salva) |
| `--nAttackers` | 0 | Quantos nós serão comprometidos (0 = sem ataque) |
| `--attackStartTime` | 300.0 | Momento de início do flood (s) |
| `--attackRate` | 50.0 | Taxa do flood (pkts/s) |
| `--attackPayloadSize` | 64 | Tamanho do payload (bytes) |
| `--attackMode` | 1 | 1=membro→líder, 2=líder→AP (reservado para v2) |
| `--floodSaturationThreshold` | 500 | Pacotes para líder cair (0 = desabilitado) |

---

## Script de Execução (paper)

`run_detective.sh` automatiza a execução cumulativa de 35 rodadas por escala, herdando convenções de sectional/synapt:

- `--run=1` fixo em todas as execuções
- Capabilities regenerada por rodada (`std::random_device`)
- `knowledge.dat` cumulativo entre rodadas (transferência de conhecimento)
- Resume parcial: pula runs que já têm `IntuitiveStats.csv`
- Trap em SIGINT/SIGTERM: mata árvore de processos limpa em Ctrl+C
- `--no-build` em cada `./ns3 run` (build apenas no início)

```bash
# Padrão: N={200, 250, 300}, 35 runs cada
./scratch/detective/run_detective.sh

# Quick (3 runs por scale)
./scratch/detective/run_detective.sh quick

# Uma scale específica
./scratch/detective/run_detective.sh scale 250

# Overrides via env var
N_RUNS=10 ./scratch/detective/run_detective.sh
SCALES="200 350" ./scratch/detective/run_detective.sh
N_ATTACKERS=10 SAT_THRESHOLD=750 ./scratch/detective/run_detective.sh
```

---

## Cenário FR (Full Random)

Além dos cenários determinísticos (5 atacantes fixos em `t=300s`), o DETECTIVE inclui o cenário **FR (Full Random)** para o paper, em que **tudo é aleatório por rodada**:

| Dimensão | Sorteio (por run) |
|---|---|
| Início do ataque | uniforme em **[200, 700] s** (sempre após o warmup completo, `t≈160`) |
| Nº de atacantes | uniforme em **[5, 20]** = 2.5%–10% de N=200 |
| Quais nós | sorteio uniforme interno (`std::random_device`) |

Escala única **N=200**, v1 (membro→líder), 35 runs cumulativos. Os parâmetros sorteados de cada run são gravados em `attack_manifest.csv` (`run, attack_start, n_attackers`) para reprodutibilidade/auditoria.

```bash
# FR completo (35 runs)
./scratch/detective/run_detective_fr.sh fr

# Smoke (3 runs)
./scratch/detective/run_detective_fr.sh fr quick

# Overrides via env var
N_RUNS=10 ./scratch/detective/run_detective_fr.sh fr
```

Saída em `results-detective/200_fr/` (mesma estrutura das outras + `attack_manifest.csv`).

**Por que o recall cai com a intensidade** — a detecção usa Z-score **relativo intra-cluster** + threshold absoluto. Com mais atacantes por cluster, o líder satura (500 pkts) **antes** do ciclo de decisão de 5s conseguir quarentenar → o atacante "vence a corrida" e vira um falso-negativo. Não é falha de detecção (a defesa sempre percebe o ataque, DR=100%), é limite temporal. Mesmo assim o serviço se recupera: no FR a recuperação é dominada por **RECLUSTER** (97/run vs 6 de REALLOCATE), ao contrário dos determinísticos que são 100% REALLOCATE — porque muitos líderes caem juntos e não sobra vizinho saudável para absorver os órfãos.

---

## Plots e Figuras

A pasta `plots/` gera as figuras e tabelas do paper (fontes no estilo synapt: DejaVu Sans, corpo grande, bordas visíveis):

| Script | Gera |
|---|---|
| `gen_results2.py` | 4 painéis A/B/C/D — QI **(A)** e SR **(B)** alinhados ao ataque; ε **(C)** e Q(QUARANTINE) **(D)** por run cumulativo — 3 séries (N=200, N=250, FR); + `fig_recovery_summary` |
| `gen_learning_extra.py` | `fig_decision_margin` (Q-QUARANTINE vs Q-DoNothing, FR) e `fig_radar` (eficácia/convergência/preferência por faixa de intensidade) |
| `compute_tables.py` | valores das tabelas de rede e de segurança (matriz de confusão pooled, ADT/AMT/Trec); reproduz o baseline publicado exatamente |

Figuras em `plots/figures/` (`.pdf` + `.png`), dados em `plots/data/`.

```bash
python3 plots/gen_results2.py        # figuras A-D + recovery
python3 plots/gen_learning_extra.py  # decision margin + radar
python3 plots/compute_tables.py      # tabelas (rede + segurança)
```

---

## Estrutura de Saída

```
scratch/detective/results-detective/
├── 200_attack5/
│   ├── knowledge.dat                         (cumulativo, herdado entre runs)
│   ├── run_001/
│   │   ├── simulation.log                    (stdout completo)
│   │   ├── IntuitiveStats.csv                (31 colunas — telemetria por ciclo)
│   │   ├── IntuitiveQValues.txt              (Q-tables finais: órfão 3×3 + atacante 3×2)
│   │   ├── APStats.txt                       (tarefas dispatchadas vs aceitas)
│   │   ├── knowledge_snapshot.dat            (snapshot do knowledge ao fim)
│   │   ├── capacitiesFile-200-contaski.txt   (caps geradas para esta run)
│   │   └── tasksFile-200.txt                 (tarefas geradas para esta run)
│   ├── run_002/
│   └── ...
├── 250_attack5/
├── 300_attack5/
└── 200_fr/                                     (cenário FR — Full Random)
    ├── knowledge.dat
    ├── attack_manifest.csv                     (run, attack_start, n_attackers — params sorteados)
    ├── run_001/ ...
```

### Colunas do `IntuitiveStats.csv`

| Categoria | Colunas |
|---|---|
| Identidade | `timestamp` |
| Motor SYNAPT | `qi`, `sr`, `tii`, `arf`, `meanRho`, `netLearning`, `pThreat` |
| Pipeline órfão | `totalOrphans`, `actionsReallocate`, `actionsRecluster`, `actionsDoNothing` |
| Dual-System órfão | `cycleS1`, `cycleS2`, `anomalies`, `qDoNothing`, `qReallocate`, `qRecluster` |
| **AttackerDualSystem** | `suspectsCount`, `actionsAttackerQuarantine`, `actionsAttackerDoNothing` |
| **Q-values atacante** | `qAtkDNHigh`, `qAtkQuarHigh`, `qAtkDNLow`, `qAtkQuarLow`, `atkEpsilon` |
| **Smart-quarantine** | `smartTransferOk`, `smartTransferNoDonor`, `smartRedundancyOk` |
| **Saturação** | `leadersAlive`, `leadersDownThisCycle` |

---

## Resultados Experimentais

Validação completa com 35 runs cumulativos para N={200, 250, 300}, 5 atacantes, threshold de saturação 500.

### Detecção e prevenção

| Scale | Atacantes | Quarentenas | Recall |
|---|---|---|---|
| N=200 | 175 | 139 | **79.4%** |
| N=250 | 165 | 123 | **74.5%** |
| N=300 | 175 | 146 | **83.4%** |

### Métricas de segurança (matriz de confusão, paper)

Confusão por nó, agregada (pooled) sobre as 35 runs. **DR** = fração de ataques com ≥1 detecção; **Recall** = TP/(TP+FN) por nó atacante. Gerado por `plots/compute_tables.py`.

| Cenário | ACC | DR | Recall | PRE | FPR | F1 | ADT | AMT | T_rec |
|---|---|---|---|---|---|---|---|---|---|
| N=200 | 99.49% | 100% | 79.43% | 100% | 0% | 88.54% | 5.9s | 0.1s | 7.0s |
| N=250 | 99.49% | 100% | 74.55% | 100% | 0% | 85.42% | 5.2s | 0.3s | 7.7s |
| **200 (FR)** | 96.41% | 100% | 41.63% | 100% | 0% | 58.78% | 8.8s | 0.3s | 8.6s |

**FP = 0 em todas as runs** → Precision 100%, nenhum nó legítimo quarentenado. O recall < 100% vem de atacantes que saturam o líder antes da quarentena (limite temporal — ver [Cenário FR](#cenário-fr-full-random)). Recall por faixa de intensidade no FR: leve (5-8 atk) **84%**, médio (9-14) **47%**, pesado (15-20) **25%** — mas o SR final se mantém ~94% nas três (auto-recuperação robusta à intensidade). AMT ≈ 0.1-0.3s porque a quarentena é emitida no **mesmo ciclo** da detecção.

### Saturação (race condition)

| Scale | Líderes caídos | % atacantes que saturaram |
|---|---|---|
| N=200 | 60 | 34.3% |
| N=250 | 61 | 37.0% |
| N=300 | 66 | 37.7% |

Em **92% das runs** pelo menos um líder cai por saturação. **Caso típico**: 2 líderes/run.

### Pipeline de recuperação

| Scale | REALLOCATE | RECLUSTER | Órfãos / líder caído |
|---|---|---|---|
| N=200 | 1148 | 0 | 19.1 |
| N=250 | 1611 | 0 | 26.4 |
| N=300 | 1983 | 0 | 30.0 |

**Política convergiu para REALLOCATE_TO_EXISTING** em 100% dos casos. RECLUSTER nunca foi escolhido com ε no piso — órfãos são absorvidos por clusters vizinhos sem reformar o cluster morto.

### Qualidade da rede

| Scale | QI final | QI durante ataque (t≥300) | QI mínimo | SR final |
|---|---|---|---|---|
| N=200 | 0.9796 | 0.9782 | 0.9083 | 0.9676 |
| N=250 | 0.9801 | 0.9785 | 0.9162 | 0.9693 |
| N=300 | 0.9785 | 0.9767 | 0.9185 | 0.9630 |

**QI mantido acima de 0.97 em todas as escalas**, com degradação máxima de ~9% no pior momento e recuperação completa ao final.

### Convergência da Q-table do atacante

Exemplo N=200 (35 runs):

| Run | Q(SH,QUAR) | Q(SL,QUAR) | ε | Quar cumulativo |
|---|---|---|---|---|
| 1 | 0.00 | 5.90 | 0.137 | 4 |
| 5 | 8.06 | 11.52 | 0.084 | 25 |
| 10 | 10.39 | 11.66 | 0.062 | 43 |
| 20 | 12.03 | 10.28 | 0.028 | 85 |
| 30 | 16.78 | 15.24 | 0.020 | 124 |
| 35 | 15.43 | 16.62 | 0.020 | 139 |

Política converge em **15-20 runs** para Q(SUSPECT_HIGH, QUARANTINE) ≈ Q(SUSPECT_LOW, QUARANTINE) ≈ 11-16, indicando que **quarentenar é sempre preferível à omissão** independente da intensidade da suspeita.

---

## Notas Metodológicas

### Líder fantasma (ghost-leader)

O protocolo de clusterização herdado de sectional/synapt elege líderes localmente, sem ack. Em redes grandes (N≥200), ~10-20% dos nós podem ter `myLeader` apontando para um candidato que não se confirmou líder no AP. Esses são **líderes fantasma** — invisíveis ao `clusterInfoMap`.

O DETECTIVE **não filtra** atacantes apontando para fantasmas (mesma política do sectional/synapt para clusters idle). O ataque continua mandando pacotes ao IP, mas o AP não recebe contagens, então o atacante fica invisível à detecção. Métrica reportada via **3 níveis de denominador**:
- `selected`: total de atacantes plantados
- `effective`: atacantes que passaram na verificação local (target válido)
- `detected`: atacantes quarentenados pelo framework

### Recompensa observacional

O AttackerDualSystem aprende **sem ground-truth**. A recompensa é derivada de:
- Para QUARANTINE: limpeza do cluster (outros suspeitos persistem ou não)
- Para DO_NOTHING: persistência do suspeito (calmou ou escalou)

Nenhuma consulta a `isNodeCompromised()` do simulador. O framework opera apenas com observações que estariam disponíveis em ambiente real.

### Smart-quarantine dormante

A lógica de transferência de doador (`findCapabilityDonor`, `transferDonorToCluster`) só dispara em cenários onde a remoção do suspeito quebraria a redundância de capabilities do cluster. Sob `SIMILARITY_THRESHOLD=0.95` (padrão), isso é raro — clusters por construção são quase idênticos. Validado em runtime sob threshold relaxado (0.80). Mantida como rede de segurança defensiva.

---

## Relação com sectional e synapt

| Dimensão | sectional | synapt-v1 | synapt-v2 | **detective-v1** |
|---|---|---|---|---|
| Cenário de stress | Nenhum (baseline) | Falha de líder (waves) | Falha de membro | **Ataque UDP DoS interno** |
| Detecção | Não | Z-score (líderes) | Z-score (líderes) | **Z-score (líderes) + flooders (origens)** |
| Reação | Q-Learning (RL3) | Dual-System S1/S2 | Dual-System + cluster state | **Dual-System (órfão + atacante)** |
| Aprendizado | Q-table reativa | Contínuo (5s cycle) | Contínuo | **Contínuo** |
| Modelo de ameaça | — | Falha externa | Falha externa | **Insider compromise (DDoS)** |
| Saturação modelada | — | — | — | **Sim (limite de pacotes recebidos)** |
| Recovery | — | Pipeline órfão | Cluster-level + órfão | **Pipeline órfão (reativo a DoS)** |

---

## Como Compilar e Executar

```bash
# Na raiz do ns-3-dev
./ns3 build

# Execução manual (uma rodada)
./ns3 run "scratch/detective/contaski --nNodes=200 --run=1 --nAttackers=5"

# Execução completa do paper (35 runs × 3 scales)
./scratch/detective/run_detective.sh

# Análise dos resultados (Python)
python3 -c "
import glob, csv
for n in [200, 250, 300]:
    qis = []
    for f in glob.glob(f'scratch/detective/results-detective/{n}_attack5/run_*/IntuitiveStats.csv'):
        rows = list(csv.DictReader(open(f)))
        if rows: qis.append(float(rows[-1]['qi']))
    print(f'N={n}: QI final médio = {sum(qis)/len(qis):.4f}  ({len(qis)} runs)')
"
```

---

## Reproducibility

- **NS-3 RNG** (`--run`): mantido **fixo em 1** entre rodadas; reproduz a topologia, mobilidade e clustering.
- **`std::random_device`** (entropia do SO): regenera `capacitiesFile-N-contaski.txt`, `tasksFile-N.txt` e seleção de atacantes a cada execução. Garante variação inter-run sem afetar o RNG do NS-3.
- **`knowledge.dat`**: cumulativo entre rodadas dentro do mesmo cenário; carregado no início, salvo ao fim. Permite ver a curva de aprendizado por run.

---

## Estrutura de Arquivos Modificados (vs SYNAPT-v1)

```
+++ FloodAttack.{cc,h}              novo: módulo de ataque UDP flood isolado
+++ run_detective.sh                novo: script de execução para o paper
~~~ constants.h                     ± FloodPacket, QuarantineOrder
~~~ AnomalyDetector.{cc,h}          + detectFlooders (Z + absoluto)
~~~ IntuitiveLearning.{cc,h}        + AttackerDualSystem (3×2), AttackerState, AttackerAction
                                    + telemetria attacker pipeline em IntuitiveSnapshot
~~~ NodeApplication.{cc,h}          + counters, blocklist, saturação, sanity check no startFlood
~~~ NodeAPApplication.{cc,h}        + processAttackersIntuitively, smart-quarantine helpers,
                                    + sendQuarantineOrder, leadersDown tracking,
                                    + filtro de atacante detectado em processOrphansIntuitively,
                                    + parser de heartbeat estendido com pares src=cnt
                                    - removido: trigger de falhas (scenário synapt)
~~~ contaski.cc                     + seleção operator-side de atacantes (lambda em t=200),
                                    + CLI flags do detective,
                                    + lifecycle do FloodSaturationThreshold,
                                    - removido: flags de cenário 4/5 do synapt
```

