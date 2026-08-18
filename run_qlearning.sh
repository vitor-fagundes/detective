#!/bin/bash
# ============================================================
# run_qlearning.sh — BASELINE Q-learning (comparação vs intuitivo)
# ============================================================
# Roda a MESMA falha do detective (flood → saturação de líder → órfãos),
# mas com --recoveryEngine=qlearning: SEM detecção/quarentena, só recuperação
# de órfãos via Q-learning puro (sectional-style). Não toca no intuitivo.
#
# Saída em results-qlearning/ (mesma estrutura de .results-detective):
#   results-qlearning/<N>_attack5/   (determinístico: 5 atacantes @ t=300)
#   results-qlearning/200_fr/        (FR: início+qtd aleatórios por run)
#     knowledge.dat + knowledge.dat.qltable (Q-table cumulativa do baseline)
#     attack_manifest.csv (só FR)
#     run_001/ ...
#
# Uso:
#   ./scratch/detective/run_qlearning.sh            # tudo (det 200/250/300 + fr)
#   ./scratch/detective/run_qlearning.sh det        # só determinístico
#   ./scratch/detective/run_qlearning.sh fr         # só FR
#   ./scratch/detective/run_qlearning.sh all quick  # smoke (3 runs)
# ============================================================
set -e
set -m

cleanup() {
    trap '' SIGINT SIGTERM EXIT
    set +e
    echo ""; echo ">>> INTERROMPIDO — matando árvore de processos..."
    kill -TERM -$$ 2>/dev/null; sleep 0.5; kill -KILL -$$ 2>/dev/null
    pkill -KILL -f "ns3.36-contaski"            2>/dev/null
    pkill -KILL -f "scratch/detective/contaski" 2>/dev/null
    pkill -KILL -f "timeout 900"                2>/dev/null
    echo ">>> Limpeza concluída. Retome rodando o script de novo (resume parcial)."
    exit 130
}
trap cleanup SIGINT SIGTERM

NS3_ROOT="${NS3_ROOT:-$(pwd)}"
cd "${NS3_ROOT}"
[ -f "ns3" ] || { echo "ERRO: rode da raiz do ns-3-dev"; exit 1; }

MODE="${1:-all}"           # all | det | fr
[ "${2:-}" = "quick" ] && QUICK=1 || QUICK=0

# ---- config ----
N_RUNS="${N_RUNS:-35}";  [ "$QUICK" = 1 ] && N_RUNS=3
SCALES_DET=(${SCALES_DET:-200 250 300})
ENGINE="qlearning"
ATTACK_MODE=1
ATTACK_RATE=50.0
ATTACK_PAYLOAD=64
SAT_THRESHOLD=500
# determinístico
DET_ATTACKERS=5
DET_START=300.0
# FR
FR_N=200
FR_START_MIN=200; FR_START_MAX=700
FR_ATK_MIN=5;     FR_ATK_MAX=20

RESULTS_ROOT="${NS3_ROOT}/scratch/detective/results-qlearning"
mkdir -p "${RESULTS_ROOT}"

rand_int(){ local min=$1 max=$2; echo $(( min + RANDOM % (max - min + 1) )); }

echo "============================================================"
echo "  BASELINE Q-LEARNING (recoveryEngine=${ENGINE}, SEM quarentena)"
echo "  modo=${MODE}  runs/cenário=${N_RUNS}  saída=${RESULTS_ROOT}"
echo "============================================================"

# build uma vez
BIN="${NS3_ROOT}/build/scratch/detective/ns3.36-contaski-default"
NEWEST_SRC=$(find "${NS3_ROOT}/scratch/detective" -maxdepth 1 \( -name "*.cc" -o -name "*.h" \) 2>/dev/null | xargs ls -t 2>/dev/null | head -1)
if [ -f "${BIN}" ] && [ "${BIN}" -nt "${NEWEST_SRC}" ]; then echo "  binário atualizado, pulando build"; else ./ns3 build; fi
echo ""

# ---- função que roda 1 cenário (N runs cumulativos) ----
# args: SCENARIO_DIR  is_fr(0/1)  N  nAttackers  startTime
run_scenario(){
    local SDIR="$1" IS_FR="$2" N="$3" NATK="$4" START="$5"
    mkdir -p "${SDIR}"
    local KNOW="${SDIR}/knowledge.dat"
    local MAN="${SDIR}/attack_manifest.csv"
    [ "$IS_FR" = 1 ] && [ ! -f "$MAN" ] && echo "run,attack_start,n_attackers" > "$MAN"

    for R in $(seq 1 "${N_RUNS}"); do
        local TAG=$(printf "run_%03d" "$R"); local RDIR="${SDIR}/${TAG}"; mkdir -p "$RDIR"
        [ -f "${RDIR}/IntuitiveStats.csv" ] && { echo "    ${SDIR##*/}/${TAG} já existe, pulando"; continue; }
        local st="$START" nn="$NATK"
        if [ "$IS_FR" = 1 ]; then st=$(rand_int $FR_START_MIN $FR_START_MAX); nn=$(rand_int $FR_ATK_MIN $FR_ATK_MAX); fi
        echo -n "    ${SDIR##*/}/${TAG} $(date +%H:%M:%S) start=${st}s natk=${nn} ... "
        rm -f "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt" "${NS3_ROOT}/tasksFile-${N}.txt"
        local CMD="scratch/detective/contaski --nNodes=${N} --run=1 --nAttackers=${nn} \
            --attackMode=${ATTACK_MODE} --attackStartTime=${st} --attackRate=${ATTACK_RATE} \
            --attackPayloadSize=${ATTACK_PAYLOAD} --floodSaturationThreshold=${SAT_THRESHOLD} \
            --recoveryEngine=${ENGINE} --knowledgePath=${KNOW}"
        local t0=$(date +%s)
        if ! timeout 900 ./ns3 run --no-build "${CMD}" > "${RDIR}/simulation.log" 2>&1; then
            echo "FAIL (ver ${RDIR}/simulation.log)"; continue; fi
        for a in IntuitiveStats.csv IntuitiveQValues.txt APStats.txt; do
            [ -f "${NS3_ROOT}/${a}" ] && mv "${NS3_ROOT}/${a}" "${RDIR}/"; done
        [ -f "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt" ] && mv "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt" "${RDIR}/"
        [ -f "${NS3_ROOT}/tasksFile-${N}.txt" ] && mv "${NS3_ROOT}/tasksFile-${N}.txt" "${RDIR}/"
        [ -f "${KNOW}" ]         && cp "${KNOW}" "${RDIR}/knowledge_snapshot.dat"
        [ -f "${KNOW}.qltable" ] && cp "${KNOW}.qltable" "${RDIR}/qltable_snapshot.dat"
        [ "$IS_FR" = 1 ] && echo "${R},${st},${nn}" >> "$MAN"
        echo "OK ($(( $(date +%s) - t0 ))s)"
    done
}

GLOBAL_START=$(date +%s)

if [ "$MODE" = "all" ] || [ "$MODE" = "det" ]; then
    for N in "${SCALES_DET[@]}"; do
        echo ">>> [determinístico N=${N}] 5 atacantes @ t=300"
        run_scenario "${RESULTS_ROOT}/${N}_attack5" 0 "$N" "$DET_ATTACKERS" "$DET_START"
    done
fi
if [ "$MODE" = "all" ] || [ "$MODE" = "fr" ]; then
    echo ">>> [FR N=${FR_N}] início∈[${FR_START_MIN},${FR_START_MAX}]s, atacantes∈[${FR_ATK_MIN},${FR_ATK_MAX}]"
    run_scenario "${RESULTS_ROOT}/${FR_N}_fr" 1 "$FR_N" 0 0
fi

echo ""
echo "============================================================"
echo "  BASELINE Q-LEARNING DONE em $(( ($(date +%s) - GLOBAL_START) / 60 ))min"
echo "  resultados em: ${RESULTS_ROOT}/"
echo "============================================================"
