#!/bin/bash
# ============================================================
# run_detective_fr.sh — cenários FR (Full Random) do paper detective
# ============================================================
# Escala única: N=200, v1 (attackMode=1, membro→líder).
#
# FR: 1 ataque, TUDO aleatório por run (tempo + quantidade + nós):
#   - início do ataque  ∈ [200, 700]s   (sempre após warmup completo, t≈160)
#   - nº de atacantes    ∈ [5, 20]       (2.5%–10% de N=200, uniforme)
#   - quais nós          → sorteio uniforme interno da sim (std::random_device)
#
# FR4 (2 ondas disjuntas) exige mudança no contaski.cc e NÃO está habilitado aqui.
#
# Todos os params sorteados são gravados em <scenario>/attack_manifest.csv
# (run,attack_start,n_attackers) para reprodutibilidade/auditoria.
#
# Estrutura de saída (igual ao run_detective.sh):
#   results-detective/200_fr/
#     knowledge.dat                 (cumulativo entre runs)
#     attack_manifest.csv           (params sorteados por run)
#     run_001/ ... run_NNN/
#
# Uso:
#   ./scratch/detective/run_detective_fr.sh fr          # 35 runs (default)
#   ./scratch/detective/run_detective_fr.sh fr quick    # 3 runs (smoke)
#   N_RUNS=10 ./scratch/detective/run_detective_fr.sh fr
# ============================================================

set -e
set -m  # job control → cada child vira process group leader

cleanup() {
    trap '' SIGINT SIGTERM EXIT
    set +e
    echo ""
    echo ">>> INTERROMPIDO — matando árvore de processos..."
    kill -TERM -$$ 2>/dev/null
    sleep 0.5
    kill -KILL -$$ 2>/dev/null
    pkill -KILL -f "ns3.36-contaski"            2>/dev/null
    pkill -KILL -f "scratch/detective/contaski" 2>/dev/null
    pkill -KILL -f "timeout 900"                2>/dev/null
    echo ">>> Limpeza concluída. Pra retomar, execute o script de novo (resume parcial)."
    exit 130
}
trap cleanup SIGINT SIGTERM

NS3_ROOT="${NS3_ROOT:-$(pwd)}"
cd "${NS3_ROOT}"
if [ ! -f "ns3" ]; then
    echo "ERRO: rode da raiz do ns-3-dev (./ns3 não encontrado em ${NS3_ROOT})"
    exit 1
fi

# ============================================================
# Cenário (fr por enquanto)
# ============================================================
SCENARIO="${1:-fr}"
if [ "${SCENARIO}" != "fr" ]; then
    echo "ERRO: só 'fr' está habilitado neste script (fr4 exige mudança no contaski.cc)."
    exit 1
fi

# ============================================================
# Configuração
# ============================================================
N=200                                       # escala única
N_RUNS="${N_RUNS:-35}"
ATTACK_MODE=1                               # v1: membro→líder
ATTACK_RATE="${ATTACK_RATE:-50.0}"
ATTACK_PAYLOAD="${ATTACK_PAYLOAD:-64}"
SAT_THRESHOLD="${SAT_THRESHOLD:-500}"

# Faixas de randomização do FR
START_MIN="${START_MIN:-200}"               # início ≥ warmup completo
START_MAX="${START_MAX:-700}"               # deixa ≥200s de observação até SIMTIME=900
ATK_MIN="${ATK_MIN:-5}"                     # 2.5% de 200
ATK_MAX="${ATK_MAX:-20}"                    # 10% de 200

case "${2:-}" in
    quick) N_RUNS=3; echo "MODO QUICK: $N_RUNS runs" ;;
esac

# rand_int MIN MAX → inteiro uniforme em [MIN, MAX]
rand_int() {
    local min=$1 max=$2
    echo $(( min + RANDOM % (max - min + 1) ))
}

RESULTS_ROOT="${NS3_ROOT}/scratch/detective/results-detective"
SCENARIO_DIR="${RESULTS_ROOT}/${N}_${SCENARIO}"
KNOWLEDGE="${SCENARIO_DIR}/knowledge.dat"
MANIFEST="${SCENARIO_DIR}/attack_manifest.csv"
mkdir -p "${SCENARIO_DIR}"

# ============================================================
# Build (uma vez)
# ============================================================
echo "============================================================"
echo "  detective — FR run script (${SCENARIO})"
echo "============================================================"
echo "  escala:        N=${N}  (v1, attackMode=${ATTACK_MODE})"
echo "  runs:          ${N_RUNS}"
echo "  início ataque: aleatório ∈ [${START_MIN}, ${START_MAX}]s"
echo "  nº atacantes:  aleatório ∈ [${ATK_MIN}, ${ATK_MAX}]  (${ATK_MIN}=$(echo "scale=1;$ATK_MIN*100/$N"|bc)% .. ${ATK_MAX}=$(echo "scale=1;$ATK_MAX*100/$N"|bc)%)"
echo "  taxa/payload:  ${ATTACK_RATE} pkts/s / ${ATTACK_PAYLOAD}B"
echo "  saturação:     ${SAT_THRESHOLD} pkts"
echo "  saída:         ${SCENARIO_DIR}"
echo "============================================================"
echo ""

BIN="${NS3_ROOT}/build/scratch/detective/ns3.36-contaski-default"
NEWEST_SRC=$(find "${NS3_ROOT}/scratch/detective" -maxdepth 1 \( -name "*.cc" -o -name "*.h" \) 2>/dev/null | xargs ls -t 2>/dev/null | head -1)
if [ -f "${BIN}" ] && [ -n "${NEWEST_SRC}" ] && [ "${BIN}" -nt "${NEWEST_SRC}" ]; then
    echo "  binário já atualizado, pulando build"
else
    ./ns3 build
fi
echo ""

# Manifest header (cria se não existir)
if [ ! -f "${MANIFEST}" ]; then
    echo "run,attack_start,n_attackers" > "${MANIFEST}"
fi

if [ ! -f "${KNOWLEDGE}" ]; then
    echo ">>> [${SCENARIO}] cenário novo, sem knowledge prévia"
else
    echo ">>> [${SCENARIO}] continuando knowledge existente"
fi

# ============================================================
# Loop de runs
# ============================================================
GLOBAL_START=$(date +%s)

for R in $(seq 1 "${N_RUNS}"); do
    RUN_TAG=$(printf "run_%03d" "${R}")
    RUN_DIR="${SCENARIO_DIR}/${RUN_TAG}"
    mkdir -p "${RUN_DIR}"

    if [ -f "${RUN_DIR}/IntuitiveStats.csv" ]; then
        echo "    [${N}_${SCENARIO}/${RUN_TAG}] já existe, pulando"
        continue
    fi

    # Sorteio dos parâmetros deste run
    ATK_START=$(rand_int "${START_MIN}" "${START_MAX}")
    ATK_N=$(rand_int "${ATK_MIN}" "${ATK_MAX}")

    RUN_START=$(date +%s)
    echo -n "    [${N}_${SCENARIO}/${RUN_TAG}] $(date +%H:%M:%S) start=${ATK_START}s natk=${ATK_N} ... "

    rm -f "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt"
    rm -f "${NS3_ROOT}/tasksFile-${N}.txt"

    SIM_CMD="scratch/detective/contaski \
        --nNodes=${N} \
        --run=1 \
        --nAttackers=${ATK_N} \
        --attackMode=${ATTACK_MODE} \
        --attackStartTime=${ATK_START} \
        --attackRate=${ATTACK_RATE} \
        --attackPayloadSize=${ATTACK_PAYLOAD} \
        --floodSaturationThreshold=${SAT_THRESHOLD} \
        --knowledgePath=${KNOWLEDGE}"

    if ! timeout 900 ./ns3 run --no-build "${SIM_CMD}" > "${RUN_DIR}/simulation.log" 2>&1; then
        echo "FAIL"
        echo "      (ver ${RUN_DIR}/simulation.log)"
        continue
    fi

    for artifact in IntuitiveStats.csv IntuitiveQValues.txt APStats.txt; do
        [ -f "${NS3_ROOT}/${artifact}" ] && mv "${NS3_ROOT}/${artifact}" "${RUN_DIR}/"
    done
    [ -f "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt" ] && \
        mv "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt" "${RUN_DIR}/"
    [ -f "${NS3_ROOT}/tasksFile-${N}.txt" ] && \
        mv "${NS3_ROOT}/tasksFile-${N}.txt" "${RUN_DIR}/"
    [ -f "${KNOWLEDGE}" ] && cp "${KNOWLEDGE}" "${RUN_DIR}/knowledge_snapshot.dat"

    # Registra params sorteados só após sucesso
    echo "${R},${ATK_START},${ATK_N}" >> "${MANIFEST}"

    RUN_END=$(date +%s)
    echo "OK ($((RUN_END - RUN_START))s)"
done

GLOBAL_END=$(date +%s)
TOTAL_MIN=$(( (GLOBAL_END - GLOBAL_START) / 60 ))
echo ""
echo "============================================================"
echo "  FR (${SCENARIO}) DONE em ${TOTAL_MIN}min"
echo "  resultados em: ${SCENARIO_DIR}/"
echo "  manifest:      ${MANIFEST}"
echo "============================================================"
