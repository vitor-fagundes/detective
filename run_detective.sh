#!/bin/bash
# ============================================================
# run_detective.sh — script de execução para o paper do detective
# ============================================================
# Estrutura herdada de sectional/synapt:
#   results-detective/
#     <N>_<scenario>/
#       knowledge.dat                    (cumulativo entre rodadas)
#       run_001/
#         simulation.log
#         IntuitiveStats.csv             (telemetria por ciclo)
#         IntuitiveQValues.txt           (Q-tables finais)
#         APStats.txt                    (tarefas dispatchadas/aceitas)
#         knowledge_snapshot.dat         (snapshot do knowledge no fim da run)
#         capacitiesFile-N-contaski.txt  (caps geradas pra esta run)
#         tasksFile-N.txt                (tarefas geradas pra esta run)
#       run_002/
#       ...
#
# Convenções herdadas do synapt:
#   - --run=1 fixo em todas as execuções
#   - capabilitiesFile regenerado por run (std::random_device dá entropia
#     diferente a cada execução, mesmo com --run=1)
#   - knowledge.dat carregado da rodada anterior + salvo no fim de cada rodada
#     (transferência de conhecimento entre rodadas)
#
# Uso:
#   ./scratch/detective/run_detective.sh                 # roda tudo (default)
#   ./scratch/detective/run_detective.sh quick           # 3 runs por scale (smoke)
#   ./scratch/detective/run_detective.sh scale 200       # só uma escala
#   N_RUNS=10 ./scratch/detective/run_detective.sh       # override # de runs
# ============================================================

set -e
set -m  # job control habilitado → cada child vira process group leader

# Cleanup ao receber Ctrl+C / SIGTERM. ./ns3 run é um wrapper python que pode
# absorver SIGINT; precisamos matar a árvore inteira de processos. Estratégia
# em camadas:
#   1. desabilita re-entrada do trap
#   2. desabilita 'set -e' (pkill com 0 matches retorna não-zero)
#   3. mata o process group inteiro do script (kill -- -PID)
#   4. mata por nome qualquer netinho que escapou
cleanup() {
    trap '' SIGINT SIGTERM EXIT
    set +e
    echo ""
    echo ">>> INTERROMPIDO — matando árvore de processos..."
    # Process group do script: PGID = PID do script
    kill -TERM -$$ 2>/dev/null
    sleep 0.5
    kill -KILL -$$ 2>/dev/null
    # Defensivo: pega netos órfãos que escaparam do grupo
    pkill -KILL -f "ns3.36-contaski"            2>/dev/null
    pkill -KILL -f "scratch/detective/contaski" 2>/dev/null
    pkill -KILL -f "timeout 900"                2>/dev/null
    echo ">>> Limpeza concluída. Pra retomar, execute o script de novo (resume parcial)."
    exit 130
}
trap cleanup SIGINT SIGTERM

# Localização do ns-3-dev (deve ser executado da raiz, ou ajustar abaixo)
NS3_ROOT="${NS3_ROOT:-$(pwd)}"
cd "${NS3_ROOT}"

if [ ! -f "ns3" ]; then
    echo "ERRO: rode da raiz do ns-3-dev (./ns3 não encontrado em ${NS3_ROOT})"
    exit 1
fi

# ============================================================
# Configuração — calibrável via env vars ou args
# ============================================================
SCALES=(${SCALES:-200 250 300})            # tamanhos de rede a testar
N_RUNS="${N_RUNS:-35}"                      # rodadas cumulativas por scale
N_ATTACKERS="${N_ATTACKERS:-5}"             # atacantes por run (5*50=250pkts/s < SAT_THRESHOLD: AP sobrevive)
ATTACK_MODE="${ATTACK_MODE:-2}"             # v2: 2=líder→AP (1=membro→líder é a v1)
ATTACK_START="${ATTACK_START:-300.0}"
ATTACK_RATE="${ATTACK_RATE:-50.0}"
ATTACK_PAYLOAD="${ATTACK_PAYLOAD:-64}"
SAT_THRESHOLD="${SAT_THRESHOLD:-500}"       # pacotes pra vítima (líder em v1 / AP em v2) cair
# Label inclui o modo pra não colidir mode1 (attack5) com mode2 (attack5_mode2).
SCENARIO_LABEL="${SCENARIO_LABEL:-attack${N_ATTACKERS}_mode${ATTACK_MODE}}"

# Parse args simples
case "${1:-}" in
    quick)
        N_RUNS=3
        echo "MODO QUICK: $N_RUNS rodadas por scale"
        ;;
    scale)
        if [ -n "${2:-}" ]; then
            SCALES=("$2")
            echo "MODO SCALE: rodando só N=$2"
        fi
        ;;
esac

# Diretório raiz dos resultados — dentro do próprio projeto (scratch/detective/),
# espelhando a convenção do sectional e do synapt (results-* dentro do source dir).
RESULTS_ROOT="${NS3_ROOT}/scratch/detective/results-detective"
mkdir -p "${RESULTS_ROOT}"

# ============================================================
# Build (uma vez no início)
# ============================================================
echo "============================================================"
echo "  detective — paper run script"
echo "============================================================"
echo "  scales:        ${SCALES[*]}"
echo "  runs/scale:    ${N_RUNS}"
echo "  attackers:     ${N_ATTACKERS}"
echo "  attack mode:   ${ATTACK_MODE}  (1=membro→líder, 2=líder→AP)"
echo "  attack start:  ${ATTACK_START}s @ ${ATTACK_RATE} pkts/s"
echo "  saturation:    ${SAT_THRESHOLD} pkts"
echo "  scenario lbl:  ${SCENARIO_LABEL}"
echo "  results root:  ${RESULTS_ROOT}"
echo "============================================================"
echo ""
echo "Building detective (pula se já estiver compilado)..."
# Sem pipe pro tail aqui: o tail bufferiza tudo e o usuário não vê progresso
# durante uma rebuild grande. Mostrar output direto.
# Se já tem binário compilado e ele é mais novo que os fontes, skip — economiza
# 30-60s por execução do script (importante quando rodamos várias vezes).
BIN="${NS3_ROOT}/build/scratch/detective/ns3.36-contaski-default"
NEWEST_SRC=$(find "${NS3_ROOT}/scratch/detective" -maxdepth 1 -name "*.cc" -o -name "*.h" 2>/dev/null | xargs ls -t 2>/dev/null | head -1)
if [ -f "${BIN}" ] && [ -n "${NEWEST_SRC}" ] && [ "${BIN}" -nt "${NEWEST_SRC}" ]; then
    echo "  binário já está atualizado, pulando build"
else
    ./ns3 build
fi
echo ""

# ============================================================
# Loop principal: scales × runs
# ============================================================
GLOBAL_START=$(date +%s)

for N in "${SCALES[@]}"; do
    SCENARIO_DIR="${RESULTS_ROOT}/${N}_${SCENARIO_LABEL}"
    mkdir -p "${SCENARIO_DIR}"
    KNOWLEDGE="${SCENARIO_DIR}/knowledge.dat"

    # Limpa knowledge se for um cenário novo (não foi parcialmente rodado)
    # Comportamento: se já existe knowledge.dat, ASSUME que é continuação
    if [ ! -f "${KNOWLEDGE}" ]; then
        echo ">>> [N=${N}] cenário novo, sem knowledge prévia"
    else
        echo ">>> [N=${N}] continuando knowledge existente em ${KNOWLEDGE}"
    fi

    SCALE_START=$(date +%s)

    for R in $(seq 1 "${N_RUNS}"); do
        RUN_TAG=$(printf "run_%03d" "${R}")
        RUN_DIR="${SCENARIO_DIR}/${RUN_TAG}"
        mkdir -p "${RUN_DIR}"

        # Skip se a run já tem resultado (resume entre execuções)
        if [ -f "${RUN_DIR}/IntuitiveStats.csv" ]; then
            echo "    [${N}_${SCENARIO_LABEL}/${RUN_TAG}] já existe, pulando"
            continue
        fi

        RUN_START=$(date +%s)
        echo -n "    [${N}_${SCENARIO_LABEL}/${RUN_TAG}] $(date +%H:%M:%S) ... "

        # Forçar regeneração das capabilities (std::random_device em generateCap)
        # gera caps diferentes a cada execução mesmo com --run=1.
        rm -f "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt"
        rm -f "${NS3_ROOT}/tasksFile-${N}.txt"

        # Executar a simulação
        SIM_CMD="scratch/detective/contaski \
            --nNodes=${N} \
            --run=1 \
            --nAttackers=${N_ATTACKERS} \
            --attackMode=${ATTACK_MODE} \
            --attackStartTime=${ATTACK_START} \
            --attackRate=${ATTACK_RATE} \
            --attackPayloadSize=${ATTACK_PAYLOAD} \
            --floodSaturationThreshold=${SAT_THRESHOLD} \
            --knowledgePath=${KNOWLEDGE}"

        # Timeout generoso pra N grande (10 min por run)
        # --no-build: pula re-check de build (já foi feito uma vez no início do
        # script). Sem isso, ns-3 escaneia o projeto inteiro a cada run, gasta
        # 5-10s por iteração extra.
        if ! timeout 900 ./ns3 run --no-build "${SIM_CMD}" > "${RUN_DIR}/simulation.log" 2>&1; then
            echo "FAIL"
            echo "      (ver ${RUN_DIR}/simulation.log)"
            continue
        fi

        # Mover artefatos pro diretório da run
        # ns-3 escreve no working dir (ns3 root), movemos pra estrutura organizada.
        for artifact in IntuitiveStats.csv IntuitiveQValues.txt APStats.txt; do
            [ -f "${NS3_ROOT}/${artifact}" ] && mv "${NS3_ROOT}/${artifact}" "${RUN_DIR}/"
        done
        # Caps/tasks files (movidos como referência da run; serão regenerados na próxima)
        [ -f "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt" ] && \
            mv "${NS3_ROOT}/capacitiesFile-${N}-contaski.txt" "${RUN_DIR}/"
        [ -f "${NS3_ROOT}/tasksFile-${N}.txt" ] && \
            mv "${NS3_ROOT}/tasksFile-${N}.txt" "${RUN_DIR}/"
        # Snapshot do knowledge ao fim desta run
        [ -f "${KNOWLEDGE}" ] && cp "${KNOWLEDGE}" "${RUN_DIR}/knowledge_snapshot.dat"

        RUN_END=$(date +%s)
        echo "OK ($((RUN_END - RUN_START))s)"
    done

    SCALE_END=$(date +%s)
    SCALE_MIN=$(( (SCALE_END - SCALE_START) / 60 ))
    echo ">>> [N=${N}] concluído em ${SCALE_MIN}min"
    echo ""
done

GLOBAL_END=$(date +%s)
TOTAL_MIN=$(( (GLOBAL_END - GLOBAL_START) / 60 ))
echo "============================================================"
echo "  ALL DONE em ${TOTAL_MIN}min"
echo "  resultados em: ${RESULTS_ROOT}/"
echo "============================================================"
