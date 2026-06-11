#pragma once

/**
 * Framework de Aprendizado Intuitivo para Resiliência em IIoT
 * ============================================================
 * Baseado em:
 *   - Trovati et al. (ICANN 2022) — modelo formal de intuição artificial
 *   - Pedroso (2026) — framework conceitual para topologias resilientes
 *
 * Módulos:
 *   1. Camadas de Conhecimento   R = Rhistorical ∪ Rintuitive ∪ Rcontextual ∪ Remergent
 *   2. Aprendizado Distribuído   Li(t+1) = Li(t) + α·ΔLi  por nó
 *   3. Detecção de Anomalias     (ver AnomalyDetector.h)
 *   4. Dual-System               System 1 (rápido/intuitivo) + System 2 (analítico)
 *   5. Métricas de Intuição      TII, ARF, ρ(i,j)
 */

#include "ns3/core-module.h"
#include "ns3/ipv6-address.h"
#include <map>
#include <set>
#include <vector>
#include <deque>
#include <string>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <fstream>

using namespace ns3;

namespace nr2 {

    // ============================================================
    // Constantes do Aprendizado Intuitivo
    // ============================================================

    // Parâmetros do aprendizado distribuído (Eqs. 2–4 do artigo)
    const double ALPHA_LEARN    = 0.2;    // Taxa de aprendizado de Li
    const double BETA_INFLUENCE = 0.1;    // Influência entre agentes βij

    // Parâmetros Q-learning (System 2)
    const double ALPHA_Q = 0.2;
    const double GAMMA_Q = 0.9;

    // Limiares Dual-System (default — calibrado para N=200/250).
    const double THRESHOLD_S1 = 0.20;    // pThreat acima disso → System 1 (resposta rápida)
    const double THRESHOLD_S2 = 0.60;    // QI/SR abaixo disso → System 2 (análise profunda)

    // Override combinado para N=300 nós. Em 300 nós, o número absoluto de líderes
    // anômalos é maior e a distribuição de pThreat desloca para cima (mediana
    // empírica ~0.245 vs ~0.19 em 200/250). Com defaults, pThreat satura acima
    // de THRESHOLD_S1=0.20 em >90% dos ciclos e System 2 quase não ativa,
    // quebrando o balanço S1/S2 observado em 200/250. Dois ajustes combinados:
    //   (i)  ξ_anomalous: -0.05 → -0.033 reduz o drag absoluto sobre mean(Li),
    //        levando pThreat para mais perto da faixa de 200/250 (corrige a
    //        dinâmica na origem).
    //   (ii) THRESHOLD_S1: 0.20 → 0.245 recalibra o gatilho para a mediana
    //        empírica observada.
    // Footnote do paper: "For N=300, ξ_anomalous is scaled by 200/N (=-0.033)
    // and the S1 activation threshold is recalibrated to 0.245, jointly
    // preserving density-invariant anomaly drag and the S1/S2 balance observed
    // at smaller scales."
    const double XI_ANOMALOUS_300 = -0.033;
    const double THRESHOLD_S1_300 = 0.245;

    // Ações de resiliência disponíveis (por órfão)
    enum IntuitiveAction {
        DO_NOTHING = 0,
        REALLOCATE_TO_EXISTING,   // Realocar este órfão para cluster existente por similaridade
        RECLUSTER_ORPHANS,        // Marcar este órfão para reclusterização com outros órfãos
        INTUITIVE_ACTION_COUNT    // Sentinel: número total de ações
    };

    enum OrphanState {
        EXISTING_VIABLE = 0,    // Similaridade alta com cluster existente → REALLOCATE
        ORPHAN_ONLY,            // Sem cluster existente compatível, mas similar a outros órfãos → RECLUSTER
        NO_MATCH,               // Nenhuma opção viável → DO_NOTHING
        ORPHAN_STATE_COUNT      // Sentinel: número total de estados
    };

    [[maybe_unused]] static const char* OrphanStateNames[] = {
        "EXISTING_VIABLE", "ORPHAN_ONLY", "NO_MATCH"
    };

    // Nomes das ações para log
    [[maybe_unused]] static const char* IntuitiveActionNames[] = {
        "DO_NOTHING",
        "REALLOCATE_TO_EXISTING",
        "RECLUSTER_ORPHANS"
    };

    // Sistema que tomou a decisão
    enum SystemUsed {
        SYSTEM_S1,      // System 1: resposta rápida/intuitiva
        SYSTEM_S1_S2,   // Ambos: S1 propõe, S2 prevalece
        SYSTEM_S2       // System 2: análise deliberada
    };

    [[maybe_unused]] static const char* SystemUsedNames[] = {
        "S1", "S1+S2", "S2"
    };

    // ============================================================
    // Pipeline de defesa contra atacante UDP DoS (Fase 2 — detective)
    // ============================================================
    // Ramo paralelo ao motor de órfãos. AnomalyDetector reporta suspeitos com
    // base em Z-score de tráfego por origem dentro do cluster. O AttackerDualSystem
    // decide DO_NOTHING ou QUARANTINE por suspeito (Q-table 3×2 separada).
    // ============================================================

    // Limiares de Z-score que definem o estado de suspeição.
    // Calibrados pra um cluster pequeno (poucos membros): 2 = 2σ acima da média.
    const double ATTACKER_Z_LOW  = 2.0;
    const double ATTACKER_Z_HIGH = 4.0;

    enum AttackerState {
        ATK_CLEAR = 0,        // z < ATTACKER_Z_LOW
        ATK_SUSPECT_LOW,      // ATTACKER_Z_LOW <= z < ATTACKER_Z_HIGH
        ATK_SUSPECT_HIGH,     // z >= ATTACKER_Z_HIGH
        ATTACKER_STATE_COUNT
    };

    [[maybe_unused]] static const char* AttackerStateNames[] = {
        "CLEAR", "SUSPECT_LOW", "SUSPECT_HIGH"
    };

    enum AttackerAction {
        ATK_DO_NOTHING = 0,
        ATK_QUARANTINE,
        ATTACKER_ACTION_COUNT
    };

    [[maybe_unused]] static const char* AttackerActionNames[] = {
        "DO_NOTHING", "QUARANTINE"
    };

    // ============================================================
    // Estruturas auxiliares
    // ============================================================

    // Registro histórico de uma decisão (Rhistorical)
    struct HistoricalRecord {
        double      timestamp;
        IntuitiveAction action;
        double      qiDelta;
        double      srDelta;
        double      reward;
    };

    // Evento emergente detectado (Remergent)
    struct EmergentEvent {
        Ipv6Address node;
        double      timestamp;
        double      anomalyScore;
    };

    // Contexto operacional atual (Rcontextual)
    struct ContextualState {
        double      timestamp;
        double      qi;             // Quality Index global
        double      sr;             // Service Reachability global
        std::string threatLevel;    // "HIGH", "MED", "LOW"
        uint32_t    activeLeaders;
        uint32_t    orphanedNodes;
        uint32_t    totalNodes;
    };

    // Snapshot de métricas para log
    struct IntuitiveSnapshot {
        double      timestamp;
        double      qi;
        double      sr;
        double      tii;
        double      arf;
        double      meanRho;
        double      netLearning;
        double      pThreat;
        // Contadores de ações por órfão neste ciclo
        uint32_t    actionsDoNothing;
        uint32_t    actionsReallocate;
        uint32_t    actionsRecluster;
        uint32_t    totalOrphans;
        // Contadores S1/S2 neste ciclo
        uint32_t    cycleS1Count;
        uint32_t    cycleS2Count;
        uint32_t    anomalies;
        // Q-values médios no momento da decisão (para plotar evolução)
        double      qDoNothing;
        double      qReallocate;
        double      qRecluster;

        // ============================================================
        // Telemetria do ramo atacante (Fase 2 / detective)
        // ============================================================
        uint32_t    suspectsCount;             // suspeitos detectados pelo Z-score neste ciclo
        uint32_t    actionsAttackerQuarantine; // QUARANTINE decididas neste ciclo
        uint32_t    actionsAttackerDoNothing;  // DO_NOTHING decididas neste ciclo
        double      qAttackerDoNothingHigh;    // Q(SUSPECT_HIGH, DO_NOTHING)
        double      qAttackerQuarantineHigh;   // Q(SUSPECT_HIGH, QUARANTINE)
        double      qAttackerDoNothingLow;     // Q(SUSPECT_LOW, DO_NOTHING)
        double      qAttackerQuarantineLow;    // Q(SUSPECT_LOW, QUARANTINE)
        double      attackerEpsilon;           // ε do AttackerDualSystem
        uint32_t    smartTransferOk;           // transferências de doador bem-sucedidas neste ciclo
        uint32_t    smartTransferNoDonor;      // missing_caps mas nenhum doador viável
        uint32_t    smartRedundancyOk;         // QUARANTINE com cluster mantendo redundância

        // Saturação de líder por flood (modelo de DoS efetivo)
        uint32_t    leadersAlive;              // líderes vivos no clusterInfoMap neste ciclo
        uint32_t    leadersDownThisCycle;      // líderes que caíram desde o ciclo anterior
    };

    // Informação que o AP mantém sobre cada cluster
    struct ClusterInfo {
        Ipv6Address leaderAddr;
        bool        leaderAlive;
        uint32_t    memberCount;        // Membros conhecidos no cluster
        uint32_t    initialMemberCount; // Membros no momento da formação
        double      lastHeartbeat;      // Timestamp do último contato
        bool        hasAcceptedTask;    // Se já aceitou pelo menos uma tarefa
    };

    // Informação de um nó para o aprendizado distribuído
    struct NodeLearningInfo {
        double      Li;             // Capacidade de aprendizado
        bool        alive;
        bool        isLeader;
        bool        isAnomalous;
        Ipv6Address clusterLeader;  // Líder do cluster a que pertence
    };

    // ============================================================
    // MÓDULO 1 — Camadas de Conhecimento
    // R = Rhistorical ∪ Rintuitive ∪ Rcontextual ∪ Remergent
    // (Definição 1, Pedroso 2026)
    // ============================================================

    class KnowledgeNetworks {
    public:
        KnowledgeNetworks();

        // --- Atualização ---
        void updateHistorical(double timestamp, IntuitiveAction action,
                              double qiDelta, double srDelta);
        void updateIntuitive(const std::string& stateBucket,
                             IntuitiveAction action, double reward);
        void updateContextual(double timestamp, double qi, double sr,
                              const std::string& threatLevel,
                              uint32_t activeLeaders, uint32_t orphans,
                              uint32_t totalNodes);
        void addEmergent(Ipv6Address node, double timestamp, double anomalyScore);

        // --- Consultas ---
        // Retorna a melhor ação intuitiva para o bucket de estado atual
        // Retorna -1 se não há experiência acumulada
        int bestIntuitiveAction(const std::string& stateBucket) const;

        // Estado contextual atual
        const ContextualState& getContextual() const { return contextual; }

        // --- Persistência entre rodadas ---
        void saveToStream(std::ofstream& out) const;

    private:
        // Rhistorical: timestamp → resultado
        std::map<double, HistoricalRecord>  historical;

        // Rintuitive: (bucket, ação) → janela deslizante de rewards
        std::map<std::pair<std::string, int>, std::deque<double>> intuitive;
        static const size_t MAX_INTUITIVE_HISTORY = 100;

        // Rcontextual: estado operacional atual
        ContextualState contextual;

        // Remergent: últimos N eventos anômalos
        std::deque<EmergentEvent> emergent;
        static const size_t MAX_EMERGENT = 50;
    };

    // ============================================================
    // MÓDULO 2 — Aprendizado Distribuído por Nó
    // ΔLi = Σj≠i βij·(Lj(t) − Li(t))   [Eq. 4]
    // Li(t+1) = Li(t) + α·ΔLi            [Eq. 3]
    // (Seção 4.2, Pedroso 2026)
    // ============================================================

    class DistributedLearning {
    public:
        DistributedLearning();

        // Override do estímulo ambiental ξ para nós anômalos. Default = -0.05.
        // Usado pelo AP em N>=300 para reduzir o drag absoluto sobre mean(Li).
        void setXiAnomalous(double xi) { m_xiAnomalous = xi; }

        // Inicializar Li para um nó (chamado quando o AP descobre um nó)
        void initNode(Ipv6Address addr, double initialEnergy, bool isLeader);

        // Atualizar Li de todos os nós baseado nos vizinhos conhecidos
        // clusterMembers: líder → lista de membros
        void step(const std::map<Ipv6Address, std::vector<Ipv6Address>>& clusterMembers,
                  const std::set<Ipv6Address>& anomalousNodes);

        // Calcular probabilidade de ameaça baseada nos líderes
        // Incorpora sobrevivência: pThreat sobe quando líderes morrem
        double threatProbability(const std::vector<Ipv6Address>& aliveLeaders,
                                 uint32_t totalLeaders) const;

        // Capacidade média de aprendizado da rede
        double networkLearningMean() const;

        // Obter Li de um nó específico
        double getLi(Ipv6Address addr) const;

        // Marcar nó como morto
        void markDead(Ipv6Address addr);

        // Promover nó existente a líder sem resetar Li (usado no RECLUSTER)
        void promoteToLeader(Ipv6Address addr);

        // Obter todos os nós e seus valores Li
        const std::map<Ipv6Address, NodeLearningInfo>& getAllNodes() const { return nodes; }

    private:
        std::map<Ipv6Address, NodeLearningInfo> nodes;
        double m_xiAnomalous = -0.05;  // configurável via setXiAnomalous()
    };

    // ============================================================
    // MÓDULO 4 — Dual-System de Resposta
    // System 1: resposta rápida/intuitiva (Kahneman S1)
    // System 2: análise deliberada e otimização (Kahneman S2)
    // (Seção 5.6, Pedroso 2026)
    // ============================================================

    class DualSystemResponse {
    public:
        DualSystemResponse(double epsilon = 0.15, double epsilonDecay = 0.97,
                           double epsilonMin = 0.02);

        // Override do gatilho S1/S2 (pThreat threshold). Default = THRESHOLD_S1 (0.20).
        // Usado pelo AP em N>=300 para recalibrar com a mediana empírica de pThreat.
        void setThresholdS1(double t) { thresholdS1 = t; }

        // Determinar estado de um órfão baseado nas suas similaridades.
        // Thresholds passados pelo AP para garantir consistência com os checks de viabilidade.
        static OrphanState determineOrphanState(double simExisting, double simOrphans,
                                                 double existingThreshold, double orphansThreshold);

        // Escolhe ação para um órfão individual (decide qual sistema ativar)
        // pThreat é global (decide S1 vs S2), estado do órfão é individual
        std::pair<IntuitiveAction, SystemUsed> chooseActionForOrphan(
            const KnowledgeNetworks& knowledge,
            const DistributedLearning& distLearn,
            double qi, double sr, double pThreat,
            OrphanState orphanState);

        // Atualiza Q-values para uma decisão individual por órfão
        void updateQForOrphan(OrphanState state, IntuitiveAction action, double reward);

        // Decai epsilon após cada ciclo de decisão
        void decayEpsilon();

        // Getters para log
        double getEpsilon() const { return epsilon; }
        double getQValue(OrphanState state, IntuitiveAction action) const;
        // Getters agregados para log do CSV (média por ação sobre todos os estados)
        double getQValueAvg(IntuitiveAction action) const;
        uint32_t getS1Count() const { return s1Count; }
        uint32_t getS2Count() const { return s2Count; }

        // --- Persistência entre rodadas ---
        void saveToStream(std::ofstream& out) const;

        // Setters pontuais usados pelo parser unificado de loadKnowledge
        void loadQValue(int state, int action, double value) { Q[state][action] = value; }
        void loadEpsilon(double eps) { epsilon = eps; }
        void loadCounters(uint32_t s1, uint32_t s2) { s1Count = s1; s2Count = s2; }

    private:
        // System 1: resposta rápida baseada em experiência (por órfão)
        IntuitiveAction system1Response(
            const KnowledgeNetworks& knowledge,
            OrphanState orphanState);

        // System 2: análise deliberada com ε-greedy (por órfão)
        IntuitiveAction system2Response(
            OrphanState orphanState,
            const DistributedLearning& distLearn);

        // Q-table 3×3: estado do órfão → ação → valor
        std::map<int, std::map<int, double>> Q;

        double epsilon;
        double epsilonDecay;
        double epsilonMin;
        double thresholdS1 = THRESHOLD_S1;  // configurável via setThresholdS1()

        uint32_t s1Count;
        uint32_t s2Count;

        // RNGs reutilizáveis — criados uma vez no construtor
        Ptr<UniformRandomVariable> m_uniformRng;
        Ptr<UniformRandomVariable> m_actionRng;
    };

    // ============================================================
    // MÓDULO 5 — Métricas de Intuição: TII, ARF, ρ(i,j)
    // (Definições 2, 3 e 4, Pedroso 2026)
    // ============================================================

    // ρ(i,j) = α(i,j) × reliability(i,j) × adaptation_potential(i,j)   [Def. 4]
    // Calculado sobre pares líder↔AP (o que o AP conhece)
    double computeResilienceActivation(
        const std::vector<ClusterInfo>& clusters,
        const DistributedLearning& distLearn);

    // TII(T) = Σ wi · anticipation_score(i) / |V|   [Def. 2]
    // anticipation_score: 1.0 se líder vivo, 0.5 se membro em cluster ativo, 0.0 se órfão
    double computeTII(
        const DistributedLearning& distLearn,
        const std::vector<ClusterInfo>& clusters,
        uint32_t totalAliveNodes);

    // ARF(T) = (structural_flexibility × learning_rate × context_awareness) / response_time   [Def. 3]
    double computeARF(
        double structuralFlexibility,
        double learningRate,
        double contextAwareness,
        double responseTime);

    // Flexibilidade estrutural: fração de nós vivos com grau > 1 (líderes ativos)
    double computeStructuralFlexibility(
        const DistributedLearning& distLearn,
        uint32_t totalAliveNodes);

    // ============================================================
    // Classe principal: IntuitiveLearningEngine
    // Orquestra todos os módulos no AP
    // ============================================================

    // ============================================================
    // AttackerDualSystem (Fase 2 — detective)
    // Q-table 3×2 ε-greedy para decisão de quarentena por suspeito.
    // Ramo paralelo ao DualSystemResponse de órfãos — mesma α/γ, ε próprio.
    // Persistência sob [QTABLE_ATTACKER], [EPSILON_ATTACKER], [COUNTERS_ATTACKER].
    // ============================================================
    class AttackerDualSystem {
    public:
        AttackerDualSystem(double epsilon = 0.15, double epsilonDecay = 0.97,
                           double epsilonMin = 0.02);

        // Discretiza Z-score em estado (CLEAR / SUSPECT_LOW / SUSPECT_HIGH).
        static AttackerState stateFromZScore(double z);

        // Escolhe ação para um suspeito (ε-greedy sobre Q-table 3×2).
        AttackerAction selectAction(AttackerState state);

        // Atualiza Q(s,a) com recompensa observada (Bellman 1-step).
        void updateQ(AttackerState state, AttackerAction action, double reward,
                     AttackerState nextState);

        // Decai ε quando teve pelo menos 1 suspeito no ciclo.
        void decayEpsilonIfActive(int suspectsThisCycle);

        // Getters/log
        double getEpsilon() const { return epsilon; }
        uint32_t getQuarantineCount() const { return quarantineCount; }
        uint32_t getDoNothingCount() const { return doNothingCount; }
        double getQ(AttackerState s, AttackerAction a) const { return qTable[s][a]; }

        // Persistência
        void saveToStream(std::ofstream& out) const;
        bool loadFromStream(std::ifstream& in);
        void loadQValue(int s, int a, double v) {
            if (s >= 0 && s < ATTACKER_STATE_COUNT &&
                a >= 0 && a < ATTACKER_ACTION_COUNT) qTable[s][a] = v;
        }
        void loadEpsilon(double e) { epsilon = e; }
        void loadCounters(uint32_t q, uint32_t d) { quarantineCount = q; doNothingCount = d; }

    private:
        double qTable[ATTACKER_STATE_COUNT][ATTACKER_ACTION_COUNT];
        double epsilon;
        const double epsilonDecay;
        const double epsilonMin;

        uint32_t quarantineCount;
        uint32_t doNothingCount;

        Ptr<UniformRandomVariable> m_uniformRng;
        Ptr<UniformRandomVariable> m_actionRng;
    };

    class IntuitiveLearningEngine {
    public:
        IntuitiveLearningEngine();

        // --- Ciclo principal de decisão (chamado periodicamente pelo AP) ---
        // Calcula métricas globais, atualiza módulos, gera snapshot
        // NÃO escolhe ação — a ação é por órfão, delegada ao AP
        IntuitiveSnapshot decisionCycle(
            double currentTime,
            const std::vector<ClusterInfo>& clusters,
            const std::set<Ipv6Address>& anomalousNodes,
            uint32_t totalNodes);

        // --- Getters do último ciclo (para uso no loop por órfão) ---
        double getLastQI() const { return lastQI; }
        double getLastSR() const { return lastSR; }
        double getLastPThreat() const { return lastPThreat; }

        // --- Registrar informação dos nós ---
        void registerNode(Ipv6Address addr, double energy, bool isLeader);
        void registerLeaderDeath(Ipv6Address addr);

        // --- Atualizar estado após todas as ações por órfão aplicadas ---
        void postActionUpdate(double qiAfter, double srAfter, bool hadOrphans);

        // --- Getters para log ---
        KnowledgeNetworks& getKnowledge() { return knowledge; }
        DistributedLearning& getDistributedLearning() { return distLearn; }
        const DualSystemResponse& getDualSystem() const { return dualSys; }
        DualSystemResponse& getDualSystemMut() { return dualSys; }
        const std::vector<IntuitiveSnapshot>& getHistory() const { return history; }
        std::vector<IntuitiveSnapshot>& getHistoryMut() { return history; }

        // --- Pipeline de atacante (Fase 2) ---
        AttackerDualSystem& getAttackerSystem() { return attackerSys; }
        const AttackerDualSystem& getAttackerSystem() const { return attackerSys; }

        // --- Persistência entre rodadas ---
        void saveKnowledge(const std::string& path) const;
        bool loadKnowledge(const std::string& path);

    private:
        // Calcular métricas globais da rede
        double calculateQI(const std::vector<ClusterInfo>& clusters, uint32_t liveDenom);
        double calculateSR(const std::vector<ClusterInfo>& clusters, uint32_t liveDenom);

        // Módulos
        KnowledgeNetworks   knowledge;
        DistributedLearning distLearn;
        DualSystemResponse  dualSys;
        AttackerDualSystem  attackerSys;

        // Estado
        double              lastQI;
        double              lastSR;
        double              lastPThreat;

        // Histórico de snapshots
        std::vector<IntuitiveSnapshot> history;
    };

} // namespace nr2