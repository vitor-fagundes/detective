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

    // Limiares Dual-System
    const double THRESHOLD_S1 = 0.35;    // Valor original (Pedroso 2026), antes do ajuste para 1200 ciclos Python
    //const double THRESHOLD_S1 = 0.25;    // Pthreat acima disso → System 1 (resposta rápida)
    const double THRESHOLD_S2 = 0.60;    // QI/SR abaixo disso → System 2 (análise profunda)

    // Ações de resiliência disponíveis (por órfão)
    enum IntuitiveAction {
        DO_NOTHING = 0,
        REALLOCATE_TO_EXISTING,   // Realocar este órfão para cluster existente por similaridade
        RECLUSTER_ORPHANS,        // Marcar este órfão para reclusterização com outros órfãos
        INTUITIVE_ACTION_COUNT    // Sentinel: número total de ações
    };

    // Estados por órfão (Q-Table 4×3, alinhado com RL3)
    // Baseado na similaridade do órfão com clusters existentes e com outros órfãos
    // Threshold para determinação de ESTADO (mais restritivo que viabilidade)
    // Com 0.85 quase tudo cai em SIM_BOTH_HIGH; 0.92 cria diversidade real
    // enquanto mantém REALLOCATION_THRESHOLD=0.85 e CLUSTERING_THRESHOLD=0.85
    const double SIMILARITY_HIGH_THRESHOLD = 0.92;

    enum OrphanState {
        SIM_BOTH_HIGH = 0,      // Similaridade alta com existentes E com órfãos
        SIM_EXISTING_HIGH,      // Similaridade alta SÓ com clusters existentes
        SIM_ORPHAN_HIGH,        // Similaridade alta SÓ com outros órfãos
        SIM_BOTH_MEDIUM,        // Similaridade média/baixa com ambos
        ORPHAN_STATE_COUNT      // Sentinel: número total de estados
    };

    [[maybe_unused]] static const char* OrphanStateNames[] = {
        "SIM_BOTH_HIGH", "SIM_EXISTING_HIGH", "SIM_ORPHAN_HIGH", "SIM_BOTH_MEDIUM"
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

        // Nós com padrões emergentes recentes
        std::vector<Ipv6Address> recentEmergentNodes() const;

        // Discretiza (QI, SR) num bucket de estado para indexar Rintuitive
        static std::string discretizeState(double qi, double sr);

        // Estado contextual atual
        const ContextualState& getContextual() const { return contextual; }

        // --- Persistência entre rodadas ---
        void saveToStream(std::ofstream& out) const;
        void loadFromStream(std::ifstream& in);

    private:
        // Rhistorical: timestamp → resultado
        std::map<double, HistoricalRecord>  historical;

        // Rintuitive: (bucket, ação) → lista de rewards
        std::map<std::pair<std::string, int>, std::vector<double>> intuitive;

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

        // Marcar nó como anômalo
        void markAnomalous(Ipv6Address addr, bool anomalous);

        // Obter todos os nós e seus valores Li
        const std::map<Ipv6Address, NodeLearningInfo>& getAllNodes() const { return nodes; }

    private:
        std::map<Ipv6Address, NodeLearningInfo> nodes;
    };

    // ============================================================
    // MÓDULO 4 — Dual-System de Resposta
    // System 1: resposta rápida/intuitiva (Kahneman S1)
    // System 2: análise deliberada e otimização (Kahneman S2)
    // (Seção 5.6, Pedroso 2026)
    // ============================================================

    class DualSystemResponse {
    public:
        DualSystemResponse(double epsilon = 0.30, double epsilonDecay = 0.97,
                           double epsilonMin = 0.02);

        // Determinar estado de um órfão baseado nas suas similaridades
        static OrphanState determineOrphanState(double simExisting, double simOrphans);

        // Escolhe ação para um órfão individual (decide qual sistema ativar)
        // pThreat é global (decide S1 vs S2), estado do órfão é individual
        std::pair<IntuitiveAction, SystemUsed> chooseActionForOrphan(
            const KnowledgeNetworks& knowledge,
            const DistributedLearning& distLearn,
            double qi, double sr, double pThreat,
            OrphanState orphanState);

        // Atualiza Q-values para uma decisão individual por órfão
        void updateQForOrphan(OrphanState state, IntuitiveAction action, double reward);

        // Atualiza Q-values com métricas globais pós-ciclo (Rhistorical e Rcontextual)
        void updateQGlobal(double qiBefore, double qiAfter,
                           double srBefore, double srAfter);

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
        void loadFromStream(std::ifstream& in);

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

        // Q-table 4×3: estado do órfão → ação → valor
        std::map<int, std::map<int, double>> Q;

        double epsilon;
        double epsilonDecay;
        double epsilonMin;

        uint32_t s1Count;
        uint32_t s2Count;
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
    double computeTII(
        const DistributedLearning& distLearn,
        const std::vector<Ipv6Address>& leaders,
        uint32_t totalAliveNodes);

    // ARF(T) = (structural_flexibility × learning_rate × context_awareness) / response_time   [Def. 3]
    double computeARF(
        double structuralFlexibility,
        double learningRate,
        double contextAwareness,
        double responseTime);

    // Flexibilidade estrutural: proporção de líderes com enlaces redundantes
    double computeStructuralFlexibility(
        const std::vector<ClusterInfo>& clusters,
        uint32_t totalAliveNodes);

    // ============================================================
    // Classe principal: IntuitiveLearningEngine
    // Orquestra todos os módulos no AP
    // ============================================================

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

        // --- Persistência entre rodadas ---
        void saveKnowledge(const std::string& path) const;
        bool loadKnowledge(const std::string& path);

    private:
        // Calcular métricas globais da rede
        double calculateQI(const std::vector<ClusterInfo>& clusters, uint32_t totalNodes);
        double calculateSR(const std::vector<ClusterInfo>& clusters, uint32_t totalNodes);

        // Módulos
        KnowledgeNetworks   knowledge;
        DistributedLearning distLearn;
        DualSystemResponse  dualSys;

        // Estado
        double              lastQI;
        double              lastSR;
        double              lastPThreat;

        // Histórico de snapshots
        std::vector<IntuitiveSnapshot> history;
    };

} // namespace nr2