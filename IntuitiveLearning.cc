#include "IntuitiveLearning.h"

#include <iostream>
#include <limits>

using namespace ns3;

namespace nr2 {

    // ============================================================
    // MÓDULO 1 — KnowledgeNetworks
    // ============================================================

    KnowledgeNetworks::KnowledgeNetworks() {
        contextual.timestamp = 0.0;
        contextual.qi = 1.0;
        contextual.sr = 1.0;
        contextual.threatLevel = "LOW";
        contextual.activeLeaders = 0;
        contextual.orphanedNodes = 0;
        contextual.totalNodes = 0;
    }

    void KnowledgeNetworks::updateHistorical(double timestamp, IntuitiveAction action,
                                              double qiDelta, double srDelta) {
        HistoricalRecord record;
        record.timestamp = timestamp;
        record.action = action;
        record.qiDelta = qiDelta;
        record.srDelta = srDelta;
        record.reward = srDelta + 0.3 * qiDelta;
        historical[timestamp] = record;
    }

    void KnowledgeNetworks::updateIntuitive(const std::string& stateBucket,
                                             IntuitiveAction action, double reward) {
        auto key = std::make_pair(stateBucket, static_cast<int>(action));
        intuitive[key].push_back(reward);
        if (intuitive[key].size() > MAX_INTUITIVE_HISTORY) {
            intuitive[key].pop_front();
        }
    }

    void KnowledgeNetworks::updateContextual(double timestamp, double qi, double sr,
                                              const std::string& threatLevel,
                                              uint32_t activeLeaders, uint32_t orphans,
                                              uint32_t totalNodes) {
        contextual.timestamp = timestamp;
        contextual.qi = qi;
        contextual.sr = sr;
        contextual.threatLevel = threatLevel;
        contextual.activeLeaders = activeLeaders;
        contextual.orphanedNodes = orphans;
        contextual.totalNodes = totalNodes;
    }

    void KnowledgeNetworks::addEmergent(Ipv6Address node, double timestamp, double anomalyScore) {
        EmergentEvent evt;
        evt.node = node;
        evt.timestamp = timestamp;
        evt.anomalyScore = anomalyScore;
        emergent.push_back(evt);
        while (emergent.size() > MAX_EMERGENT) {
            emergent.pop_front();
        }
    }

    int KnowledgeNetworks::bestIntuitiveAction(const std::string& stateBucket) const {
        double bestReward = -std::numeric_limits<double>::infinity();
        int bestAction = -1;

        for (const auto& entry : intuitive) {
            if (entry.first.first == stateBucket && !entry.second.empty()) {
                double mean = 0.0;
                for (double r : entry.second) {
                    mean += r;
                }
                mean /= entry.second.size();

                if (mean > bestReward) {
                    bestReward = mean;
                    bestAction = entry.first.second;
                }
            }
        }

        return bestAction;
    }

    // ============================================================
    // MÓDULO 2 — DistributedLearning
    // ============================================================

    DistributedLearning::DistributedLearning() {
    }

    void DistributedLearning::initNode(Ipv6Address addr, double initialEnergy, bool isLeader) {
        NodeLearningInfo info;
        // Li inicial proporcional à energia do nó
        info.Li = std::min(1.0, std::max(0.0, initialEnergy));
        info.alive = true;
        info.isLeader = isLeader;
        info.isAnomalous = false;
        info.clusterLeader = Ipv6Address();
        nodes[addr] = info;
    }

    void DistributedLearning::step(
            const std::map<Ipv6Address, std::vector<Ipv6Address>>& clusterMembers,
            const std::set<Ipv6Address>& anomalousNodes) {

        // Construir mapa de vizinhança: dentro de cada cluster, todos os membros
        // são vizinhos entre si e do líder
        std::map<Ipv6Address, std::vector<Ipv6Address>> neighbors;
        for (const auto& cluster : clusterMembers) {
            Ipv6Address leader = cluster.first;
            const auto& members = cluster.second;

            // Líder-membro (bidirecional) + membro-membro (cada par uma vez — O(M²/2))
            for (size_t i = 0; i < members.size(); i++) {
                neighbors[leader].push_back(members[i]);
                neighbors[members[i]].push_back(leader);
                for (size_t j = i + 1; j < members.size(); j++) {
                    neighbors[members[i]].push_back(members[j]);
                    neighbors[members[j]].push_back(members[i]);
                }
            }
        }

        // Atualizar clusterLeader para cada nó (necessário para antScore do TII)
        for (const auto& cluster : clusterMembers) {
            Ipv6Address leader = cluster.first;
            auto lit = nodes.find(leader);
            if (lit != nodes.end()) lit->second.clusterLeader = leader;
            for (const auto& member : cluster.second) {
                auto mit = nodes.find(member);
                if (mit != nodes.end()) mit->second.clusterLeader = leader;
            }
        }

        // Calcular ΔLi para cada nó — Eq. 4
        std::map<Ipv6Address, double> delta;
        for (auto& entry : nodes) {
            Ipv6Address addr = entry.first;
            NodeLearningInfo& info = entry.second;

            if (!info.alive) {
                delta[addr] = 0.0;
                continue;
            }

            // Influência dos vizinhos vivos — Eq. 4: ΔLi = Σj βij·(Lj − Li)
            double influence = 0.0;
            auto it = neighbors.find(addr);
            int aliveNeighCount = 0;
            int totalNeighCount = 0;

            if (it != neighbors.end()) {
                totalNeighCount = it->second.size();
                for (const auto& neighbor : it->second) {
                    auto nit = nodes.find(neighbor);
                    if (nit != nodes.end() && nit->second.alive) {
                        influence += BETA_INFLUENCE * (nit->second.Li - info.Li);
                        aliveNeighCount++;
                    }
                }
            }

            // Estímulo ambiental: penalidade se anômalo, bônus se vizinhos saudáveis
            double envStimulus = 0.0;
            if (anomalousNodes.count(addr) > 0) {
                envStimulus = m_xiAnomalous;
            } else if (totalNeighCount > 0) {
                envStimulus = 0.01 * (double)aliveNeighCount / (double)totalNeighCount;
            }

            delta[addr] = influence + envStimulus;
        }

        // Li(t+1) = Li(t) + α·ΔLi  [Eq. 3] — clampado em [0, 1]
        for (auto& entry : nodes) {
            if (!entry.second.alive) continue;
            double newLi = entry.second.Li + ALPHA_LEARN * delta[entry.first];
            entry.second.Li = std::min(1.0, std::max(0.0, newLi));

            // Atualizar flag de anomalia
            entry.second.isAnomalous = (anomalousNodes.count(entry.first) > 0);
        }
    }

    double DistributedLearning::threatProbability(
            const std::vector<Ipv6Address>& aliveLeaders,
            uint32_t totalLeaders) const {
        // pThreat = 1 - mean_Li(líderes vivos)
        // Alinhado com Python: líderes com Li baixo sinalizam rede frágil.
        (void)totalLeaders;

        std::vector<double> leaderLi;
        for (const auto& leader : aliveLeaders) {
            auto it = nodes.find(leader);
            if (it != nodes.end() && it->second.alive) {
                leaderLi.push_back(it->second.Li);
            }
        }

        if (leaderLi.empty()) {
            return 1.0; // Sem líderes vivos → ameaça máxima
        }

        double mean = 0.0;
        for (double li : leaderLi) {
            mean += li;
        }
        mean /= leaderLi.size();

        return std::min(1.0, std::max(0.0, 1.0 - mean));
    }

    double DistributedLearning::networkLearningMean() const {
        if (nodes.empty()) return 0.0;

        double sum = 0.0;
        int count = 0;
        for (const auto& entry : nodes) {
            if (entry.second.alive) {
                sum += entry.second.Li;
                count++;
            }
        }
        return count > 0 ? sum / count : 0.0;
    }

    double DistributedLearning::getLi(Ipv6Address addr) const {
        auto it = nodes.find(addr);
        if (it != nodes.end()) {
            return it->second.Li;
        }
        return 0.5; // Default
    }

    void DistributedLearning::markDead(Ipv6Address addr) {
        auto it = nodes.find(addr);
        if (it != nodes.end()) {
            it->second.alive = false;
            it->second.Li = 0.0;
        }
    }

    void DistributedLearning::promoteToLeader(Ipv6Address addr) {
        auto it = nodes.find(addr);
        if (it != nodes.end()) {
            it->second.isLeader = true;
            it->second.clusterLeader = addr;
        }
    }

    // ============================================================
    // MÓDULO 4 — DualSystemResponse
    // ============================================================

    DualSystemResponse::DualSystemResponse(double epsilon, double epsilonDecay,
                                           double epsilonMin)
        : epsilon(epsilon), epsilonDecay(epsilonDecay), epsilonMin(epsilonMin),
          s1Count(0), s2Count(0) {
        // Inicializar Q-table 3×3 com zeros
        for (int s = 0; s < ORPHAN_STATE_COUNT; s++) {
            for (int a = 0; a < INTUITIVE_ACTION_COUNT; a++) {
                Q[s][a] = 0.0;
            }
        }
        // RNGs criados uma vez — evitar alocação NS-3 por chamada S2
        m_uniformRng = CreateObject<UniformRandomVariable>();
        m_uniformRng->SetAttribute("Min", DoubleValue(0.0));
        m_uniformRng->SetAttribute("Max", DoubleValue(1.0));
        m_actionRng = CreateObject<UniformRandomVariable>();
        m_actionRng->SetAttribute("Min", DoubleValue(0.0));
        m_actionRng->SetAttribute("Max", DoubleValue(INTUITIVE_ACTION_COUNT - 0.001));
    }

    OrphanState DualSystemResponse::determineOrphanState(double simExisting, double simOrphans,
                                                           double existingThreshold, double orphansThreshold) {
        if (simExisting >= existingThreshold) return EXISTING_VIABLE;
        if (simOrphans  >= orphansThreshold)  return ORPHAN_ONLY;
        return NO_MATCH;
    }

    IntuitiveAction DualSystemResponse::system1Response(
            const KnowledgeNetworks& knowledge,
            OrphanState orphanState) {
        s1Count++;

        // System 1 (Kahneman): resposta rápida baseada em experiência acumulada.
        // Consulta Rintuitive para pattern-matching com histórico de rewards.
        // Fallback para heurística estática quando não há experiência para o estado.
        std::string bucket = OrphanStateNames[orphanState];
        int intuitive = knowledge.bestIntuitiveAction(bucket);

        if (intuitive >= 0) {
            return static_cast<IntuitiveAction>(intuitive);
        }

        // Fallback: heurística estática (bootstrap — sem experiência acumulada)
        switch (orphanState) {
            case EXISTING_VIABLE:
                return REALLOCATE_TO_EXISTING;
            case ORPHAN_ONLY:
                return RECLUSTER_ORPHANS;
            case NO_MATCH:
            default:
                return DO_NOTHING;
        }
    }

    IntuitiveAction DualSystemResponse::system2Response(
            OrphanState orphanState,
            const DistributedLearning& distLearn) {
        s2Count++;
        int s = static_cast<int>(orphanState);

        // ε-greedy: exploração aleatória
        if (m_uniformRng->GetValue() < epsilon) {
            return static_cast<IntuitiveAction>((int)m_actionRng->GetValue());
        }

        // Explotação: melhor ação ajustada pela capacidade de aprendizado
        double netLearning = distLearn.networkLearningMean();
        std::map<int, double> adjustedQ;

        for (int a = 0; a < INTUITIVE_ACTION_COUNT; a++) {
            adjustedQ[a] = Q[s][a] + 0.1 * netLearning * (a != DO_NOTHING ? 1.0 : 0.0);
        }

        // Penalizar DO_NOTHING para estados onde há opção viável
        if (orphanState == EXISTING_VIABLE || orphanState == ORPHAN_ONLY) {
            adjustedQ[DO_NOTHING] -= 0.5;
        }

        // Encontrar ação com maior Q ajustado
        int bestAction = DO_NOTHING;
        double bestValue = adjustedQ[0];
        for (int a = 1; a < INTUITIVE_ACTION_COUNT; a++) {
            if (adjustedQ[a] > bestValue) {
                bestValue = adjustedQ[a];
                bestAction = a;
            }
        }

        return static_cast<IntuitiveAction>(bestAction);
    }

    std::pair<IntuitiveAction, SystemUsed> DualSystemResponse::chooseActionForOrphan(
            const KnowledgeNetworks& knowledge,
            const DistributedLearning& distLearn,
            double qi, double sr, double pThreat,
            OrphanState orphanState) {

        if (pThreat > thresholdS1) {
            // Ameaça alta → System 1 (resposta imediata baseada em experiência)
            IntuitiveAction action = system1Response(knowledge, orphanState);
            return std::make_pair(action, SYSTEM_S1);
        } else if (qi < THRESHOLD_S2 || sr < THRESHOLD_S2) {
            // Degradação moderada → S2 prevalece
            IntuitiveAction action = system2Response(orphanState, distLearn);
            return std::make_pair(action, SYSTEM_S1_S2);
        } else {
            // Rede saudável → S2 para otimização contínua
            IntuitiveAction action = system2Response(orphanState, distLearn);
            return std::make_pair(action, SYSTEM_S2);
        }
    }

    void DualSystemResponse::updateQForOrphan(OrphanState state, IntuitiveAction action,
                                               double reward) {
        int s = static_cast<int>(state);
        int a = static_cast<int>(action);

        // Encontrar max Q para o próximo estado (mesmo estado, como RL3)
        double maxQ = -std::numeric_limits<double>::infinity();
        for (int nextA = 0; nextA < INTUITIVE_ACTION_COUNT; nextA++) {
            if (Q[s][nextA] > maxQ) {
                maxQ = Q[s][nextA];
            }
        }

        // Q-learning update
        double oldQ = Q[s][a];
        Q[s][a] = (1.0 - ALPHA_Q) * oldQ + ALPHA_Q * (reward + GAMMA_Q * maxQ);
    }

    void DualSystemResponse::decayEpsilon() {
        epsilon = std::max(epsilonMin, epsilon * epsilonDecay);
    }

    double DualSystemResponse::getQValue(OrphanState state, IntuitiveAction action) const {
        int s = static_cast<int>(state);
        int a = static_cast<int>(action);
        auto sit = Q.find(s);
        if (sit != Q.end()) {
            auto ait = sit->second.find(a);
            if (ait != sit->second.end()) {
                return ait->second;
            }
        }
        return 0.0;
    }

    double DualSystemResponse::getQValueAvg(IntuitiveAction action) const {
        int a = static_cast<int>(action);
        double sum = 0.0;
        for (int s = 0; s < ORPHAN_STATE_COUNT; s++) {
            auto sit = Q.find(s);
            if (sit != Q.end()) {
                auto ait = sit->second.find(a);
                if (ait != sit->second.end()) {
                    sum += ait->second;
                }
            }
        }
        return sum / ORPHAN_STATE_COUNT;
    }

    // ============================================================
    // MÓDULO 5 — Métricas de Intuição
    // ============================================================

    double computeResilienceActivation(
            const std::vector<ClusterInfo>& clusters,
            const DistributedLearning& distLearn) {
        // ρ(i,j) = α(i,j) × reliability(i,j) × adaptation_potential(i,j)
        // Calculado sobre pares líder↔AP conhecidos
        if (clusters.empty()) return 0.0;

        double sumRho = 0.0;
        int count = 0;

        for (const auto& cluster : clusters) {
            if (!cluster.leaderAlive) continue;

            // α(i,j): qualidade do enlace — proxy baseado na recência do contato
            // No Python: α(i,j) = edge quality. No NS-3: aproximação via heartbeat.
            // Se contato é recente (< 120s), enlace saudável → α próximo de 1.0
            double now = Simulator::Now().GetSeconds();
            double elapsed = (cluster.lastHeartbeat > 0) ?
                (now - cluster.lastHeartbeat) : 120.0;
            double linkQuality = std::max(0.0, 1.0 - std::min(1.0, elapsed / 120.0));

            // reliability: proporção de membros ativos vs iniciais (clampado em [0,1])
            double reliability = (cluster.initialMemberCount > 0) ?
                std::min(1.0, (double)cluster.memberCount / cluster.initialMemberCount) : 0.0;

            // adaptation_potential: Li do líder
            double adaptPot = distLearn.getLi(cluster.leaderAddr);

            double rho = linkQuality * reliability * adaptPot;
            sumRho += rho;
            count++;
        }

        return count > 0 ? sumRho / count : 0.0;
    }

    double computeTII(
            const DistributedLearning& distLearn,
            const std::vector<ClusterInfo>& clusters,
            uint32_t totalAliveNodes) {
        // TII(T) = Σ wi · anticipation_score(i) / |V|   [Def. 2]
        // wi = Li do nó
        // anticipation_score: 1.0 se líder ativo (conectado ao AP)
        //                     0.5 se membro em cluster ativo (um salto do AP)
        //                     0.0 se órfão (sem caminho ao serviço)
        if (totalAliveNodes == 0) return 0.0;

        std::set<Ipv6Address> aliveLeaderSet;
        for (const auto& c : clusters) {
            if (c.leaderAlive) aliveLeaderSet.insert(c.leaderAddr);
        }

        double sum = 0.0;
        for (const auto& entry : distLearn.getAllNodes()) {
            if (!entry.second.alive) continue;

            double wi = entry.second.Li;
            double antScore;

            if (entry.second.isLeader && aliveLeaderSet.count(entry.first) > 0) {
                antScore = 1.0;
            } else if (aliveLeaderSet.count(entry.second.clusterLeader) > 0) {
                antScore = 0.5;
            } else {
                antScore = 0.0;
            }

            sum += wi * antScore;
        }

        return sum / totalAliveNodes;
    }

    double computeARF(double structuralFlexibility, double learningRate,
                       double contextAwareness, double responseTime) {
        // ARF(T) = (structural_flexibility × learning_rate × context_awareness) / response_time
        double denominator = std::max(0.01, responseTime);
        return (structuralFlexibility * learningRate * contextAwareness) / denominator;
    }

    double computeStructuralFlexibility(
            const DistributedLearning& distLearn,
            uint32_t totalAliveNodes) {
        // Fração de nós vivos com grau > 1 na topologia de cluster.
        // Líderes ativos conectam AP + membros → grau > 1.
        // Membros conectam apenas ao líder → grau = 1.
        if (totalAliveNodes == 0) return 0.0;

        int redundant = 0;
        for (const auto& entry : distLearn.getAllNodes()) {
            if (entry.second.alive && entry.second.isLeader) {
                redundant++;
            }
        }

        return (double)redundant / totalAliveNodes;
    }

    // ============================================================
    // AttackerDualSystem — Pipeline de defesa UDP DoS (Fase 2)
    // ============================================================

    AttackerDualSystem::AttackerDualSystem(double eps, double decay, double minEps)
        : epsilon(eps), epsilonDecay(decay), epsilonMin(minEps),
          quarantineCount(0), doNothingCount(0) {
        for(int s = 0; s < ATTACKER_STATE_COUNT; s++){
            for(int a = 0; a < ATTACKER_ACTION_COUNT; a++){
                qTable[s][a] = 0.0;
            }
        }
        m_uniformRng = CreateObject<UniformRandomVariable>();
        m_uniformRng->SetAttribute("Min", DoubleValue(0.0));
        m_uniformRng->SetAttribute("Max", DoubleValue(1.0));
        m_actionRng = CreateObject<UniformRandomVariable>();
        m_actionRng->SetAttribute("Min", DoubleValue(0.0));
        m_actionRng->SetAttribute("Max", DoubleValue(ATTACKER_ACTION_COUNT - 0.001));
    }

    AttackerState AttackerDualSystem::stateFromZScore(double z) {
        if (z < ATTACKER_Z_LOW)  return ATK_CLEAR;
        if (z < ATTACKER_Z_HIGH) return ATK_SUSPECT_LOW;
        return ATK_SUSPECT_HIGH;
    }

    AttackerAction AttackerDualSystem::selectAction(AttackerState state) {
        // ε-greedy
        if (m_uniformRng->GetValue() < epsilon) {
            AttackerAction a = static_cast<AttackerAction>((int)m_actionRng->GetValue());
            if (a == ATK_QUARANTINE) quarantineCount++; else doNothingCount++;
            return a;
        }
        // Exploit: argmax(Q)
        AttackerAction best = ATK_DO_NOTHING;
        double bestQ = qTable[state][ATK_DO_NOTHING];
        for (int a = 1; a < ATTACKER_ACTION_COUNT; a++) {
            if (qTable[state][a] > bestQ) {
                bestQ = qTable[state][a];
                best = static_cast<AttackerAction>(a);
            }
        }
        if (best == ATK_QUARANTINE) quarantineCount++; else doNothingCount++;
        return best;
    }

    void AttackerDualSystem::updateQ(AttackerState state, AttackerAction action,
                                      double reward, AttackerState nextState) {
        // Reaproveita ALPHA_Q e GAMMA_Q do motor de órfãos.
        double maxNext = qTable[nextState][0];
        for (int a = 1; a < ATTACKER_ACTION_COUNT; a++) {
            if (qTable[nextState][a] > maxNext) maxNext = qTable[nextState][a];
        }
        double target = reward + GAMMA_Q * maxNext;
        qTable[state][action] += ALPHA_Q * (target - qTable[state][action]);
    }

    void AttackerDualSystem::decayEpsilonIfActive(int suspectsThisCycle) {
        if (suspectsThisCycle > 0 && epsilon > epsilonMin) {
            epsilon = std::max(epsilonMin, epsilon * epsilonDecay);
        }
    }

    void AttackerDualSystem::saveToStream(std::ofstream& out) const {
        out << "[QTABLE_ATTACKER]" << std::endl;
        out << "# state,action,q_value" << std::endl;
        for (int s = 0; s < ATTACKER_STATE_COUNT; s++) {
            for (int a = 0; a < ATTACKER_ACTION_COUNT; a++) {
                out << s << "," << a << "," << qTable[s][a] << std::endl;
            }
        }
        out << "[EPSILON_ATTACKER]" << std::endl;
        out << "# epsilon" << std::endl;
        out << epsilon << std::endl;
        out << "[COUNTERS_ATTACKER]" << std::endl;
        out << "# quarantine_count,do_nothing_count" << std::endl;
        out << quarantineCount << "," << doNothingCount << std::endl;
    }

    bool AttackerDualSystem::loadFromStream(std::ifstream& /*in*/) {
        // O parser de saveKnowledge() do engine consome as 3 seções no loop principal.
        // Mantido por simetria de API.
        return true;
    }

    // ============================================================
    // IntuitiveLearningEngine — Orquestrador
    // ============================================================

    IntuitiveLearningEngine::IntuitiveLearningEngine()
        : lastQI(1.0), lastSR(1.0), lastPThreat(0.0) {
    }

    void IntuitiveLearningEngine::registerNode(Ipv6Address addr, double energy, bool isLeader) {
        distLearn.initNode(addr, energy, isLeader);
    }

    void IntuitiveLearningEngine::registerLeaderDeath(Ipv6Address addr) {
        distLearn.markDead(addr);
    }

    double IntuitiveLearningEngine::calculateQI(
            const std::vector<ClusterInfo>& clusters, uint32_t liveDenom) {
        if (clusters.empty() || liveDenom == 0) return 0.0;

        double now = Simulator::Now().GetSeconds();

        int activeClusters = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive) activeClusters++;
        }
        double connectivity = (double)activeClusters / clusters.size();

        uint32_t coveredNodes = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive) {
                coveredNodes += c.memberCount + 1;
            }
        }
        double propagation = std::min(1.0, (double)coveredNodes / liveDenom);

        double deliverySum = 0.0;
        int deliveryCount = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive && c.initialMemberCount > 0) {
                double healthRatio = std::min(1.0, (double)c.memberCount / c.initialMemberCount);
                double elapsed = (c.lastHeartbeat > 0) ?
                    (now - c.lastHeartbeat) : 120.0;
                double linkQuality = std::max(0.1, 1.0 - std::min(1.0, elapsed / 120.0));
                deliverySum += healthRatio * linkQuality;
                deliveryCount++;
            }
        }
        double delivery = deliveryCount > 0 ? deliverySum / deliveryCount : 0.0;

        return std::min(1.0, 0.5 * connectivity + 0.3 * propagation + 0.2 * delivery);
    }

    double IntuitiveLearningEngine::calculateSR(
            const std::vector<ClusterInfo>& clusters, uint32_t liveDenom) {
        if (liveDenom == 0) return 0.0;

        uint32_t reachableNodes = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive) {
                reachableNodes += c.memberCount + 1;
            }
        }

        return std::min(1.0, (double)reachableNodes / liveDenom);
    }

    IntuitiveSnapshot IntuitiveLearningEngine::decisionCycle(
            double currentTime,
            const std::vector<ClusterInfo>& clusters,
            const std::set<Ipv6Address>& anomalousNodes,
            uint32_t totalNodes) {

        // [1] Calcular métricas globais (aliveCount computado uma vez — reutilizado em [5])
        uint32_t aliveCount = 0;
        for (const auto& e : distLearn.getAllNodes()) {
            if (e.second.alive) aliveCount++;
        }
        uint32_t liveDenom = aliveCount > 0 ? aliveCount : totalNodes;

        double qi = calculateQI(clusters, liveDenom);
        double sr = calculateSR(clusters, liveDenom);

        // [2] Calcular probabilidade de ameaça via aprendizado distribuído
        std::vector<Ipv6Address> aliveLeaders;
        for (const auto& c : clusters) {
            if (c.leaderAlive) {
                aliveLeaders.push_back(c.leaderAddr);
            }
        }
        double pThreat = distLearn.threatProbability(aliveLeaders, clusters.size());

        // [3] Atualizar contexto (Rcontextual)
        std::string threatLevel;
        if (pThreat > THRESHOLD_S1) {
            threatLevel = "HIGH";
        } else if (pThreat > 0.2) {
            threatLevel = "MED";
        } else {
            threatLevel = "LOW";
        }

        // Contar órfãos (nós em clusters sem líder)
        uint32_t orphans = 0;
        uint32_t activeLeaders = 0;
        for (const auto& c : clusters) {
            if (!c.leaderAlive) {
                orphans += c.memberCount;
            } else {
                activeLeaders++;
            }
        }
        knowledge.updateContextual(currentTime, qi, sr, threatLevel,
                                    activeLeaders, orphans, totalNodes);

        // [4] Salvar estado para uso no loop por órfão (no AP)
        lastQI = qi;
        lastSR = sr;
        lastPThreat = pThreat;

        // [5] Métricas de intuição — liveDenom calculado em [1]
        double meanRho = computeResilienceActivation(clusters, distLearn);
        double tii = computeTII(distLearn, clusters, liveDenom);
        double flex = computeStructuralFlexibility(distLearn, liveDenom);
        // ARF com response_time placeholder — será recalculado pelo AP após saber S1/S2
        double arf = computeARF(flex, ALPHA_LEARN, distLearn.networkLearningMean(), 2.0);

        // [6] Construir snapshot parcial (contadores de ação preenchidos pelo AP)
        IntuitiveSnapshot snap;
        snap.timestamp = currentTime;
        snap.qi = qi;
        snap.sr = sr;
        snap.tii = tii;
        snap.arf = arf;
        snap.meanRho = meanRho;
        snap.netLearning = distLearn.networkLearningMean();
        snap.pThreat = pThreat;
        snap.actionsDoNothing = 0;
        snap.actionsReallocate = 0;
        snap.actionsRecluster = 0;
        snap.totalOrphans = 0;
        snap.cycleS1Count = 0;
        snap.cycleS2Count = 0;
        snap.anomalies = anomalousNodes.size();
        snap.qDoNothing = dualSys.getQValueAvg(DO_NOTHING);
        snap.qReallocate = dualSys.getQValueAvg(REALLOCATE_TO_EXISTING);
        snap.qRecluster = dualSys.getQValueAvg(RECLUSTER_ORPHANS);

        // Telemetria do ramo atacante — contadores zerados, AP preenche depois.
        // Q-values capturados aqui pra refletir estado pré-decisão deste ciclo.
        snap.suspectsCount = 0;
        snap.actionsAttackerQuarantine = 0;
        snap.actionsAttackerDoNothing  = 0;
        snap.smartTransferOk      = 0;
        snap.smartTransferNoDonor = 0;
        snap.smartRedundancyOk    = 0;
        snap.leadersAlive         = 0;  // AP preenche depois
        snap.leadersDownThisCycle = 0;  // AP preenche depois
        snap.apIncomingFloodTotal       = 0;  // AP preenche depois (v2)
        snap.apQuarantinedLeadersCount  = 0;  // idem
        snap.forcedReelectionsThisCycle = 0;  // idem
        snap.apAliveSnapshot            = true; // default; AP atualiza se cair
        snap.qAttackerDoNothingHigh  = attackerSys.getQ(ATK_SUSPECT_HIGH, ATK_DO_NOTHING);
        snap.qAttackerQuarantineHigh = attackerSys.getQ(ATK_SUSPECT_HIGH, ATK_QUARANTINE);
        snap.qAttackerDoNothingLow   = attackerSys.getQ(ATK_SUSPECT_LOW,  ATK_DO_NOTHING);
        snap.qAttackerQuarantineLow  = attackerSys.getQ(ATK_SUSPECT_LOW,  ATK_QUARANTINE);
        snap.attackerEpsilon         = attackerSys.getEpsilon();

        // NÃO push_back ainda — o AP preencherá os contadores e fará push

        NS_LOG_UNCOND("INTUITIVE: t=" << currentTime
                      << " QI=" << qi << " SR=" << sr
                      << " Pthr=" << pThreat
                      << " TII=" << tii << " ARF=" << arf
                      << " Anom=" << anomalousNodes.size()
                      << " Orphans=" << orphans);

        return snap;
    }

    void IntuitiveLearningEngine::postActionUpdate(double qiAfter, double srAfter, bool hadOrphans) {
        // Decai epsilon apenas quando houve decisões sobre órfãos
        // Sem órfãos → sem decisão → sem razão para reduzir exploração
        if(hadOrphans){
            dualSys.decayEpsilon();
        }

        // Atualizar Rhistorical com métricas globais pós-ação
        // Usar DO_NOTHING como placeholder — a ação real é por órfão
        knowledge.updateHistorical(Simulator::Now().GetSeconds(), DO_NOTHING, qiAfter - lastQI, srAfter - lastSR);
    }

    // ============================================================
    // Persistência — KnowledgeNetworks
    // ============================================================

    void KnowledgeNetworks::saveToStream(std::ofstream& out) const {
        out << "[HISTORICAL]" << std::endl;
        out << "# timestamp,action,qiDelta,srDelta,reward" << std::endl;
        for (const auto& entry : historical) {
            out << entry.first << ","
                << entry.second.action << ","
                << entry.second.qiDelta << ","
                << entry.second.srDelta << ","
                << entry.second.reward << std::endl;
        }

        out << "[INTUITIVE]" << std::endl;
        out << "# stateBucket,action,reward_window..." << std::endl;
        for (const auto& entry : intuitive) {
            out << entry.first.first << "," << entry.first.second;
            for (double r : entry.second) {
                out << "," << r;
            }
            out << std::endl;
        }
    }

    // ============================================================
    // Persistência — DualSystemResponse
    // ============================================================

    void DualSystemResponse::saveToStream(std::ofstream& out) const {
        out << "[QTABLE]" << std::endl;
        out << "# state,action,q_value" << std::endl;
        for (int s = 0; s < ORPHAN_STATE_COUNT; s++) {
            for (int a = 0; a < INTUITIVE_ACTION_COUNT; a++) {
                auto sit = Q.find(s);
                double val = 0.0;
                if (sit != Q.end()) {
                    auto ait = sit->second.find(a);
                    if (ait != sit->second.end()) val = ait->second;
                }
                out << s << "," << a << "," << val << std::endl;
            }
        }
        out << "[EPSILON]" << std::endl;
        out << "# epsilon" << std::endl;
        out << epsilon << std::endl;
        out << "[COUNTERS]" << std::endl;
        out << "# s1count,s2count" << std::endl;
        out << s1Count << "," << s2Count << std::endl;
    }

    // ============================================================
    // Persistência — IntuitiveLearningEngine (orquestrador)
    // ============================================================

    void IntuitiveLearningEngine::saveKnowledge(const std::string& path) const {
        std::ofstream out(path);
        if (!out.is_open()) {
            NS_LOG_UNCOND("INTUITIVE_PERSIST: Erro ao abrir " << path << " para escrita");
            return;
        }

        knowledge.saveToStream(out);
        dualSys.saveToStream(out);
        attackerSys.saveToStream(out);

        out.close();
        NS_LOG_UNCOND("INTUITIVE_PERSIST: Conhecimento salvo em " << path);
    }

    bool IntuitiveLearningEngine::loadKnowledge(const std::string& path) {
        std::ifstream in(path);
        if (!in.is_open()) {
            NS_LOG_UNCOND("INTUITIVE_PERSIST: Arquivo " << path << " não encontrado — iniciando do zero");
            return false;
        }

        // Parser de passada única: lê todas as seções em sequência
        std::string line;
        std::string section;

        while (std::getline(in, line)) {
            // Remover \r se presente (WSL/Windows)
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) continue;

            if (line[0] == '[') {
                section = line;
                continue;
            }

            if (line[0] == '#') continue;

            if (section == "[HISTORICAL]") {
                std::stringstream ss(line);
                std::string tok;
                HistoricalRecord rec;
                std::getline(ss, tok, ','); double ts = std::stod(tok);
                std::getline(ss, tok, ','); rec.action = static_cast<IntuitiveAction>(std::stoi(tok));
                std::getline(ss, tok, ','); rec.qiDelta = std::stod(tok);
                std::getline(ss, tok, ','); rec.srDelta = std::stod(tok);
                std::getline(ss, tok, ','); rec.reward = std::stod(tok);
                rec.timestamp = ts;
                knowledge.updateHistorical(ts, rec.action, rec.qiDelta, rec.srDelta);
            }
            else if (section == "[INTUITIVE]") {
                std::stringstream ss(line);
                std::string bucket;
                std::getline(ss, bucket, ',');
                std::string tok;
                std::getline(ss, tok, ',');
                int action = std::stoi(tok);
                while (std::getline(ss, tok, ',')) {
                    knowledge.updateIntuitive(bucket, static_cast<IntuitiveAction>(action), std::stod(tok));
                }
            }
            else if (section == "[QTABLE]") {
                std::stringstream ss(line);
                std::string tok;
                std::getline(ss, tok, ','); int s = std::stoi(tok);
                std::getline(ss, tok, ','); int a = std::stoi(tok);
                std::getline(ss, tok, ','); double val = std::stod(tok);
                dualSys.loadQValue(s, a, val);
            }
            else if (section == "[EPSILON]") {
                dualSys.loadEpsilon(std::stod(line));
            }
            else if (section == "[COUNTERS]") {
                std::stringstream ss(line);
                std::string tok;
                std::getline(ss, tok, ','); uint32_t s1 = std::stoul(tok);
                std::getline(ss, tok, ','); uint32_t s2 = std::stoul(tok);
                dualSys.loadCounters(s1, s2);
            }
            else if (section == "[QTABLE_ATTACKER]") {
                std::stringstream ss(line);
                std::string tok;
                std::getline(ss, tok, ','); int s = std::stoi(tok);
                std::getline(ss, tok, ','); int a = std::stoi(tok);
                std::getline(ss, tok, ','); double val = std::stod(tok);
                attackerSys.loadQValue(s, a, val);
            }
            else if (section == "[EPSILON_ATTACKER]") {
                attackerSys.loadEpsilon(std::stod(line));
            }
            else if (section == "[COUNTERS_ATTACKER]") {
                std::stringstream ss(line);
                std::string tok;
                std::getline(ss, tok, ','); uint32_t q = std::stoul(tok);
                std::getline(ss, tok, ','); uint32_t d = std::stoul(tok);
                attackerSys.loadCounters(q, d);
            }
        }

        in.close();
        NS_LOG_UNCOND("INTUITIVE_PERSIST: Conhecimento carregado de " << path);
        return true;
    }

} // namespace nr2