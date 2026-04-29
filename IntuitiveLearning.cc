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

    std::vector<Ipv6Address> KnowledgeNetworks::recentEmergentNodes() const {
        std::vector<Ipv6Address> result;
        for (const auto& evt : emergent) {
            result.push_back(evt.node);
        }
        return result;
    }

    std::string KnowledgeNetworks::discretizeState(double qi, double sr) {
        // Discretiza (QI, SR) em 9 combinações: {low,mid,high} × {low,mid,high}
        auto bucket = [](double v) -> std::string {
            if (v < 0.35) return "low";
            if (v < 0.65) return "mid";
            return "high";
        };
        return "qi_" + bucket(qi) + "_sr_" + bucket(sr);
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

            // Líder é vizinho dos membros
            for (const auto& member : members) {
                neighbors[leader].push_back(member);
                neighbors[member].push_back(leader);
                // Membros são vizinhos entre si dentro do cluster
                for (const auto& otherMember : members) {
                    if (member != otherMember) {
                        neighbors[member].push_back(otherMember);
                    }
                }
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
                envStimulus = -0.05;
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
        // pThreat = 1 - (mean_Li_vivos × fração_sobreviventes)
        // Antes: pThreat = 1 - mean_Li_vivos, que DESCIA quando líderes morriam
        // (porque os remanescentes tinham Li acima da média).
        // Agora: matar 4 de 11 líderes → survivalRatio=0.636 → pThreat sobe.
        if (totalLeaders == 0) {
            return 1.0;
        }

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

        double survivalRatio = (double)leaderLi.size() / (double)totalLeaders;

        return std::min(1.0, std::max(0.0, 1.0 - mean * survivalRatio));
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

    void DistributedLearning::markAnomalous(Ipv6Address addr, bool anomalous) {
        auto it = nodes.find(addr);
        if (it != nodes.end()) {
            it->second.isAnomalous = anomalous;
        }
    }

    // ============================================================
    // MÓDULO 4 — DualSystemResponse
    // ============================================================

    DualSystemResponse::DualSystemResponse(double epsilon, double epsilonDecay,
                                           double epsilonMin)
        : epsilon(epsilon), epsilonDecay(epsilonDecay), epsilonMin(epsilonMin),
          s1Count(0), s2Count(0) {
        // Inicializar Q-table 4×3 com zeros
        for (int s = 0; s < ORPHAN_STATE_COUNT; s++) {
            for (int a = 0; a < INTUITIVE_ACTION_COUNT; a++) {
                Q[s][a] = 0.0;
            }
        }
    }

    OrphanState DualSystemResponse::determineOrphanState(double simExisting, double simOrphans) {
        bool existingHigh = (simExisting >= SIMILARITY_HIGH_THRESHOLD);
        bool orphansHigh  = (simOrphans >= SIMILARITY_HIGH_THRESHOLD);

        if (existingHigh && orphansHigh)  return SIM_BOTH_HIGH;
        if (existingHigh && !orphansHigh) return SIM_EXISTING_HIGH;
        if (!existingHigh && orphansHigh) return SIM_ORPHAN_HIGH;
        return SIM_BOTH_MEDIUM;
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
            case SIM_EXISTING_HIGH:
                return REALLOCATE_TO_EXISTING;
            case SIM_ORPHAN_HIGH:
                return RECLUSTER_ORPHANS;
            case SIM_BOTH_HIGH:
                return REALLOCATE_TO_EXISTING;
            case SIM_BOTH_MEDIUM:
            default:
                return DO_NOTHING;
        }
    }

    IntuitiveAction DualSystemResponse::system2Response(
            OrphanState orphanState,
            const DistributedLearning& distLearn) {
        s2Count++;
        int s = static_cast<int>(orphanState);

        // ε-greedy: exploração aleatória (NS-3 RNG para reprodutibilidade)
        Ptr<UniformRandomVariable> uRng = CreateObject<UniformRandomVariable>();
        uRng->SetAttribute("Min", DoubleValue(0.0));
        uRng->SetAttribute("Max", DoubleValue(1.0));
        if (uRng->GetValue() < epsilon) {
            Ptr<UniformRandomVariable> aRng = CreateObject<UniformRandomVariable>();
            aRng->SetAttribute("Min", DoubleValue(0.0));
            aRng->SetAttribute("Max", DoubleValue(INTUITIVE_ACTION_COUNT - 0.001));
            return static_cast<IntuitiveAction>((int)aRng->GetValue());
        }

        // Explotação: melhor ação ajustada pela capacidade de aprendizado
        double netLearning = distLearn.networkLearningMean();
        std::map<int, double> adjustedQ;

        for (int a = 0; a < INTUITIVE_ACTION_COUNT; a++) {
            adjustedQ[a] = Q[s][a] + 0.1 * netLearning * (a != DO_NOTHING ? 1.0 : 0.0);
        }

        // Penalizar DO_NOTHING para estados onde há opção viável
        if (orphanState == SIM_EXISTING_HIGH || orphanState == SIM_ORPHAN_HIGH
            || orphanState == SIM_BOTH_HIGH) {
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

        if (pThreat > THRESHOLD_S1) {
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

    void DualSystemResponse::updateQGlobal(double qiBefore, double qiAfter,
                                            double srBefore, double srAfter) {
        // Atualização global pós-ciclo — não modifica Q-Table (já atualizada por órfão)
        // Reservado para uso futuro ou métricas adicionais
        (void)qiBefore; (void)qiAfter; (void)srBefore; (void)srAfter;
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
            const std::vector<Ipv6Address>& leaders,
            uint32_t totalAliveNodes) {
        // TII(T) = Σ wi · anticipation_score(i) / |V|
        // Simplificado: wi = Li, anticipation_score = 1 se líder vivo, 0 se não
        if (totalAliveNodes == 0) return 0.0;

        double sum = 0.0;
        for (const auto& leader : leaders) {
            double wi = distLearn.getLi(leader);
            // Líderes com Li alto → alta capacidade de antecipação
            sum += wi;
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
            const std::vector<ClusterInfo>& clusters,
            uint32_t totalAliveNodes) {
        // Proporção de clusters com líder ativo e que aceitaram tarefas
        if (clusters.empty()) return 0.0;

        int healthyClusters = 0;
        for (const auto& cluster : clusters) {
            if (cluster.leaderAlive && cluster.hasAcceptedTask) {
                healthyClusters++;
            }
        }

        return (double)healthyClusters / clusters.size();
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
            const std::vector<ClusterInfo>& clusters, uint32_t totalNodes) {
        // QI = combinação ponderada de:
        //   - Fração de clusters com líder ativo (connectivity)
        //   - Proporção de nós cobertos (propagation)
        //   - Saúde média dos clusters ponderada por qualidade do enlace (delivery)
        //
        // No Python: delivery usa edge_quality × capacity.
        // No NS-3: usamos (memberCount/initialMemberCount) × linkQuality
        //   onde linkQuality = proxy baseado na recência do heartbeat.
        //   Isso faz com que ações que melhoram heartbeat (REINFORCE, REPAIR)
        //   impactem diretamente o QI.
        if (clusters.empty() || totalNodes == 0) return 0.0;

        double now = Simulator::Now().GetSeconds();

        // Connectivity: fração de clusters com líder ativo
        int activeClusters = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive) activeClusters++;
        }
        double connectivity = (double)activeClusters / clusters.size();

        // Propagation: nós cobertos por clusters ativos / total de nós
        uint32_t coveredNodes = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive) {
                coveredNodes += c.memberCount + 1; // +1 para o líder
            }
        }
        double propagation = std::min(1.0, (double)coveredNodes / totalNodes);

        // Delivery: saúde média dos clusters × qualidade do enlace
        // Alinhado com Python: delivery_ratio_proxy usa quality × capacity
        double deliverySum = 0.0;
        int deliveryCount = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive && c.initialMemberCount > 0) {
                double healthRatio = std::min(1.0, (double)c.memberCount / c.initialMemberCount);
                
                // linkQuality: proxy de edge quality via recência do heartbeat
                double elapsed = (c.lastHeartbeat > 0) ?
                    (now - c.lastHeartbeat) : 120.0;
                double linkQuality = std::max(0.1, 1.0 - std::min(1.0, elapsed / 120.0));
                
                deliverySum += healthRatio * linkQuality;
                deliveryCount++;
            }
        }
        double delivery = deliveryCount > 0 ? deliverySum / deliveryCount : 0.0;

        // QI = 0.5·connectivity + 0.3·propagation + 0.2·delivery
        return std::min(1.0, 0.5 * connectivity + 0.3 * propagation + 0.2 * delivery);
    }

    double IntuitiveLearningEngine::calculateSR(
            const std::vector<ClusterInfo>& clusters, uint32_t totalNodes) {
        // SR = fração de nós que alcançam o AP (via clusters com líder ativo)
        if (totalNodes == 0) return 0.0;

        uint32_t reachableNodes = 0;
        for (const auto& c : clusters) {
            if (c.leaderAlive) {
                reachableNodes += c.memberCount + 1;
            }
        }

        return std::min(1.0, (double)reachableNodes / totalNodes);
    }

    IntuitiveSnapshot IntuitiveLearningEngine::decisionCycle(
            double currentTime,
            const std::vector<ClusterInfo>& clusters,
            const std::set<Ipv6Address>& anomalousNodes,
            uint32_t totalNodes) {

        // [1] Calcular métricas globais
        double qi = calculateQI(clusters, totalNodes);
        double sr = calculateSR(clusters, totalNodes);

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

        // [4] Atualizar aprendizado distribuído
        std::map<Ipv6Address, std::vector<Ipv6Address>> clusterMembers;
        for (const auto& c : clusters) {
            if (c.leaderAlive) {
                clusterMembers[c.leaderAddr] = {};
            }
        }
        distLearn.step(clusterMembers, anomalousNodes);

        // [5] Salvar estado para uso no loop por órfão (no AP)
        lastQI = qi;
        lastSR = sr;
        lastPThreat = pThreat;

        // [6] Métricas de intuição
        double meanRho = computeResilienceActivation(clusters, distLearn);
        double tii = computeTII(distLearn, aliveLeaders, totalNodes);
        double flex = computeStructuralFlexibility(clusters, totalNodes);
        // responseTime será preenchido pelo AP com base nos contadores S1/S2
        double arf = computeARF(flex, ALPHA_LEARN, distLearn.networkLearningMean(), 2.0);

        // [7] Construir snapshot parcial (contadores de ação preenchidos pelo AP)
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
        knowledge.updateHistorical(lastQI, DO_NOTHING, qiAfter - lastQI, srAfter - lastSR);
    }

    // ============================================================
    // Persistência — KnowledgeNetworks
    // ============================================================

    void KnowledgeNetworks::saveToStream(std::ofstream& out) const {
        // Rhistorical: timestamp,action,qiDelta,srDelta,reward
        out << "[HISTORICAL]" << std::endl;
        for (const auto& entry : historical) {
            out << entry.first << ","
                << entry.second.action << ","
                << entry.second.qiDelta << ","
                << entry.second.srDelta << ","
                << entry.second.reward << std::endl;
        }

        // Rintuitive: stateBucket,action,reward1;reward2;...
        out << "[INTUITIVE]" << std::endl;
        for (const auto& entry : intuitive) {
            out << entry.first.first << "," << entry.first.second;
            for (double r : entry.second) {
                out << "," << r;
            }
            out << std::endl;
        }
    }

    void KnowledgeNetworks::loadFromStream(std::ifstream& in) {
        std::string line;
        std::string section;

        while (std::getline(in, line)) {
            if (line.empty()) continue;
            if (line[0] == '[') {
                section = line;
                if (section != "[HISTORICAL]" && section != "[INTUITIVE]") {
                    break; // Próxima seção de outro módulo
                }
                continue;
            }

            if (section == "[HISTORICAL]") {
                // timestamp,action,qiDelta,srDelta,reward
                std::stringstream ss(line);
                std::string tok;
                HistoricalRecord rec;

                std::getline(ss, tok, ','); double ts = std::stod(tok);
                std::getline(ss, tok, ','); rec.action = static_cast<IntuitiveAction>(std::stoi(tok));
                std::getline(ss, tok, ','); rec.qiDelta = std::stod(tok);
                std::getline(ss, tok, ','); rec.srDelta = std::stod(tok);
                std::getline(ss, tok, ','); rec.reward = std::stod(tok);
                rec.timestamp = ts;
                historical[ts] = rec;
            }
            else if (section == "[INTUITIVE]") {
                // stateBucket,action,reward1,reward2,...
                std::stringstream ss(line);
                std::string bucket;
                std::getline(ss, bucket, ',');
                std::string tok;
                std::getline(ss, tok, ',');
                int action = std::stoi(tok);

                auto key = std::make_pair(bucket, action);
                while (std::getline(ss, tok, ',')) {
                    intuitive[key].push_back(std::stod(tok));
                }
            }
        }
    }

    // ============================================================
    // Persistência — DualSystemResponse
    // ============================================================

    void DualSystemResponse::saveToStream(std::ofstream& out) const {
        out << "[QTABLE]" << std::endl;
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
        out << epsilon << std::endl;
        out << "[COUNTERS]" << std::endl;
        out << s1Count << "," << s2Count << std::endl;
    }

    void DualSystemResponse::loadFromStream(std::ifstream& in) {
        std::string line;
        std::string section;

        while (std::getline(in, line)) {
            if (line.empty()) continue;
            if (line[0] == '[') {
                section = line;
                // Parar se encontrar seção de outro módulo
                if (section != "[QTABLE]" && section != "[EPSILON]" && section != "[COUNTERS]") {
                    break;
                }
                continue;
            }

            if (section == "[QTABLE]") {
                // Formato: state,action,value
                std::stringstream ss(line);
                std::string tok;
                std::getline(ss, tok, ','); int s = std::stoi(tok);
                std::getline(ss, tok, ','); int a = std::stoi(tok);
                std::getline(ss, tok, ','); double val = std::stod(tok);
                Q[s][a] = val;
            }
            else if (section == "[EPSILON]") {
                epsilon = std::stod(line);
            }
            else if (section == "[COUNTERS]") {
                std::stringstream ss(line);
                std::string tok;
                std::getline(ss, tok, ','); s1Count = std::stoul(tok);
                std::getline(ss, tok, ','); s2Count = std::stoul(tok);
            }
        }
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
        }

        in.close();
        NS_LOG_UNCOND("INTUITIVE_PERSIST: Conhecimento carregado de " << path);
        return true;
    }

} // namespace nr2