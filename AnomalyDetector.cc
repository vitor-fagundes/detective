#include "AnomalyDetector.h"
#include "IntuitiveLearning.h"   // ATTACKER_Z_LOW / ATTACKER_Z_HIGH

namespace nr2 {

    AnomalyDetector::AnomalyDetector(double zThreshold, size_t windowSize)
        : zThreshold(zThreshold), windowSize(windowSize) {
    }

    void AnomalyDetector::updateFeatures(Ipv6Address addr, const NodeFeatures& features) {
        currentFeatures[addr] = features;

        // Manter histórico com janela deslizante
        featureHistory[addr].push_back(features);
        while (featureHistory[addr].size() > windowSize) {
            featureHistory[addr].pop_front();
        }
    }

    double AnomalyDetector::zScore(double value, double mean, double stddev) {
        if (stddev < 1e-10) return 0.0;
        return std::abs(value - mean) / stddev;
    }

    std::pair<double, double> AnomalyDetector::meanStd(const std::vector<double>& values) {
        if (values.empty()) return {0.0, 0.0};

        double mean = 0.0;
        for (double v : values) mean += v;
        mean /= values.size();

        double variance = 0.0;
        for (double v : values) {
            double diff = v - mean;
            variance += diff * diff;
        }
        variance /= values.size();

        return {mean, std::sqrt(variance)};
    }

    std::set<Ipv6Address> AnomalyDetector::detect() {
        std::set<Ipv6Address> anomalous;
        lastScores.clear();

        if (currentFeatures.size() < 3) {
            // Precisa de pelo menos 3 nós para calcular estatísticas
            return anomalous;
        }

        // ---- Critério 1: Z-score GLOBAL ----
        // Comparar cada nó com a distribuição de TODOS os nós atuais
        // (análogo ao Isolation Forest: isola pontos raros na distribuição global)

        std::vector<double> allAcceptRates, allTimeSinceContact, allHealthRatios;
        for (const auto& entry : currentFeatures) {
            allAcceptRates.push_back(entry.second.taskAcceptRate);
            allTimeSinceContact.push_back(entry.second.timeSinceContact);
            allHealthRatios.push_back(entry.second.clusterHealthRatio);
        }

        auto [meanAccept, stdAccept] = meanStd(allAcceptRates);
        auto [meanTime, stdTime] = meanStd(allTimeSinceContact);
        auto [meanHealth, stdHealth] = meanStd(allHealthRatios);

        std::set<Ipv6Address> globalAnomalous;
        std::map<Ipv6Address, double> globalScores;

        for (const auto& entry : currentFeatures) {
            double zAccept  = zScore(entry.second.taskAcceptRate, meanAccept, stdAccept);
            double zTime    = zScore(entry.second.timeSinceContact, meanTime, stdTime);
            double zHealth  = zScore(entry.second.clusterHealthRatio, meanHealth, stdHealth);

            // Score composto: média dos Z-scores
            double score = (zAccept + zTime + zHealth) / 3.0;
            globalScores[entry.first] = score;

            if (score > zThreshold) {
                globalAnomalous.insert(entry.first);
            }
        }

        // ---- Critério 2: Z-score TEMPORAL (por nó) ----
        // Comparar o nó consigo mesmo ao longo do tempo
        // (análogo ao LOF: compara densidade local com vizinhança temporal)

        std::set<Ipv6Address> temporalAnomalous;

        for (const auto& entry : currentFeatures) {
            auto histIt = featureHistory.find(entry.first);
            if (histIt == featureHistory.end() || histIt->second.size() < 3) {
                continue; // Histórico insuficiente
            }

            // Calcular baseline temporal para este nó
            std::vector<double> histAccept, histTime, histHealth;
            for (const auto& f : histIt->second) {
                histAccept.push_back(f.taskAcceptRate);
                histTime.push_back(f.timeSinceContact);
                histHealth.push_back(f.clusterHealthRatio);
            }

            auto [tMeanAccept, tStdAccept] = meanStd(histAccept);
            auto [tMeanTime, tStdTime] = meanStd(histTime);
            auto [tMeanHealth, tStdHealth] = meanStd(histHealth);

            double tZAccept = zScore(entry.second.taskAcceptRate, tMeanAccept, tStdAccept);
            double tZTime   = zScore(entry.second.timeSinceContact, tMeanTime, tStdTime);
            double tZHealth = zScore(entry.second.clusterHealthRatio, tMeanHealth, tStdHealth);

            double tScore = (tZAccept + tZTime + tZHealth) / 3.0;

            if (tScore > zThreshold) {
                temporalAnomalous.insert(entry.first);
            }
        }

        // ---- Ensemble: voto DUPLO obrigatório ----
        // (ambos global e temporal devem concordar, como IF+LOF no Python)
        for (const auto& addr : globalAnomalous) {
            if (temporalAnomalous.count(addr) > 0) {
                anomalous.insert(addr);
                lastScores[addr] = globalScores[addr];
            }
        }

        return anomalous;
    }

    // ============================================================
    // Fase 2 — detecção de UDP flooder (dual: Z-score + threshold absoluto)
    // ============================================================
    std::map<Ipv6Address, double> AnomalyDetector::detectFlooders(
            const std::map<Ipv6Address, std::map<Ipv6Address, uint32_t>>& leaderSourceCounts) const {
        // Threshold absoluto: pacotes recebidos por origem em uma janela de 5s
        // que claramente indica flood. Baseline normal de um membro IIoT é
        // ~0-20 pkts/janela (beacons + ocasional task response). 100 = 20pkts/s
        // sustentado, alto o suficiente pra ser suspeito mesmo num cluster
        // tomado por múltiplos atacantes (cenário em que Z-score colapsa).
        constexpr double ABSOLUTE_FLOOD_THRESHOLD = 100.0;

        std::map<Ipv6Address, double> suspects;

        for (const auto& leaderEntry : leaderSourceCounts) {
            const Ipv6Address& leader = leaderEntry.first;
            const auto& sources = leaderEntry.second;

            // Coletar contagens excluindo o próprio líder
            std::vector<double> counts;
            std::vector<Ipv6Address> sourceList;
            counts.reserve(sources.size());
            sourceList.reserve(sources.size());
            for (const auto& s : sources) {
                if (s.first == leader) continue;       // auto-tráfego não entra no baseline
                counts.push_back((double)s.second);
                sourceList.push_back(s.first);
            }

            // Detector absoluto (independente de tamanho do cluster).
            // Score sintético: mapeia (count / threshold) para faixa do Z-score
            // pra que stateFromZScore() categorize coerentemente.
            //   count == THRESHOLD  → score = ATTACKER_Z_LOW
            //   count == 2*THRESHOLD → score = 2 * ATTACKER_Z_LOW
            for (size_t i = 0; i < counts.size(); i++) {
                if (counts[i] >= ABSOLUTE_FLOOD_THRESHOLD) {
                    double absScore = (counts[i] / ABSOLUTE_FLOOD_THRESHOLD) * ATTACKER_Z_LOW;
                    auto it = suspects.find(sourceList[i]);
                    if (it == suspects.end() || absScore > it->second) {
                        suspects[sourceList[i]] = absScore;
                    }
                }
            }

            // Cluster muito pequeno (<3 origens): só o detector absoluto vale,
            // Z-score não é significativo. Já foi tratado acima.
            if (counts.size() < 3) continue;

            // Detector Z-score relativo (sensível a outliers no cluster normal).
            auto [mean, stddev] = meanStd(counts);
            if (stddev < 1e-6) continue;  // sem dispersão → nada relativo suspeito

            for (size_t i = 0; i < counts.size(); i++) {
                double z = (counts[i] - mean) / stddev;
                if (z >= ATTACKER_Z_LOW) {
                    // Score: max entre Z relativo e Z absoluto já registrado
                    auto it = suspects.find(sourceList[i]);
                    if (it == suspects.end() || z > it->second) {
                        suspects[sourceList[i]] = z;
                    }
                }
            }
        }

        return suspects;
    }

} // namespace nr2