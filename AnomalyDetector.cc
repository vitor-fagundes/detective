#include "AnomalyDetector.h"

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

    // double AnomalyDetector::zScore(double value, double mean, double stddev) {
    //     if (stddev < 1e-10) return 0.0;
    //     return std::abs(value - mean) / stddev;
    // }

    double AnomalyDetector::zScore(double value, double mean, double stddev) {
        // Se a rede está perfeitamente determinística (stddev quase 0)
        if (stddev < 1e-10) {
            // Verifica se o valor mudou em relação à média.
            // Se o valor continuou igual à média, não há anomalia.
            if (std::abs(value - mean) < 1e-10) {
                return 0.0; 
            } else {
                // Se o valor mudou (ex: heartbeat pulou de 5s para 10s),
                // é uma anomalia extrema! Retornamos um score alto.
                return 10.0; 
            }
        }
        // Cálculo normal do Z-Score se houver variância
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

} // namespace nr2