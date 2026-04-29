#pragma once

/**
 * Módulo 3 — Detecção de Anomalias
 * ==================================
 * Implementação adaptada para C++/NS-3.
 *
 * O código Python original usa Isolation Forest + LOF (scikit-learn).
 * Em C++, implementamos um detector baseado em Z-score multivariado
 * com janela deslizante, que captura o mesmo conceito:
 *   - Nós com métricas fora do padrão da rede são anômalos
 *   - Ensemble de dois critérios para reduzir falsos positivos
 *     (ambos devem concordar, como o voto duplo IF+LOF do Python)
 *
 * Features por nó: [taskAcceptRate, timeSinceContact, clusterHealthRatio]
 * Estas são as métricas observáveis pelo AP sem comunicação adicional.
 */

#include "ns3/ipv6-address.h"
#include <map>
#include <set>
#include <vector>
#include <deque>
#include <cmath>
#include <algorithm>
#include <numeric>

using namespace ns3;

namespace nr2 {

    // Feature vector de um nó observado pelo AP
    struct NodeFeatures {
        double taskAcceptRate;      // Taxa de aceitação de tarefas recente
        double timeSinceContact;    // Tempo desde último contato (s)
        double clusterHealthRatio;  // Saúde do cluster (membros/inicial)
    };

    class AnomalyDetector {
    public:
        AnomalyDetector(double zThreshold = 2.0, size_t windowSize = 20);

        // Atualizar features de um nó (chamado pelo AP quando recebe informação)
        void updateFeatures(Ipv6Address addr, const NodeFeatures& features);

        // Executar detecção de anomalias
        // Retorna set de nós detectados como anômalos
        std::set<Ipv6Address> detect();

        // Obter scores de anomalia (maior = mais anômalo)
        std::map<Ipv6Address, double> getScores() const { return lastScores; }

    private:
        // Calcular Z-score de um valor em relação à média/desvpad
        static double zScore(double value, double mean, double stddev);

        // Calcular média e desvio padrão de um vetor
        static std::pair<double, double> meanStd(const std::vector<double>& values);

        // Limiar de Z-score para considerar anômalo
        double zThreshold;

        // Janela de observações por nó (para baseline temporal)
        size_t windowSize;

        // Features atuais por nó
        std::map<Ipv6Address, NodeFeatures> currentFeatures;

        // Histórico de features por nó (janela deslizante)
        std::map<Ipv6Address, std::deque<NodeFeatures>> featureHistory;

        // Último resultado de detecção
        std::map<Ipv6Address, double> lastScores;
    };

} // namespace nr2