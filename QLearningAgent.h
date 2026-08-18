#pragma once
// ============================================================
// QLearningAgent — baseline Q-learning REATIVO (portado do sectional).
// Usado APENAS no modo --recoveryEngine=qlearning como comparação contra
// o motor intuitivo do detective. Isolado em `namespace qlbaseline` para
// não colidir com as constantes/enums do motor intuitivo (nr2).
//
// Trata a MESMA falha do detective (flood → saturação de líder → órfãos),
// mas decide a recuperação com Q-learning puro (Q-table 4×3, ε-greedy),
// exatamente como o sectional fazia para falhas de enlace.
// ============================================================
#include <string>
#include <random>
#include <vector>
#include <algorithm>

namespace qlbaseline {

    const int NUM_STATES = 4;
    const int NUM_ACTIONS = 3;

    // Estados compostos por DUAS similaridades (existentes × órfãos)
    enum State {
        SIM_BOTH_HIGH = 0,
        SIM_EXISTING_HIGH = 1,
        SIM_ORPHAN_HIGH = 2,
        SIM_BOTH_MEDIUM = 3
    };

    // Ações (mapeiam 1:1 com a recuperação do detective)
    enum Action {
        DO_NOT_ALLOCATE = 0,        // deixa órfão            (≈ DO_NOTHING)
        REALLOCATE_EXISTING = 1,    // realoca p/ existente   (≈ REALLOCATE)
        FORM_NEW_CLUSTER = 2        // forma novo cluster     (≈ RECLUSTER)
    };

    // Recompensas base (sectional-rl3)
    const double REWARD_SUCCESS = 10.0;
    const double REWARD_ORPHAN  = -5.0;
    const double REWARD_INVALID = -10.0;

    // Limiares (mesmos do detective para paridade de execução)
    const double QL_REALLOCATION_THRESHOLD  = 0.85;
    const double QL_SIMILARITY_HIGH_THRESHOLD = 0.92;
    const double QL_CLUSTERING_THRESHOLD     = 0.85;
    const int    QL_MIN_NODES_FOR_NEW_CLUSTER = 2;

    class QLearningAgent {
        private:
            double qTable[NUM_STATES][NUM_ACTIONS];
            double alpha;   // learning rate
            double gamma;   // discount
            double epsilon; // exploration
            double epsilonDecay = 0.97; // paridade com o intuitivo
            double epsilonMin   = 0.02;
            std::mt19937 rng;
            std::string qTableFilePath;

        public:
            QLearningAgent();
            QLearningAgent(double alpha, double gamma, double epsilon);
            ~QLearningAgent();

            void initializeQTable();
            Action chooseAction(State state);
            void updateQTable(State state, Action action, double reward, State nextState);
            State determineState(double simExisting, double simOrphan);

            void saveQTable(const std::string& filePath);
            void loadQTable(const std::string& filePath);
            void setQTableFilePath(const std::string& filePath);

            double getQValue(State state, Action action);
            void printQTable();

            void setAlpha(double a);
            void setGamma(double g);
            void setEpsilon(double e);
            double getEpsilon() const { return epsilon; }
            // Decai ε (só em ciclos com órfãos processados), igual ao intuitivo
            void decayEpsilon(int orphansThisCycle) {
                if (orphansThisCycle > 0 && epsilon > epsilonMin)
                    epsilon = std::max(epsilonMin, epsilon * epsilonDecay);
            }
    };
}
