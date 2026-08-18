#include "QLearningAgent.h"
#include <fstream>
#include <iostream>
#include <cmath>

namespace qlbaseline {

    QLearningAgent::QLearningAgent() {
        this->alpha = 0.2;    // paridade com ALPHA_Q do detective
        this->gamma = 0.9;    // paridade com GAMMA_Q
        this->epsilon = 0.15; // paridade com ε inicial do detective
        std::random_device rd;
        this->rng = std::mt19937(rd());
        this->qTableFilePath = "qtable_ql.csv";
        initializeQTable();
    }

    QLearningAgent::QLearningAgent(double alpha, double gamma, double epsilon) {
        this->alpha = alpha;
        this->gamma = gamma;
        this->epsilon = epsilon;
        std::random_device rd;
        this->rng = std::mt19937(rd());
        this->qTableFilePath = "qtable_ql.csv";
        initializeQTable();
    }

    QLearningAgent::~QLearningAgent() {}

    void QLearningAgent::initializeQTable() {
        for (int s = 0; s < NUM_STATES; s++)
            for (int a = 0; a < NUM_ACTIONS; a++)
                qTable[s][a] = 0.0;
    }

    Action QLearningAgent::chooseAction(State state) {
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        if (dist(this->rng) < this->epsilon) {
            std::uniform_int_distribution<int> actionDist(0, NUM_ACTIONS - 1);
            return static_cast<Action>(actionDist(this->rng));
        }
        int bestAction = 0;
        double bestValue = qTable[state][0];
        for (int a = 1; a < NUM_ACTIONS; a++) {
            if (qTable[state][a] > bestValue) {
                bestValue = qTable[state][a];
                bestAction = a;
            }
        }
        // desempate aleatório
        std::vector<int> tied;
        for (int a = 0; a < NUM_ACTIONS; a++)
            if (qTable[state][a] == bestValue) tied.push_back(a);
        if (tied.size() > 1) {
            std::uniform_int_distribution<int> tieDist(0, (int)tied.size() - 1);
            bestAction = tied[tieDist(this->rng)];
        }
        return static_cast<Action>(bestAction);
    }

    void QLearningAgent::updateQTable(State state, Action action, double reward, State nextState) {
        double maxNextQ = qTable[nextState][0];
        for (int a = 1; a < NUM_ACTIONS; a++)
            if (qTable[nextState][a] > maxNextQ) maxNextQ = qTable[nextState][a];
        double currentQ = qTable[state][action];
        qTable[state][action] = currentQ + this->alpha * (reward + this->gamma * maxNextQ - currentQ);
    }

    State QLearningAgent::determineState(double simExisting, double simOrphan) {
        bool existingHigh = (simExisting >= QL_SIMILARITY_HIGH_THRESHOLD);
        bool orphanHigh   = (simOrphan   >= QL_SIMILARITY_HIGH_THRESHOLD);
        if (existingHigh && orphanHigh)   return SIM_BOTH_HIGH;
        if (existingHigh && !orphanHigh)  return SIM_EXISTING_HIGH;
        if (!existingHigh && orphanHigh)  return SIM_ORPHAN_HIGH;
        return SIM_BOTH_MEDIUM;
    }

    void QLearningAgent::saveQTable(const std::string& filePath) {
        std::ofstream file(filePath);
        if (!file.is_open()) return;
        file << "state,action,qvalue\n";
        for (int s = 0; s < NUM_STATES; s++)
            for (int a = 0; a < NUM_ACTIONS; a++)
                file << s << "," << a << "," << qTable[s][a] << "\n";
        file << "epsilon," << epsilon << ",0\n";  // persiste ε (decaimento cumulativo)
        file.close();
    }

    void QLearningAgent::loadQTable(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) { initializeQTable(); return; }
        std::string line;
        std::getline(file, line); // header
        while (std::getline(file, line)) {
            size_t p1 = line.find(','), p2 = line.find(',', p1 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos) continue;
            // Linha do epsilon persistido: "epsilon,<val>,0"
            if (line.compare(0, p1, "epsilon") == 0) {
                epsilon = std::stod(line.substr(p1 + 1, p2 - p1 - 1));
                continue;
            }
            int s = std::stoi(line.substr(0, p1));
            int a = std::stoi(line.substr(p1 + 1, p2 - p1 - 1));
            double q = std::stod(line.substr(p2 + 1));
            if (s >= 0 && s < NUM_STATES && a >= 0 && a < NUM_ACTIONS) qTable[s][a] = q;
        }
        file.close();
    }

    void QLearningAgent::setQTableFilePath(const std::string& filePath) { this->qTableFilePath = filePath; }
    double QLearningAgent::getQValue(State state, Action action) { return qTable[state][action]; }
    void QLearningAgent::printQTable() {}
    void QLearningAgent::setAlpha(double a) { this->alpha = a; }
    void QLearningAgent::setGamma(double g) { this->gamma = g; }
    void QLearningAgent::setEpsilon(double e) { this->epsilon = e; }
}
