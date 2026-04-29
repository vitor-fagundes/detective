#pragma once

#include "ns3/core-module.h"
#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/node-container.h"

#include "capabilities.h"
#include "task.h"
#include "IntuitiveLearning.h"
#include "AnomalyDetector.h"

using namespace ns3;

namespace nr2{
    class NodeApplication;  // Forward declaration

    class NodeAPApplication : public Application{
        private:
            taskVector*             tasks;              // Vector of tasks waiting to be dispatched
            taskVector*             dispatchedTasks;    // Vector of dispatched tasks
            Task*                   currentDispatchedTask;
            std::vector<Ipv6Address>*   clusterLeaders;     // Addresses of clusterLeaders
            std::vector<Ipv6Address>*   aptLeaders;         // Leaders que aceitaram tarefas (aptos)
            Ptr<Socket>     		m_socket;       	// Associated socket
            Address					m_node;				// Node's
            TypeId          		m_tid;          	// Type of the socket used
            Ipv6Address             GetNodeIpAddress();
            uint32_t                confirmationsSinceLastDispatch;
            uint32_t                requiredQuorum;     // Número mínimo de agrupamentos que devem aceitar

            // Falhas
            double                  failurePercentage;      // Porcentagem de líderes aptos que irão falhar
            double                  failurePercentageMin;   // Porcentagem mínima (para modo aleatório)
            double                  failurePercentageMax;   // Porcentagem máxima (para modo aleatório)
            double                  failureTimeMin;         // Tempo mínimo para falha (segundos)
            double                  failureTimeMax;         // Tempo máximo para falha (segundos)
            double                  actualFailureTime;      // Tempo real da falha (calculado)
            double                  actualFailurePercentage; // Porcentagem real da falha (calculada)
            NodeContainer           networkNodes;           // Referência aos nós da rede

            // Cenário 4: Múltiplas falhas sequenciais na mesma rodada
            bool                    multipleFailuresEnabled;    // Se true, usa failureTimes[]
            std::vector<double>     failureTimes;               // Tempos das falhas (ex: 300, 450, 600)
            double                  multipleFailurePercentage;  // Porcentagem fixa para cada falha
            int                     currentFailureWave;         // Contador de qual onda de falha estamos

            // ============================================================
            // Aprendizado Intuitivo — Módulos 1-5
            // ============================================================
            IntuitiveLearningEngine*    intuitiveEngine;    // Motor de aprendizado intuitivo
            AnomalyDetector*            anomalyDetector;    // Detector de anomalias (Módulo 3)
            
            // Intervalo entre ciclos de decisão do aprendizado intuitivo (segundos)
            double                      decisionInterval;
            
            // Informação dos clusters mantida pelo AP
            std::map<Ipv6Address, ClusterInfo>  clusterInfoMap;
            
            // Nós detectados como anômalos no último ciclo
            std::set<Ipv6Address>       anomalousNodes;
            
            // Contagem total de nós na rede
            uint32_t                    totalNetworkNodes;

            // Contagem de tarefas aceitas por líder (para taxa de aceitação)
            std::map<Ipv6Address, uint32_t> taskAcceptCount;
            // Contagem de tarefas enviadas a cada líder
            std::map<Ipv6Address, uint32_t> taskDispatchCount;

            // Flag: todos os nós já foram registrados no aprendizado distribuído
            bool                        allNodesRegistered;

            // Lista de nós órfãos que não foram realocados (persiste entre ciclos)
            // Populada por REALLOCATE quando não encontra cluster compatível
            // Consumida por RECLUSTER para formar novos clusters
            std::vector<Ipv6Address>    pendingOrphans;

            // Caminho para o arquivo de conhecimento persistente entre rodadas
            std::string                 knowledgePath;

            // Configuração de ataque UDP flood (gerenciado pelo AP pós-clustering)
            uint32_t                    attackNAttackers;
            double                      attackStartTime;
            double                      attackRate;
            uint32_t                    attackPayloadSize;
            uint32_t                    attackMode;  // 1=membro→líder, 2=líder→AP

        public:
            void setup();
            void generateTasks(int totalDuration);
            void sendTaskToLeaders();
            void recvCallback(Ptr<Socket> socket);
            void taskConfirmation();
            void StartApplication();
            void StopApplication();
            static TypeId GetTypeId();
            void setTasks(taskVector*);

            // Falhas
            void setFailurePercentage(double percentage);
            void setFailurePercentageRange(double min, double max);
            void setFailureTimeRange(double min, double max);
            void setNodes(NodeContainer nodes);
            void triggerLeaderFailures();

            // Cenário 4: Múltiplas falhas sequenciais
            void setMultipleFailures(std::vector<double> times, double percentage);
            void triggerMultipleFailureWave();

            // ============================================================
            // Aprendizado Intuitivo — Métodos de integração
            // ============================================================
            
            // Configurar número total de nós (chamado por contaski.cc)
            void setTotalNodes(uint32_t n) { this->totalNetworkNodes = n; }
            
            // Configurar intervalo de decisão (padrão: 60s)
            void setDecisionInterval(double interval) { this->decisionInterval = interval; }

            // Configurar caminho do arquivo de conhecimento persistente
            void setKnowledgePath(const std::string& path) { this->knowledgePath = path; }

            // Configurar ataque UDP flood (seleção adiada para pós-clustering)
            void setAttackConfig(uint32_t nAttackers, double startTime, double rate,
                                 uint32_t payloadSize, uint32_t mode);
            void selectAndConfigureAttackers();

            // Ciclo periódico de decisão do aprendizado intuitivo
            void intuitiveDecisionCycle();
            
            // Processar órfãos com decisão individual por órfão (S1/S2 + Q-Table 4×3)
            void processOrphansIntuitively(IntuitiveSnapshot& snap);
            
            // Atualizar informações de cluster no mapa do AP
            void updateClusterInfo(Ipv6Address leader, uint32_t memberCount,
                                   uint32_t initialMemberCount);
            
            // Construir vetor de ClusterInfo a partir do mapa
            std::vector<ClusterInfo> buildClusterInfoVector() const;

            // Processar heartbeat de um líder
            void processHeartbeat(Ipv6Address leaderAddr, uint32_t currentMembers);

            // Escrever log de snapshots intuitivos ao final da simulação
            void writeIntuitiveLog();
    };
}