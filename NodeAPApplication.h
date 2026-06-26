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

            NodeContainer           networkNodes;           // Referência aos nós da rede (acesso por idx pelo AP)

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

            // RNG reutilizável para Li inicial de líderes (LeaderRegister)
            Ptr<UniformRandomVariable>  m_liRng;

            // Fase 2 — pipeline de defesa contra atacante (membro→líder)
            // Contadores reportados pelos líderes via heartbeat: leader → (source → packets).
            // Consumidos pelo AnomalyDetector::detectFlooders no intuitiveDecisionCycle.
            std::map<Ipv6Address, std::map<Ipv6Address, uint32_t>>  leaderSourceCounts;
            // Decisão da janela anterior por suspeito (state, action) — usado pra computar
            // recompensa observacional no próximo ciclo.
            struct PendingDecision {
                AttackerState  state;
                AttackerAction action;
                Ipv6Address    leader;     // qual líder reportou
            };
            std::map<Ipv6Address, PendingDecision> lastAttackerDecisions;
            // IPs quarentenados → timestamp do comando. Com TTL, um IP volta a
            // poder ser quarentenado depois de QUARANTINE_TTL segundos sem
            // observação de novo flood. Suporta cenários longos e re-emissão
            // após líder original ter morrido sem disseminar a blocklist.
            std::map<Ipv6Address, double>  globallyQuarantined;
            static constexpr double QUARANTINE_TTL = 60.0;  // 12 ciclos de 5s

            // ============================================================
            // v2 — Defesa contra líder atacando o AP
            // ============================================================
            // Contador de FloodPackets recebidos pelo AP, por origem.
            // Equivalente ao incomingPacketCount do líder em v1, mas observado
            // diretamente pela vítima (AP) sem precisar de heartbeat.
            std::map<Ipv6Address, uint32_t>  apIncomingFloodCount;

            // Total acumulado de FloodPackets recebidos no AP — modelo de
            // saturação análogo ao do líder em v1. Quando atinge
            // FLOOD_SATURATION_THRESHOLD, AP "cai" (apAlive=false).
            uint64_t                         apTotalFloodReceived;
            bool                             apAlive;

            // Líderes quarentenados pelo pipeline AP (subset de
            // globallyQuarantined; usado pra disparar ForceReelection e contar
            // telemetria separada do v1).
            std::set<Ipv6Address>            apQuarantinedLeaders;

            // Contador cumulativo de re-eleições forçadas (telemetria).
            uint32_t                         forcedReelectionsTotal;

            // ------------------------------------------------------------
            // v2 fast-path — auto-vigilância do AP
            // ------------------------------------------------------------
            // O detector vive NO AP (a própria vítima). Com o ciclo estratégico
            // de 5s, o AP satura (FLOOD_SATURATION_THRESHOLD pkts) em segundos —
            // antes de qualquer decisão — e, morto, não há agente pra mitigar.
            // Por isso a detecção/mitigação flood→AP roda num timer rápido
            // dedicado (apMonitorInterval), que age MUITO antes da saturação.
            double                           apMonitorInterval = 1.0;  // s

            // Telemetria desacoplada: o monitor rápido esvazia apIncomingFloodCount
            // a cada tick, então o ciclo estratégico (5s) lê deltas cumulativos.
            uint64_t                         apFloodAtLastCycle;       // apTotalFloodReceived no último ciclo 5s
            uint32_t                         forcedReelecAtLastCycle;  // forcedReelectionsTotal no último ciclo 5s
            // Acumuladores preenchidos pelo monitor rápido, drenados pelo ciclo 5s.
            uint32_t                         apSuspectsAccum;
            uint32_t                         apQuarAccum;
            uint32_t                         apDoNothingAccum;

            // Override determinístico: o orçamento de tempo até saturar é minúsculo,
            // então não dá pra esperar o ε-greedy explorar. Se a evidência é forte
            // (z alto E volume na janela acima do piso), quarentena na hora — espelha
            // o fallback de limiar absoluto do detectFlooders (v1). A decisão ainda
            // alimenta o Q-learning (aprende que o override foi acertado).
            static constexpr double          AP_Z_HARD    = 4.0;
            static constexpr uint32_t        AP_ABS_FLOOR = 20;  // pkts na janela do monitor

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

            // Setter da referência aos nós da rede (consumido pelo smart-quarantine
            // para procurar doadores via getNodeCapabilities + getMyLeader).
            void setNodes(NodeContainer nodes);

            // ============================================================
            // Aprendizado Intuitivo — Métodos de integração
            // ============================================================

            // Configurar número total de nós (chamado por contaski.cc)
            void setTotalNodes(uint32_t n) { this->totalNetworkNodes = n; }

            // Configurar intervalo de decisão (padrão: 60s)
            void setDecisionInterval(double interval) { this->decisionInterval = interval; }

            // Configurar caminho do arquivo de conhecimento persistente
            void setKnowledgePath(const std::string& path) { this->knowledgePath = path; }

            // Ciclo periódico de decisão do aprendizado intuitivo
            void intuitiveDecisionCycle();

            // Processar órfãos com decisão individual por órfão (S1/S2 + Q-Table 3×3)
            void processOrphansIntuitively(IntuitiveSnapshot& snap);

            // Construir vetor de ClusterInfo a partir do mapa
            std::vector<ClusterInfo> buildClusterInfoVector() const;

            // Escrever log de snapshots intuitivos ao final da simulação
            void writeIntuitiveLog();

            // Processar heartbeat de líder (atualiza memberCount e lastHeartbeat)
            void processHeartbeat(Ipv6Address leaderAddr, uint32_t currentMembers);

            // Atualizar contagens de membros de cluster
            void updateClusterInfo(Ipv6Address leader, uint32_t memberCount, uint32_t initialMemberCount);

            // Fase 2 — defesa
            // Roda a etapa de detecção de flood + decisão DualSystem (atacante) por suspeito.
            // Chamada de dentro do intuitiveDecisionCycle. snap recebe os contadores
            // do ramo atacante deste ciclo para telemetria do CSV.
            void processAttackersIntuitively(IntuitiveSnapshot& snap);

            // v2 — pipeline simétrico ao processAttackersIntuitively, mas pra
            // atacantes que são líderes flodando o AP. Detecta suspeitos sobre
            // apIncomingFloodCount, decide via mesmo AttackerDualSystem, executa
            // quarentena local no AP (drop) + ForceReelection no cluster afetado.
            void processAPAttackersIntuitively(IntuitiveSnapshot& snap);

            // v2 fast-path — monitor de auto-vigilância do AP. Roda a cada
            // apMonitorInterval (independente do ciclo estratégico de 5s):
            // detecta flood→AP, decide via AttackerDualSystem (com override
            // determinístico) e dispara quarentena + ForceReelection ANTES da
            // saturação. Se o AP cair, não reagenda (AP morto não monitora).
            void apFloodMonitorCycle();

            // Envia ForceReelection a todos os membros do cluster cujo líder
            // está sendo quarentenado, pedindo que re-elejam um novo líder
            // excluindo o IP do antigo.
            void sendForceReelection(Ipv6Address badLeader);
            // Envia ordem de quarentena a um líder específico, payload = IP alvo.
            void sendQuarantineOrder(Ipv6Address leaderAddr, Ipv6Address target);

            // ============================================================
            // Fase 2.5 — smart quarantine (capability-aware)
            // ============================================================
            // União das capabilities dos membros vivos de um cluster, opcionalmente
            // excluindo um IP (usado pra simular "e se eu tirar este nó?").
            std::vector<capabilities> getClusterCapabilityUnion(
                Ipv6Address leader, Ipv6Address excludeNode) const;
            // Caps que o cluster perderia se `suspect` fosse removido (set difference).
            std::vector<capabilities> capsLostIfRemoved(
                Ipv6Address leader, Ipv6Address suspect) const;
            // Resultado da busca por doador compatível.
            struct DonorChoice {
                Ipv6Address donor;
                Ipv6Address donorLeader;
                int         coveredCount;     // quantas das missingCaps o doador tem
                double      similarityToRecv; // capabilitiesSimilarity com cluster receptor
                bool        found;
            };
            // Procura membro de outro cluster que cubra as missing caps SEM deixar
            // seu próprio cluster sem redundância. Critério: cobre mais caps;
            // empate desempata por maior similaridade com cluster receptor.
            DonorChoice findCapabilityDonor(
                const std::vector<capabilities>& missingCaps,
                Ipv6Address receiverLeader,
                Ipv6Address suspectToExclude) const;
            // Aplica a transferência (in-process, mesmo padrão do REALLOCATE de órfãos).
            // Atualiza clusterList dos dois líderes, myLeader do doador, e memberCount.
            bool transferDonorToCluster(Ipv6Address donor,
                                        Ipv6Address oldLeader,
                                        Ipv6Address newLeader);
    };
}
