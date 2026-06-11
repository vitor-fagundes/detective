#pragma once

#include "ns3/core-module.h"
#include "ns3/application.h"
#include "ns3/socket.h"

#include "capabilities.h"
#include "task.h"
#include "constants.h"
#include "FloodAttack.h"

#include <map>
#include <set>

using namespace ns3;

namespace nr2{
    class NodeApplication : public Application{
        private:
            std::map<Ipv6Address, int>*                             neighList;
            std::map<Ipv6Address, int>*                             clusterList;

            std::map< Ipv6Address, capabilitiesVector>*             neighCapabilities;
            std::vector< std::pair<double, Ipv6Address>* >*          neighSimilatiries;
            Ptr<Socket>                                             m_socket;
            Address                                                 m_node;
            TypeId                                                  m_tid;
            Address                                                 leaderNode;
            Ipv6Address                                             apAddress;

            capabilitiesVector*                                     capabilities;
            bool                                                    isLeader;
            capabilitiesVector*                                     clusterCapabilities;
            double                                                  delay;

            std::vector<Ipv6Address>                                allNodesAddrs;

            // Flag para indicar se o nó está ativo
            bool                                                    alive;

            // Intervalo de heartbeat para líderes (segundos)
            double                                                  heartbeatInterval;

            // Líder eleito por este nó (relação exclusiva 1:1)
            Ipv6Address                                             myLeader;

            // UDP Flood (módulo isolado)
            FloodAttack*                                            floodAttack;
            bool                                                    isCompromised;
            double                                                  attackStartTime;

            // Modelo de saturação: pacotes de flood acumulados recebidos enquanto
            // este nó é líder. NS-3 não modela exaustão de recurso por default —
            // este contador + threshold simulam o efeito de "líder sobrecarregado
            // por DDoS cai". Reset implícito ao perder/recuperar liderança.
            uint64_t                                                totalFloodReceived;

            // Fase 2 — detecção e quarentena
            // Contador de pacotes recebidos por origem desde o último heartbeat.
            // Líder reporta ao AP no heartbeat; resetado a cada envio.
            std::map<Ipv6Address, uint32_t>                         incomingPacketCount;
            // Blocklist: origens cujos pacotes devem ser descartados na recepção.
            // Populada via MessageTypes::QuarantineOrder vindo do AP.
            std::set<Ipv6Address>                                   quarantinedSources;

        public:
            void setup(capabilitiesVector cap);
            void recvCallback(Ptr<Socket> socket);
            void StartApplication();
            void StopApplication();
            static TypeId GetTypeId();
            Ipv6Address GetNodeIpAddress();

            void beacon();
            void disseminateCapabilities();
            void similarityCalculation();
            void doClustering();
            float getSimilarityMode();
            void selectAndRegisterLeader();
            void registerLeader();

            Ipv6Address tiebreakLeader();
            void setAPAddress(Ipv6Address ip);
            void dispatchTaskToCluster(string cap);
            int sendMessageHelper(MessageTypes type, Ipv6Address addr, uint8_t* buffer, int size);
            void sendBroadcastMessageHelper(MessageTypes type, uint8_t* buffer, int size);
            void performTask(string);

            void nullFunction();
            void setAllNodesAddrs(std::vector<Ipv6Address>);
            void setDelay(double);

            int getClusterSize();
            std::vector<Ipv6Address> getClusterMembers();
            void addClusterMember(Ipv6Address member);
            void removeClusterMember(Ipv6Address member);
            bool isNodeAlive() const { return alive; }
            void sendHeartbeat();
            void clearClusterMembers();
            capabilitiesVector getNodeCapabilities() const;
            void becomeLeader(Ipv6Address apAddr);

            Ipv6Address getMyLeader() const { return myLeader; }
            void setMyLeader(Ipv6Address leader) { myLeader = leader; }

            // UDP Flood (insider threat)
            void setAttackParams(double startTime, double rate, uint32_t payloadSize);
            void startFlood();
            bool isNodeCompromised() const { return isCompromised; }
            bool isNodeLeader() const { return isLeader; }

            // Fase 2 — quarentena
            // Marca uma origem como bloqueada localmente (chamado pelo handler do QuarantineOrder).
            void quarantineSource(Ipv6Address src) { quarantinedSources.insert(src); }
            bool isQuarantined(Ipv6Address src) const { return quarantinedSources.count(src) > 0; }

            // ============================================================
            // Modelo de saturação por flood (Fase 2 / detective)
            // ============================================================
            // Threshold (acumulado de FloodPacket recebidos enquanto é líder)
            // a partir do qual o líder cai (alive=false). Configurável globalmente
            // via setFloodSaturationThreshold. Default 500 pacotes corresponde a
            // ~10s de attack sustentado de 1 atacante a 50pkts/s — dá ao framework
            // 1-2 ciclos pra detectar antes do colapso.
            static uint64_t FLOOD_SATURATION_THRESHOLD;
            static void setFloodSaturationThreshold(uint64_t t) { FLOOD_SATURATION_THRESHOLD = t; }
    };
}