#pragma once

#include "ns3/core-module.h"
#include "ns3/application.h"
#include "ns3/socket.h"

#include "capabilities.h"
#include "task.h"
#include "constants.h"
#include "FloodAttack.h"

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
    };
}