#include "NodeAPApplication.h"
#include "NodeApplication.h"
#include "ns3/address.h"
#include "ns3/ipv6.h"
#include "ns3/udp-socket-factory.h"
#include "MyTag.h"
#include "constants.h"

#include <iostream>
#include <algorithm>
#include <random>
#include "ns3/lr-wpan-net-device.h"
#include "ns3/lr-wpan-spectrum-value-helper.h"
#include "ns3/spectrum-value.h"
#include "ns3/mobility-model.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Contaski_V1_AP");

namespace nr2{
    // Limiar de similaridade para REALOCAÇÃO em cluster existente (RL1)
    // Mais flexível que o threshold de formação (0.95), pois órfãos tentam
    // entrar em clusters formados por outros nós — similaridade natural é menor
    const double REALLOCATION_THRESHOLD = 0.85;

    // Limiar de similaridade para RECLUSTERIZAÇÃO entre órfãos (RL2)
    // Mesmo valor da formação original dos clusters (NodeApplication.cc)
    const double CLUSTERING_THRESHOLD = 0.85;

    Ipv6Address NodeAPApplication::GetNodeIpAddress(){
        Ptr <Node> PtrNode = this->GetNode();
        Ptr<Ipv6> ipv6 = PtrNode->GetObject<Ipv6> ();
        Ipv6InterfaceAddress iaddr = ipv6->GetAddress (1,0);
        Ipv6Address ipAddr = iaddr.GetAddress();

        return ipAddr;
    }

    void NodeAPApplication::setup(){
        this->m_node = GetNodeIpAddress();
        this->m_tid = ns3::UdpSocketFactory::GetTypeId();
        this->m_socket = this->GetNode()->GetObject<Socket>();
        this->clusterLeaders = new std::vector<Ipv6Address>;
        this->aptLeaders = new std::vector<Ipv6Address>;
        this->dispatchedTasks = new taskVector();

        this->confirmationsSinceLastDispatch = 0;

        this->totalNetworkNodes = 0;
        this->decisionInterval = 60.0;  // Ciclo de decisão a cada 60 segundos
        this->allNodesRegistered = false;

        // Inicializar módulos do aprendizado intuitivo
        this->intuitiveEngine = new IntuitiveLearningEngine();
        this->anomalyDetector = new AnomalyDetector(2.0, 20);  // Z-threshold=2.0, janela=20

        for(auto task:*this->tasks){
            task->print();
        }
    }

    void NodeAPApplication::StartApplication(){
        // Override combinado por densidade da rede para N>=300. Ver IntuitiveLearning.h
        // (XI_ANOMALOUS_300, THRESHOLD_S1_300) para a justificativa detalhada:
        //   (i)  ξ_anomalous=-0.033 reduz o drag absoluto sobre mean(Li) (paper-citado)
        //   (ii) THRESHOLD_S1=0.245 recalibra o gatilho S1/S2 (hyperparâmetro interno)
        if(this->totalNetworkNodes >= 300){
            this->intuitiveEngine->getDistributedLearning().setXiAnomalous(XI_ANOMALOUS_300);
            this->intuitiveEngine->getDualSystemMut().setThresholdS1(THRESHOLD_S1_300);
            NS_LOG_INFO("DENSITY_OVERRIDE: N=" << this->totalNetworkNodes
                        << " → ξ_anomalous=" << XI_ANOMALOUS_300
                        << ", THRESHOLD_S1=" << THRESHOLD_S1_300);
        }

        // If socket is not created yet
        if(!this->m_socket){
            // Create socket
            auto netdev = this->GetNode()->GetDevice(2);
            
            this->m_socket = Socket::CreateSocket(GetNode(), m_tid);
            this->m_socket->BindToNetDevice(netdev);
            
            this->m_socket->SetAllowBroadcast(true);
            this->m_socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny (), 2020));
            this->m_socket->Listen();
            this->m_socket->SetRecvCallback(MakeCallback (&NodeAPApplication::recvCallback, this));
        }

        m_socket->SetRecvCallback(MakeCallback (&NodeAPApplication::recvCallback, this));
        Simulator::Schedule(Seconds(150), &NodeAPApplication::sendTaskToLeaders, this);

        // Carregar conhecimento persistente de rodadas anteriores (se disponível)
        if(!this->knowledgePath.empty()){
            this->intuitiveEngine->loadKnowledge(this->knowledgePath);
        }

        // ============================================================
        // Agendar primeiro ciclo de decisão do aprendizado intuitivo
        // Líderes registram em t=105s; ciclo começa em t=115s (antes do primeiro dispatch em t=150s)
        Simulator::Schedule(Seconds(160.0), &NodeAPApplication::intuitiveDecisionCycle, this);
    }

    void NodeAPApplication::StopApplication(){
        this->m_socket->Close();

        stringstream out;
        for(auto task: *this->dispatchedTasks){
            out << task->serialize() << "\n";
        }

        out << "\n\n";

        for(auto task: *this->tasks){
            out << task->serialize() << "\n";
        }

        ofstream outFile("APStats.txt");
        outFile << out.str();
        outFile.close();

        // Escrever log do aprendizado intuitivo
        writeIntuitiveLog();

        // Salvar conhecimento persistente para próxima rodada
        if(!this->knowledgePath.empty()){
            this->intuitiveEngine->saveKnowledge(this->knowledgePath);
        }
    }

    TypeId NodeAPApplication::GetTypeId(){
        static TypeId tid = TypeId ("ns3::NodeAPApplication")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<NodeAPApplication>()
            .AddAttribute ("Protocol", "The type of protocol to use. This should be "
                   "a subclass of ns3::SocketFactory",
                   TypeIdValue (UdpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&NodeAPApplication::m_tid),
                   // This should check for SocketFactory as a parent
                   MakeTypeIdChecker ())
            ;

        return tid;
    }

    void NodeAPApplication::generateTasks(int totalDuration){
        if(this->tasks == nullptr){
            this->tasks = new taskVector();
        }else{
            this->tasks->clear();
        }

        for(int i = 0; i < 10; i++){
            this->tasks->push_back(new Task());
        }
    }

    void NodeAPApplication::sendTaskToLeaders(){
        // Select one task
        this->currentDispatchedTask = this->tasks->front();

        if(!this->currentDispatchedTask)
            return;

        this->tasks->pop_front();
        std::string serializedTask = this->currentDispatchedTask->serialize();

        // Guardar o quorum necessário (número de agrupamentos)
        this->requiredQuorum = this->currentDispatchedTask->getQuorum();

        // Dispatch
        uint16_t port = 2020;
        /*
        Inet6SocketAddress remote = Inet6SocketAddress(Ipv6Address("FF02::1"), port);
        status = this->m_socket->Connect(remote);
        if(status == -1){
            NS_LOG_INFO("Could not bind socket");
        }*/


        Ptr<Packet> pack = Create<Packet>(reinterpret_cast<const uint8_t*> (serializedTask.c_str()), serializedTask.size());
        MyTag tag;
        tag.SetSimpleValue(MessageTypes::TaskDispatch);
        pack->AddPacketTag(tag);

        for(size_t i = 0; i < clusterLeaders->size(); i++) {
            Inet6SocketAddress remote = Inet6SocketAddress(clusterLeaders->at(i), port);
            int status = this->m_socket->SendTo(pack, 0, remote);
            
            if(status == -1){
                NS_LOG_FUNCTION("Could not dispatch task to " << Address(remote.GetIpv6()) << " at port "+remote.GetPort());
            }
            NS_LOG_INFO("AP: MS (" << this->GetNodeIpAddress() << ", " << remote.GetIpv6() << ", " << status << ")");
            // Contabilizar dispatch para taxa de aceitação
            taskDispatchCount[clusterLeaders->at(i)]++;
        }

        this->confirmationsSinceLastDispatch = 0;

        NS_LOG_INFO("AP: TD " << this->currentDispatchedTask->getTid() << " " << Simulator::Now().GetSeconds());
        Simulator::Schedule(Seconds(10), &NodeAPApplication::taskConfirmation, this);
    }

    void NodeAPApplication::recvCallback(Ptr<Socket> socket){
        Ptr<Packet> packet;
        Address from;
        Ipv6Address fromIP;
        MyTag tag;
        
        while((packet = socket->RecvFrom(from))){
            fromIP = Inet6SocketAddress::ConvertFrom(from).GetIpv6();
            packet->PeekPacketTag(tag);

            switch (tag.GetSimpleValue()){
                case MessageTypes::LeaderRegister:
                {
                    NS_LOG_INFO("LR: " << fromIP << " at " << Simulator::Now().GetSeconds());
                    this->clusterLeaders->push_back(fromIP);

                    // Registrar líder no motor intuitivo
                    // Li inicial = energia aleatória em [0.5, 1.0] como no Python:
                    //   self.L = {v: G.nodes[v].get("energy", 0.5)} com energy ~ U(0.5, 1.0)
                    {
                        Ptr<UniformRandomVariable> liRng = CreateObject<UniformRandomVariable>();
                        liRng->SetAttribute("Min", DoubleValue(0.5));
                        liRng->SetAttribute("Max", DoubleValue(1.0));
                        double initialLi = liRng->GetValue();
                        this->intuitiveEngine->registerNode(fromIP, initialLi, true);
                    }

                    // Inicializar informação do cluster
                    ClusterInfo info;
                    info.leaderAddr = fromIP;
                    info.leaderAlive = true;
                    info.memberCount = 0;
                    info.initialMemberCount = 0;
                    info.lastHeartbeat = Simulator::Now().GetSeconds();
                    info.hasAcceptedTask = false;
                    clusterInfoMap[fromIP] = info;
                    break;
                }
                
                case MessageTypes::TaskAccept:
                    NS_LOG_INFO("AP: TA " << this->currentDispatchedTask->getTid() << ", " << fromIP << " " << Simulator::Now().GetSeconds());
                    this->confirmationsSinceLastDispatch++;
                    // Registrar líder como apto
                    if(std::find(this->aptLeaders->begin(), this->aptLeaders->end(), fromIP) == this->aptLeaders->end()){
                        this->aptLeaders->push_back(fromIP);
                            // Atualizar informação do cluster
                        auto it = clusterInfoMap.find(fromIP);
                        if(it != clusterInfoMap.end()){
                            it->second.lastHeartbeat = Simulator::Now().GetSeconds();
                            it->second.hasAcceptedTask = true;
                        }

                        // Contabilizar aceitação
                        taskAcceptCount[fromIP]++;
                    }
                    break;
                case MessageTypes::HeartbeatReport:
                {
                    // Heartbeat confirma que o líder está vivo
                    // memberCount é calculado via myLeader no intuitiveDecisionCycle
                    auto it = clusterInfoMap.find(fromIP);
                    if(it != clusterInfoMap.end()){
                        it->second.lastHeartbeat = Simulator::Now().GetSeconds();
                    }

                    // Fase 2 — parsing do formato estendido com defesa em camadas:
                    //   "members,initialMembers|src1=cnt1;src2=cnt2;..."
                    // Tolerante a payload mal-formado: null bytes, tokens vazios,
                    // IPs inválidos, números não-parseáveis, pipe ausente. Em
                    // qualquer falha por payload, o entry vira map vazio (não
                    // crash). Log uma vez por líder pra alertar sem flood.
                    uint32_t psize = packet->GetSize();
                    if (psize == 0) break;  // payload vazio: ignora
                    std::vector<uint8_t> buf(psize);
                    packet->CopyData(buf.data(), psize);
                    std::string payload((char*)buf.data(), psize);
                    // Sanitiza terminador nulo final se presente
                    while (!payload.empty() && payload.back() == '\0') payload.pop_back();

                    size_t pipePos = payload.find('|');
                    std::map<Ipv6Address, uint32_t> srcMap;

                    if (pipePos == std::string::npos) {
                        // Heartbeat legado (sem contadores) — aceita, srcMap vazio
                        NS_LOG_DEBUG("HEARTBEAT_PARSE: " << fromIP
                                     << " sem '|' (formato legado, sem contadores)");
                    } else if (pipePos + 1 < payload.size()) {
                        std::string countsStr = payload.substr(pipePos + 1);
                        std::stringstream ss(countsStr);
                        std::string token;
                        int parsedOk = 0, parsedBad = 0;
                        while (std::getline(ss, token, ';')) {
                            // Filtrar caracteres residuais
                            while (!token.empty() && (token.back() == '\0' || token.back() == '\r' ||
                                                       token.back() == ' '  || token.back() == '\n'))
                                token.pop_back();
                            if (token.empty()) continue;
                            size_t eq = token.find('=');
                            if (eq == std::string::npos || eq == 0 || eq == token.size()-1) {
                                parsedBad++;
                                continue;  // separador mal-posicionado
                            }
                            std::string ipStr = token.substr(0, eq);
                            std::string cntStr = token.substr(eq + 1);
                            // Validar IPv6 minimamente: precisa ter ':'
                            if (ipStr.find(':') == std::string::npos) {
                                parsedBad++;
                                continue;
                            }
                            // Validar contador: deve ser todo numérico
                            bool allDigits = !cntStr.empty();
                            for (char c : cntStr) {
                                if (c < '0' || c > '9') { allDigits = false; break; }
                            }
                            if (!allDigits) {
                                parsedBad++;
                                continue;
                            }
                            try {
                                Ipv6Address src(ipStr.c_str());
                                uint32_t cnt = (uint32_t)std::stoul(cntStr);
                                srcMap[src] = cnt;
                                parsedOk++;
                            } catch (const std::exception&) {
                                parsedBad++;
                            }
                        }
                        if (parsedBad > 0) {
                            NS_LOG_INFO("HEARTBEAT_PARSE: " << fromIP
                                        << " ok=" << parsedOk << " bad=" << parsedBad
                                        << " (payload parcialmente corrompido — manter pares válidos)");
                        }
                    }
                    leaderSourceCounts[fromIP] = srcMap;
                    break;
                }

                default:
                    break;
            }
        }
    }

    void NodeAPApplication::taskConfirmation(){
        // If no confimation: Re-enqeue the task
        if(this->confirmationsSinceLastDispatch < this->requiredQuorum){
            // Não atingiu o quorum mínimo de agrupamentos - re-enfileirar
            NS_LOG_INFO("AP: Task " << this->currentDispatchedTask->getTid() 
                        << " failed quorum check: " << this->confirmationsSinceLastDispatch 
                        << "/" << this->requiredQuorum << " clusters accepted");
            this->tasks->push_back(this->currentDispatchedTask);
            Simulator::Schedule(Seconds(1), &NodeAPApplication::sendTaskToLeaders, this);
        }
        else{
            // Quorum atingido - tarefa aceita por agrupamentos suficientes
            NS_LOG_INFO("AP: Task " << this->currentDispatchedTask->getTid() 
                        << " quorum satisfied: " << this->confirmationsSinceLastDispatch 
                        << "/" << this->requiredQuorum << " clusters accepted");
            // Wait for task to be completed
            auto current = this->currentDispatchedTask;
            this->dispatchedTasks->push_back(current);

            // Dispatch another task
            Simulator::Schedule(Seconds(this->currentDispatchedTask->getDuration()), &NodeAPApplication::sendTaskToLeaders, this);
        }
    }

    void NodeAPApplication::setTasks(taskVector* tasks){
        this->tasks = tasks;
    }

    void NodeAPApplication::setNodes(NodeContainer nodes){
        this->networkNodes = nodes;
    }

    // ============================================================
    // Helper: encontrar Ptr<Node> pelo endereço IPv6
    // ============================================================
    static Ptr<Node> findNodeByAddress(NodeContainer& nodes, Ipv6Address addr){
        for(uint32_t j = 0; j < nodes.GetN(); j++){
            Ptr<Node> node = nodes.Get(j);
            Ptr<Ipv6> ipv6 = node->GetObject<Ipv6>();
            if(ipv6->GetAddress(1, 0).GetAddress() == addr){
                return node;
            }
        }
        return nullptr;
    }

    // ============================================================
    // Aprendizado Intuitivo — Ciclo de Decisão
    // ============================================================

    void NodeAPApplication::intuitiveDecisionCycle(){
        double now = Simulator::Now().GetSeconds();

        // Guard: não rodar ciclo após SIMTIME — nós já pararam
        if(now >= 895.0) {
            return;
        }

        // Contador de líderes que caíram (saturação por flood) entre o último
        // ciclo e este. Populado pelo polling abaixo, atribuído ao snap depois.
        uint32_t downThisCycle = 0;

        // [0] Primeiro ciclo: registrar TODOS os nós no aprendizado distribuído
        // No Python: self.L = {v: G.nodes[v].get("energy", 0.5) for v in G.nodes}
        // Inclui sensores, líderes e AP — não apenas líderes
        if(!allNodesRegistered){
            Ptr<UniformRandomVariable> liRng = CreateObject<UniformRandomVariable>();
            liRng->SetAttribute("Min", DoubleValue(0.4));
            liRng->SetAttribute("Max", DoubleValue(1.0));
            
            for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
                Ptr<Node> node = this->networkNodes.Get(j);
                Ptr<Ipv6> ipv6 = node->GetObject<Ipv6>();
                Ipv6Address nodeAddr = ipv6->GetAddress(1, 0).GetAddress();
                
                // Verificar se já foi registrado como líder
                auto& allNodes = intuitiveEngine->getDistributedLearning().getAllNodes();
                if(allNodes.find(nodeAddr) == allNodes.end()){
                    // Sensor: energia em [0.4, 1.0] como no Python
                    double energy = liRng->GetValue();
                    Ptr<Application> app = node->GetApplication(0);
                    bool isLeader = false;
                    if(app){
                        Ptr<NodeApplication> nodeApp = DynamicCast<NodeApplication>(app);
                        if(nodeApp){
                            isLeader = (clusterInfoMap.find(nodeAddr) != clusterInfoMap.end());
                        }
                    }
                    intuitiveEngine->registerNode(nodeAddr, energy, isLeader);
                }
            }
            allNodesRegistered = true;
            NS_LOG_INFO("INTUITIVE: Registrados " << this->networkNodes.GetN() 
                        << " nós no aprendizado distribuído");
        }

        // [1] Buscar informação atual dos clusters via myLeader (pertencimento real)
        for(auto& entry : clusterInfoMap){
            Ipv6Address leaderAddr = entry.first;

            // Contar membros reais: nós vivos cujo myLeader é este líder (excluindo o próprio)
            int realMembers = 0;
            for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
                Ptr<Node> node = this->networkNodes.Get(j);
                Ptr<NodeApplication> nodeApp = DynamicCast<NodeApplication>(
                    node->GetApplication(0));
                if(!nodeApp || !nodeApp->isNodeAlive()) continue;
                if(nodeApp->getMyLeader() == leaderAddr && 
                   nodeApp->GetNodeIpAddress() != leaderAddr){
                    realMembers++;
                }
            }
            entry.second.memberCount = realMembers;
            if(entry.second.initialMemberCount == 0 && realMembers > 0){
                entry.second.initialMemberCount = realMembers;
            }

            // Verificar se líder está vivo — detectar transição alive→dead
            // (= líder caiu desde o ciclo anterior; provável saturação por flood)
            Ptr<Node> leaderNode = findNodeByAddress(this->networkNodes, leaderAddr);
            if(leaderNode){
                Ptr<NodeApplication> leaderApp = DynamicCast<NodeApplication>(
                    leaderNode->GetApplication(0));
                if(leaderApp){
                    bool wasAlive = entry.second.leaderAlive;
                    bool nowAlive = leaderApp->isNodeAlive();
                    if(wasAlive && !nowAlive){
                        downThisCycle++;
                        NS_LOG_INFO("LEADER_DETECTED_DOWN: " << leaderAddr
                                    << " at t=" << now
                                    << " (provável saturação por flood)");
                    }
                    entry.second.leaderAlive = nowAlive;
                }
            }
        }

        // Contar líderes vivos no ciclo atual (depois de atualizar leaderAlive)
        uint32_t aliveCount = 0;
        for(const auto& entry : clusterInfoMap){
            if(entry.second.leaderAlive) aliveCount++;
        }

        // [2] Atualizar features do detector de anomalias para cada líder
        for(const auto& entry : clusterInfoMap){
            if(!entry.second.leaderAlive) continue;

            NodeFeatures features;
            
            uint32_t dispatched = taskDispatchCount[entry.first];
            uint32_t accepted = taskAcceptCount[entry.first];
            features.taskAcceptRate = (dispatched > 0) ? 
                (double)accepted / dispatched : 1.0;

            features.timeSinceContact = now - entry.second.lastHeartbeat;

            features.clusterHealthRatio = (entry.second.initialMemberCount > 0) ?
                (double)entry.second.memberCount / entry.second.initialMemberCount : 1.0;

            anomalyDetector->updateFeatures(entry.first, features);
        }

        // [3] Executar detecção de anomalias (Módulo 3)
        anomalousNodes = anomalyDetector->detect();

        for(const auto& addr : anomalousNodes){
            auto scores = anomalyDetector->getScores();
            double score = scores.count(addr) > 0 ? scores[addr] : 0.0;
            intuitiveEngine->getKnowledge().addEmergent(addr, now, score);
        }

        // [3.5] Atualizar aprendizado distribuído com mapa de vizinhança real
        {
            std::map<Ipv6Address, std::vector<Ipv6Address>> realClusterMembers;
            for (const auto& entry : clusterInfoMap) {
                if (!entry.second.leaderAlive) continue;
                std::vector<Ipv6Address> members;
                for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
                    Ptr<Node> node = this->networkNodes.Get(j);
                    Ptr<NodeApplication> nodeApp = DynamicCast<NodeApplication>(
                        node->GetApplication(0));
                    if(!nodeApp || !nodeApp->isNodeAlive()) continue;
                    if(nodeApp->getMyLeader() == entry.first &&
                       nodeApp->GetNodeIpAddress() != entry.first){
                        members.push_back(nodeApp->GetNodeIpAddress());
                    }
                }
                realClusterMembers[entry.first] = members;
            }
            intuitiveEngine->getDistributedLearning().step(realClusterMembers, anomalousNodes);
        }

        // [4] Construir vetor de ClusterInfo e executar ciclo de decisão (métricas globais)
        auto clusters = buildClusterInfoVector();
        IntuitiveSnapshot snap = intuitiveEngine->decisionCycle(
            now, clusters, anomalousNodes, totalNetworkNodes);

        // Telemetria de saturação: líderes vivos agora + quantos caíram este ciclo
        snap.leadersAlive = aliveCount;
        snap.leadersDownThisCycle = downThisCycle;

        // [4.5] Fase 2 — defesa contra UDP flooder (membro→líder)
        // Roda antes do processamento de órfãos pra que a próxima rodada já veja o
        // efeito da quarentena (e o líder talvez deixe de ser anômalo).
        processAttackersIntuitively(snap);

        // [5] Processar órfãos com decisão individual por órfão
        processOrphansIntuitively(snap);

        // [6] Recalcular métricas após ação via myLeader
        for(auto& entry : clusterInfoMap){
            int realMembers = 0;
            for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
                Ptr<Node> node = this->networkNodes.Get(j);
                Ptr<NodeApplication> nodeApp = DynamicCast<NodeApplication>(
                    node->GetApplication(0));
                if(!nodeApp || !nodeApp->isNodeAlive()) continue;
                if(nodeApp->getMyLeader() == entry.first &&
                   nodeApp->GetNodeIpAddress() != entry.first){
                    realMembers++;
                }
            }
            entry.second.memberCount = realMembers;
            // Após recovery (REALLOCATE/RECLUSTER), atualizar baseline:
            // initialMemberCount representa o melhor estado já observado.
            // Isso permite que reliability volte a 1.0 após recuperação bem-sucedida.
            if(realMembers > (int)entry.second.initialMemberCount){
                entry.second.initialMemberCount = realMembers;
            }

            Ptr<Node> leaderNode = findNodeByAddress(this->networkNodes, entry.first);
            if(leaderNode){
                Ptr<NodeApplication> leaderApp = DynamicCast<NodeApplication>(
                    leaderNode->GetApplication(0));
                if(leaderApp){
                    entry.second.leaderAlive = leaderApp->isNodeAlive();
                }
            }
        }

        auto clustersAfter = buildClusterInfoVector();
        double qiAfter = 0.0, srAfter = 0.0;
        {
            int activeClusters = 0;
            uint32_t coveredNodes = 0;
            double deliverySum = 0.0;
            int deliveryCount = 0;
            for(const auto& c : clustersAfter){
                if(c.leaderAlive){
                    activeClusters++;
                    coveredNodes += c.memberCount + 1;
                    if(c.initialMemberCount > 0){
                        double healthRatio = std::min(1.0, (double)c.memberCount / c.initialMemberCount);
                        double elapsed = (c.lastHeartbeat > 0) ?
                            (now - c.lastHeartbeat) : 120.0;
                        double linkQuality = std::max(0.1, 1.0 - std::min(1.0, elapsed / 120.0));
                        deliverySum += healthRatio * linkQuality;
                        deliveryCount++;
                    }
                }
            }
            double connectivity = clustersAfter.empty() ? 0.0 : 
                (double)activeClusters / clustersAfter.size();
            double propagation = totalNetworkNodes > 0 ? 
                std::min(1.0, (double)coveredNodes / totalNetworkNodes) : 0.0;
            double delivery = deliveryCount > 0 ? deliverySum / deliveryCount : 0.0;
            qiAfter = std::min(1.0, 0.5 * connectivity + 0.3 * propagation + 0.2 * delivery);
            srAfter = totalNetworkNodes > 0 ? 
                std::min(1.0, (double)coveredNodes / totalNetworkNodes) : 0.0;
        }

        intuitiveEngine->postActionUpdate(qiAfter, srAfter, snap.totalOrphans > 0);

        // [7] Agendar próximo ciclo
        Simulator::Schedule(Seconds(this->decisionInterval), 
                           &NodeAPApplication::intuitiveDecisionCycle, this);
    }

    // ============================================================
    // Processamento de órfãos com decisão individual por órfão
    // Integra RL3-style per-orphan iteration com o framework S1/S2
    // ============================================================
    void NodeAPApplication::processOrphansIntuitively(IntuitiveSnapshot& snap){
        double now = Simulator::Now().GetSeconds();

        // Constantes de recompensa proporcional (RL3.1-style)
        const double REWARD_BASE    = 10.0;   // Base, modulada por similaridade real
        const double REWARD_INVALID = -10.0;
        const double REWARD_ORPHAN  = -5.0;

        // [1] Coletar órfãos reais: nós cujo myLeader está morto
        struct OrphanInfo {
            Ipv6Address addr;
            Ptr<NodeApplication> app;
            capabilitiesVector caps;
        };
        std::vector<OrphanInfo> allOrphans;
        std::set<Ipv6Address> collectedAddrs;

        // Construir set de líderes mortos para lookup rápido
        std::set<Ipv6Address> deadLeaders;
        for(const auto& entry : clusterInfoMap){
            if(!entry.second.leaderAlive){
                deadLeaders.insert(entry.first);
            }
        }

        // Fonte 1: iterar todos os nós — órfão é quem tem myLeader morto
        for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
            Ptr<Node> node = this->networkNodes.Get(j);
            Ptr<Ipv6> ipv6 = node->GetObject<Ipv6>();
            Ipv6Address nodeAddr = ipv6->GetAddress(1, 0).GetAddress();

            Ptr<NodeApplication> nodeApp = DynamicCast<NodeApplication>(
                node->GetApplication(0));
            if(!nodeApp || !nodeApp->isNodeAlive()) continue;

            // Excluir atacantes detectados: nó em globallyQuarantined é resíduo
            // de ameaça, não candidato a recuperação. Sem este filtro, um atacante
            // cujo líder original caiu seria realocado/reclusterizado como membro
            // saudável e, no pior caso (RECLUSTER + caps raras), poderia virar
            // líder do novo cluster. A flag de quarentena permanece global até o
            // TTL (QUARANTINE_TTL) expirar.
            if(globallyQuarantined.count(nodeAddr) > 0) continue;

            Ipv6Address leader = nodeApp->getMyLeader();
            // Nó é órfão se seu líder está no set de mortos
            // (e não é o próprio líder morto, que já foi desligado)
            if(deadLeaders.count(leader) > 0){
                if(collectedAddrs.count(nodeAddr) > 0) continue;
                OrphanInfo oi;
                oi.addr = nodeAddr;
                oi.app = nodeApp;
                oi.caps = nodeApp->getNodeCapabilities();
                allOrphans.push_back(oi);
                collectedAddrs.insert(nodeAddr);
            }
        }

        // Fonte 2: pendingOrphans (de ciclos anteriores)
        for(const auto& orphanAddr : pendingOrphans){
            if(collectedAddrs.count(orphanAddr) > 0) continue;
            // Mesmo filtro de atacante detectado da Fonte 1
            if(globallyQuarantined.count(orphanAddr) > 0) continue;
            Ptr<Node> orphanNode = findNodeByAddress(this->networkNodes, orphanAddr);
            if(!orphanNode) continue;
            Ptr<NodeApplication> orphanApp = DynamicCast<NodeApplication>(
                orphanNode->GetApplication(0));
            if(!orphanApp || !orphanApp->isNodeAlive()) continue;

            OrphanInfo oi;
            oi.addr = orphanAddr;
            oi.app = orphanApp;
            oi.caps = orphanApp->getNodeCapabilities();
            allOrphans.push_back(oi);
            collectedAddrs.insert(orphanAddr);
        }

        snap.totalOrphans = allOrphans.size();

        if(allOrphans.empty()){
            NS_LOG_INFO("INTUITIVE_ORPHANS: Nenhum órfão para processar");
            // Registrar snapshot mesmo sem órfãos
            intuitiveEngine->getHistoryMut().push_back(snap);
            return;
        }

        // [2] Coletar clusters ativos e suas capacidades
        struct ActiveCluster {
            Ipv6Address leaderAddr;
            Ptr<NodeApplication> leaderApp;
            capabilitiesVector caps;
        };
        std::vector<ActiveCluster> activeClusters;
        for(const auto& entry : clusterInfoMap){
            if(!entry.second.leaderAlive) continue;
            Ptr<Node> leaderNode = findNodeByAddress(this->networkNodes, entry.first);
            if(!leaderNode) continue;
            Ptr<NodeApplication> leaderApp = DynamicCast<NodeApplication>(
                leaderNode->GetApplication(0));
            if(!leaderApp || !leaderApp->isNodeAlive()) continue;

            ActiveCluster ac;
            ac.leaderAddr = entry.first;
            ac.leaderApp = leaderApp;
            ac.caps = leaderApp->getNodeCapabilities();
            activeClusters.push_back(ac);
        }

        // [3] Calcular similaridade média entre todos os órfãos (para contexto RECLUSTER)
        // Pré-computar para eficiência
        std::map<Ipv6Address, double> bestSimWithOrphans;
        for(size_t i = 0; i < allOrphans.size(); i++){
            double maxSim = 0.0;
            for(size_t j = 0; j < allOrphans.size(); j++){
                if(i == j) continue;
                capabilitiesVector capI = allOrphans[i].caps;
                capabilitiesVector capJ = allOrphans[j].caps;
                double sim = capabilitiesSimilarity(&capI, &capJ);
                if(sim > maxSim) maxSim = sim;
            }
            bestSimWithOrphans[allOrphans[i].addr] = maxSim;
        }

        // [4] Iterar sobre cada órfão: avaliar estado, S1/S2, escolher ação
        std::vector<Ipv6Address> newClusterCandidates;  // Órfãos marcados para RECLUSTER
        std::vector<Ipv6Address> stillOrphaned;          // Órfãos não resolvidos

        double qi = intuitiveEngine->getLastQI();
        double sr = intuitiveEngine->getLastSR();
        double pThreat = intuitiveEngine->getLastPThreat();

        auto& dualSys = intuitiveEngine->getDualSystemMut();
        auto& knowledge = intuitiveEngine->getKnowledge();
        auto& distLearn = intuitiveEngine->getDistributedLearning();

        uint32_t s1CountBefore = dualSys.getS1Count();
        uint32_t s2CountBefore = dualSys.getS2Count();

        for(auto& orphan : allOrphans){
            // [4a] Calcular similaridade com melhor cluster existente
            double bestSimExisting = 0.0;
            int bestClusterIdx = -1;
            for(size_t i = 0; i < activeClusters.size(); i++){
                capabilitiesVector orphanCaps = orphan.caps;
                capabilitiesVector leaderCaps = activeClusters[i].caps;
                double sim = capabilitiesSimilarity(&orphanCaps, &leaderCaps);
                if(sim > bestSimExisting){
                    bestSimExisting = sim;
                    bestClusterIdx = i;
                }
            }

            // [4b] Similaridade com outros órfãos (pré-computado)
            double simOrphans = bestSimWithOrphans[orphan.addr];

            // [4c] Determinar estado do órfão
            OrphanState orphanState = DualSystemResponse::determineOrphanState(
                bestSimExisting, simOrphans, REALLOCATION_THRESHOLD, CLUSTERING_THRESHOLD);

            // [4d] S1/S2 escolhe ação para este órfão
            auto result = dualSys.chooseActionForOrphan(
                knowledge, distLearn, qi, sr, pThreat, orphanState);
            IntuitiveAction action = result.first;
            SystemUsed system = result.second;

            // [4e] Validar viabilidade e aplicar fallback (como RL3)
            bool existingViable = (bestSimExisting >= REALLOCATION_THRESHOLD && bestClusterIdx >= 0);
            bool orphansViable  = (simOrphans >= CLUSTERING_THRESHOLD);

            if(action == REALLOCATE_TO_EXISTING && !existingViable){
                action = orphansViable ? RECLUSTER_ORPHANS : DO_NOTHING;
                NS_LOG_INFO("INTUITIVE_FALLBACK: REALLOCATE inviável para " << orphan.addr
                            << ", fallback para " << IntuitiveActionNames[action]);
            } else if(action == RECLUSTER_ORPHANS && !orphansViable){
                action = existingViable ? REALLOCATE_TO_EXISTING : DO_NOTHING;
                NS_LOG_INFO("INTUITIVE_FALLBACK: RECLUSTER inviável para " << orphan.addr
                            << ", fallback para " << IntuitiveActionNames[action]);
            }

            // [4f] Executar ação e calcular recompensa PROPORCIONAL (RL3.1-style)
            // Reward = REWARD_BASE × similaridade × qualityFactor + bônus contextual
            // Isso dá gradiente: sim=0.98 vale mais que sim=0.87 para a mesma ação
            double reward = 0.0;
            bool resolved = false;

            if(action == REALLOCATE_TO_EXISTING){
                if(existingViable){
                    activeClusters[bestClusterIdx].leaderApp->addClusterMember(orphan.addr);
                    orphan.app->setMyLeader(activeClusters[bestClusterIdx].leaderAddr);
                    auto it = clusterInfoMap.find(activeClusters[bestClusterIdx].leaderAddr);
                    if(it != clusterInfoMap.end()){
                        it->second.memberCount++;
                    }

                    // Recompensa proporcional à qualidade do match individual
                    // Sem bônus artificial — a similaridade per-orphan é o sinal correto
                    reward = REWARD_BASE * bestSimExisting;

                    resolved = true;
                    snap.actionsReallocate++;
                    NS_LOG_INFO("INTUITIVE_ORPHAN: " << orphan.addr << " [" << OrphanStateNames[orphanState]
                                << "] → REALLOCATE para " << activeClusters[bestClusterIdx].leaderAddr
                                << " (sim=" << bestSimExisting << " r=" << reward << ") [" << SystemUsedNames[system] << "]");
                } else {
                    reward = REWARD_INVALID;
                }
            } else if(action == RECLUSTER_ORPHANS){
                if(orphansViable){
                    newClusterCandidates.push_back(orphan.addr);

                    // Recompensa proporcional à similaridade com outros órfãos
                    // Sem bônus artificial — a similaridade per-orphan é o sinal correto
                    reward = REWARD_BASE * simOrphans;

                    resolved = true;
                    snap.actionsRecluster++;
                    NS_LOG_INFO("INTUITIVE_ORPHAN: " << orphan.addr << " [" << OrphanStateNames[orphanState]
                                << "] → RECLUSTER (simOrphans=" << simOrphans << " r=" << reward << ") [" << SystemUsedNames[system] << "]");
                } else {
                    reward = REWARD_INVALID;
                }
            } else {
                // DO_NOTHING
                reward = REWARD_ORPHAN;
                snap.actionsDoNothing++;
                NS_LOG_INFO("INTUITIVE_ORPHAN: " << orphan.addr << " [" << OrphanStateNames[orphanState]
                            << "] → DO_NOTHING [" << SystemUsedNames[system] << "]");
            }

            // [4g] Atualizar Q-Table e Rintuitive para este órfão
            dualSys.updateQForOrphan(orphanState, action, reward);
            std::string bucket = OrphanStateNames[orphanState];
            knowledge.updateIntuitive(bucket, action, reward);

            if(!resolved){
                stillOrphaned.push_back(orphan.addr);
            }
        }

        // [5] Processar candidatos a reclusterização (fase coletiva)
        if(!newClusterCandidates.empty()){
            NS_LOG_INFO("INTUITIVE_RECLUSTER: " << newClusterCandidates.size()
                        << " órfãos marcados para reclusterização");

            // Coletar info dos candidatos
            struct ReclusterOrphan {
                Ipv6Address addr;
                Ptr<NodeApplication> app;
                capabilitiesVector caps;
            };
            std::vector<ReclusterOrphan> reclusterOrphans;
            for(const auto& addr : newClusterCandidates){
                Ptr<Node> node = findNodeByAddress(this->networkNodes, addr);
                if(!node) continue;
                Ptr<NodeApplication> app = DynamicCast<NodeApplication>(node->GetApplication(0));
                if(!app || !app->isNodeAlive()) continue;

                ReclusterOrphan ro;
                ro.addr = addr;
                ro.app = app;
                ro.caps = app->getNodeCapabilities();
                reclusterOrphans.push_back(ro);
            }

            // Agrupar por similaridade (mesmo algoritmo que o RECLUSTER original)
            std::vector<bool> assigned(reclusterOrphans.size(), false);
            int newClustersFormed = 0;

            for(size_t i = 0; i < reclusterOrphans.size(); i++){
                if(assigned[i]) continue;

                std::vector<size_t> clusterIndices;
                clusterIndices.push_back(i);
                assigned[i] = true;

                for(size_t j = i + 1; j < reclusterOrphans.size(); j++){
                    if(assigned[j]) continue;
                    capabilitiesVector capI = reclusterOrphans[i].caps;
                    capabilitiesVector capJ = reclusterOrphans[j].caps;
                    double sim = capabilitiesSimilarity(&capI, &capJ);
                    if(sim >= CLUSTERING_THRESHOLD){
                        clusterIndices.push_back(j);
                        assigned[j] = true;
                    }
                }

                // Precisa de pelo menos 2 nós para formar cluster
                if(clusterIndices.size() < 2){
                    assigned[i] = false;
                    continue;
                }

                // Eleger líder: órfão com mais capacidades (desempate por IP)
                size_t leaderIdx = clusterIndices[0];
                for(size_t k = 1; k < clusterIndices.size(); k++){
                    size_t candidateIdx = clusterIndices[k];
                    if(reclusterOrphans[candidateIdx].caps.size() > reclusterOrphans[leaderIdx].caps.size()){
                        leaderIdx = candidateIdx;
                    } else if(reclusterOrphans[candidateIdx].caps.size() == reclusterOrphans[leaderIdx].caps.size()){
                        uint8_t bufA[16], bufB[16];
                        reclusterOrphans[candidateIdx].addr.GetBytes(bufA);
                        reclusterOrphans[leaderIdx].addr.GetBytes(bufB);
                        if(memcmp(bufA, bufB, 16) < 0){
                            leaderIdx = candidateIdx;
                        }
                    }
                }

                // Promover líder e registrar novo cluster
                Ipv6Address newLeaderAddr = reclusterOrphans[leaderIdx].addr;
                reclusterOrphans[leaderIdx].app->becomeLeader(this->GetNodeIpAddress());

                for(size_t k = 0; k < clusterIndices.size(); k++){
                    size_t idx = clusterIndices[k];
                    if(idx == leaderIdx) continue;
                    reclusterOrphans[leaderIdx].app->addClusterMember(reclusterOrphans[idx].addr);
                    reclusterOrphans[idx].app->setMyLeader(newLeaderAddr);
                }

                ClusterInfo newInfo;
                newInfo.leaderAddr = newLeaderAddr;
                newInfo.leaderAlive = true;
                newInfo.memberCount = clusterIndices.size() - 1;
                newInfo.initialMemberCount = clusterIndices.size() - 1;
                newInfo.lastHeartbeat = now;
                newInfo.hasAcceptedTask = false;
                clusterInfoMap[newLeaderAddr] = newInfo;

                this->clusterLeaders->push_back(newLeaderAddr);
                intuitiveEngine->registerNode(newLeaderAddr, 0.7, true);

                newClustersFormed++;
                NS_LOG_INFO("INTUITIVE_RECLUSTER: Novo cluster - Líder " << newLeaderAddr
                            << " com " << (clusterIndices.size() - 1) << " seguidores");
            }

            // Órfãos marcados para RECLUSTER mas não agrupados → fallback para pendentes
            for(size_t i = 0; i < reclusterOrphans.size(); i++){
                if(!assigned[i]){
                    stillOrphaned.push_back(reclusterOrphans[i].addr);
                    NS_LOG_INFO("INTUITIVE_RECLUSTER_FALLBACK: " << reclusterOrphans[i].addr
                                << " não agrupado → pendente");
                }
            }

            NS_LOG_INFO("INTUITIVE_RECLUSTER: " << newClustersFormed << " novos clusters formados");
        }

        // [6] Limpar clusters mortos do mapa
        std::vector<Ipv6Address> deadToRemove;
        for(auto& entry : clusterInfoMap){
            if(entry.second.leaderAlive) continue;
            Ptr<Node> deadNode = findNodeByAddress(this->networkNodes, entry.first);
            if(deadNode){
                Ptr<NodeApplication> deadApp = DynamicCast<NodeApplication>(
                    deadNode->GetApplication(0));
                if(deadApp) deadApp->clearClusterMembers();
            }
            deadToRemove.push_back(entry.first);
        }
        for(const auto& addr : deadToRemove){
            clusterInfoMap.erase(addr);
        }

        // [7] Atualizar lista de pendentes
        pendingOrphans.clear();
        for(const auto& addr : stillOrphaned){
            pendingOrphans.push_back(addr);
        }

        // [8] Completar snapshot com contadores S1/S2 deste ciclo
        snap.cycleS1Count = dualSys.getS1Count() - s1CountBefore;
        snap.cycleS2Count = dualSys.getS2Count() - s2CountBefore;

        // Registrar snapshot no histórico
        intuitiveEngine->getHistoryMut().push_back(snap);

        NS_LOG_INFO("INTUITIVE_ORPHANS: Processados " << allOrphans.size() << " órfãos"
                    << " | REALLOCATE=" << snap.actionsReallocate
                    << " RECLUSTER=" << snap.actionsRecluster
                    << " DO_NOTHING=" << snap.actionsDoNothing
                    << " | Pendentes=" << pendingOrphans.size()
                    << " | S1=" << snap.cycleS1Count << " S2=" << snap.cycleS2Count);
    }

    std::vector<ClusterInfo> NodeAPApplication::buildClusterInfoVector() const {
        std::vector<ClusterInfo> result;
        for(const auto& entry : clusterInfoMap){
            result.push_back(entry.second);
        }
        return result;
    }

    void NodeAPApplication::processHeartbeat(Ipv6Address leaderAddr, uint32_t currentMembers){
        auto it = clusterInfoMap.find(leaderAddr);
        if(it != clusterInfoMap.end()){
            it->second.memberCount = currentMembers;
            it->second.lastHeartbeat = Simulator::Now().GetSeconds();
        }
    }

    void NodeAPApplication::updateClusterInfo(Ipv6Address leader, uint32_t memberCount,
                                               uint32_t initialMemberCount){
        auto it = clusterInfoMap.find(leader);
        if(it != clusterInfoMap.end()){
            it->second.memberCount = memberCount;
            if(it->second.initialMemberCount == 0){
                it->second.initialMemberCount = initialMemberCount;
            }
        }
    }

    void NodeAPApplication::writeIntuitiveLog(){
        const auto& history = intuitiveEngine->getHistory();
        if(history.empty()) return;

        ofstream logFile("IntuitiveStats.csv");
        logFile << "timestamp,qi,sr,tii,arf,meanRho,netLearning,pThreat,"
                << "totalOrphans,actionsReallocate,actionsRecluster,actionsDoNothing,"
                << "cycleS1,cycleS2,anomalies,qDoNothing,qReallocate,qRecluster,"
                // Telemetria do ramo atacante
                << "suspectsCount,actionsAttackerQuarantine,actionsAttackerDoNothing,"
                << "qAtkDNHigh,qAtkQuarHigh,qAtkDNLow,qAtkQuarLow,atkEpsilon,"
                << "smartTransferOk,smartTransferNoDonor,smartRedundancyOk,"
                << "leadersAlive,leadersDownThisCycle"
                << std::endl;

        for(const auto& snap : history){
            logFile << snap.timestamp << ","
                    << snap.qi << ","
                    << snap.sr << ","
                    << snap.tii << ","
                    << snap.arf << ","
                    << snap.meanRho << ","
                    << snap.netLearning << ","
                    << snap.pThreat << ","
                    << snap.totalOrphans << ","
                    << snap.actionsReallocate << ","
                    << snap.actionsRecluster << ","
                    << snap.actionsDoNothing << ","
                    << snap.cycleS1Count << ","
                    << snap.cycleS2Count << ","
                    << snap.anomalies << ","
                    << snap.qDoNothing << ","
                    << snap.qReallocate << ","
                    << snap.qRecluster << ","
                    << snap.suspectsCount << ","
                    << snap.actionsAttackerQuarantine << ","
                    << snap.actionsAttackerDoNothing << ","
                    << snap.qAttackerDoNothingHigh << ","
                    << snap.qAttackerQuarantineHigh << ","
                    << snap.qAttackerDoNothingLow << ","
                    << snap.qAttackerQuarantineLow << ","
                    << snap.attackerEpsilon << ","
                    << snap.smartTransferOk << ","
                    << snap.smartTransferNoDonor << ","
                    << snap.smartRedundancyOk << ","
                    << snap.leadersAlive << ","
                    << snap.leadersDownThisCycle
                    << std::endl;
        }
        logFile.close();

        ofstream qFile("IntuitiveQValues.txt");
        qFile << "=== Q-VALORES FINAIS (4x3) ===" << std::endl;
        for(int s = 0; s < ORPHAN_STATE_COUNT; s++){
            qFile << "Estado " << OrphanStateNames[s] << ":" << std::endl;
            for(int a = 0; a < INTUITIVE_ACTION_COUNT; a++){
                qFile << "  " << IntuitiveActionNames[a] << ": " 
                      << intuitiveEngine->getDualSystem().getQValue(
                            static_cast<OrphanState>(s),
                            static_cast<IntuitiveAction>(a))
                      << std::endl;
            }
        }
        qFile << "Epsilon final: " << intuitiveEngine->getDualSystem().getEpsilon() << std::endl;
        qFile << "S1 count total: " << intuitiveEngine->getDualSystem().getS1Count() << std::endl;
        qFile << "S2 count total: " << intuitiveEngine->getDualSystem().getS2Count() << std::endl;

        // ============================================================
        // Q-VALORES FINAIS — Ramo Atacante (Fase 2 / detective)
        // ============================================================
        const auto& aSys = intuitiveEngine->getAttackerSystem();
        qFile << std::endl << "=== Q-VALORES FINAIS DO RAMO ATACANTE (3x2) ===" << std::endl;
        for(int s = 0; s < ATTACKER_STATE_COUNT; s++){
            qFile << "Estado " << AttackerStateNames[s] << ":" << std::endl;
            for(int a = 0; a < ATTACKER_ACTION_COUNT; a++){
                qFile << "  " << AttackerActionNames[a] << ": "
                      << aSys.getQ(static_cast<AttackerState>(s),
                                   static_cast<AttackerAction>(a))
                      << std::endl;
            }
        }
        qFile << "Epsilon atacante final: " << aSys.getEpsilon() << std::endl;
        qFile << "Quarantine count total: " << aSys.getQuarantineCount() << std::endl;
        qFile << "DoNothing count total:  " << aSys.getDoNothingCount() << std::endl;
        qFile.close();

        NS_LOG_INFO("INTUITIVE: Logs escritos em IntuitiveStats.csv e IntuitiveQValues.txt");
    }

    // ============================================================
    // Fase 2 — pipeline de defesa (membro→líder)
    // ============================================================

    void NodeAPApplication::sendQuarantineOrder(Ipv6Address leaderAddr, Ipv6Address target){
        // Payload: representação textual do IPv6 alvo (Ipv6Address::Print()).
        std::stringstream ts;
        target.Print(ts);
        std::string payload = ts.str();

        // sendMessageHelper unicast — usa o mesmo padrão dos demais envios do AP.
        Ptr<Packet> p = Create<Packet>((uint8_t*)payload.c_str(), payload.size() + 1);
        MyTag tag;
        tag.SetSimpleValue(MessageTypes::QuarantineOrder);
        p->AddPacketTag(tag);
        Inet6SocketAddress remote(leaderAddr, 2020);
        m_socket->SendTo(p, 0, remote);

        NS_LOG_INFO("AP_QUARANTINE: order sent to leader " << leaderAddr
                    << " target=" << target);
    }

    // ============================================================
    // NOTA METODOLÓGICA — "líder fantasma" (ghost-leader)
    // ============================================================
    // O protocolo de clusterização herdado de sectional/synapt elege líderes
    // de forma DISTRIBUÍDA E LOCAL: cada nó decide quem é seu myLeader olhando
    // só sua própria vizinhança similar (clusterList passa pelo Z-score >=
    // SIMILARITY_THRESHOLD = 0.95). Não há ack/handshake — o "líder" eleito
    // pode ter elegido alguém diferente de si mesmo na visão dele.
    //
    // Consequência: existem nós cujo myLeader aponta para um IP que NUNCA
    // enviou LeaderRegister ao AP (porque do ponto de vista do "líder" eleito,
    // ele mesmo é membro de outro cluster). Esses são líderes fantasma — o AP
    // não os conhece em clusterInfoMap. Em N grande (rede esparsa em
    // LR-WPAN), ~10-20% dos nós podem cair nesta situação.
    //
    // No detective, isso se manifesta como atacantes cujo target é um IP que
    // o AP não monitora — leaderSourceCounts não recebe nada de lá, e o
    // AnomalyDetector não tem dados pra flagar. O atacante "ataca o vazio".
    //
    // **Tratamento adotado** (alinhado com sectional/synapt, que enfrentam o
    // mesmo fenômeno como "clusters idle"): NÃO filtrar. Reportar via 3
    // métricas separadas no paper (selected / effective / detected), onde a
    // diferença selected → effective expõe a propriedade do clustering, e a
    // diferença effective → detected é a capacidade do framework. Detalhes
    // documentados em memory/detective_v1_state.md.
    // ============================================================
    void NodeAPApplication::processAttackersIntuitively(IntuitiveSnapshot& snap){
        // Sem nenhum líder reportando contadores: nada a fazer.
        if (leaderSourceCounts.empty()) return;

        // 0) TTL cleanup: expirar quarentenas antigas para permitir reavaliação.
        //    Caso de uso: líder original que aplicou a blocklist morreu/foi
        //    substituído; ou o suspeito mudou de cluster e a quarentena antiga
        //    não tem mais sentido. Após QUARANTINE_TTL segundos sem nova
        //    observação, o IP pode ser re-quarentenado se voltar como suspeito.
        double now = Simulator::Now().GetSeconds();
        for (auto it = globallyQuarantined.begin(); it != globallyQuarantined.end(); ) {
            if (now - it->second > QUARANTINE_TTL) it = globallyQuarantined.erase(it);
            else ++it;
        }

        // 1) Detectar suspeitos via Z-score intra-cluster.
        auto suspects = anomalyDetector->detectFlooders(leaderSourceCounts);
        snap.suspectsCount = (uint32_t)suspects.size();

        // 2) Mapear cada suspeito → líder que mais reportou tráfego dele.
        //    Esse "líder do suspeito" é o cluster onde o atacante incomoda mais.
        //    Usado tanto na decisão (smart-quarantine) quanto no reward observacional
        //    (cluster cleanup metric).
        std::map<Ipv6Address, Ipv6Address> suspectToLeader;
        for (const auto& s : suspects) {
            Ipv6Address bestLeader;
            uint32_t maxCount = 0;
            for (const auto& lr : leaderSourceCounts) {
                auto it = lr.second.find(s.first);
                if (it != lr.second.end() && it->second > maxCount) {
                    maxCount = it->second;
                    bestLeader = lr.first;
                }
            }
            suspectToLeader[s.first] = bestLeader;
        }

        // 3) Recompensa observacional (sem ground-truth do simulador).
        //    Sinais usados:
        //      QUARANTINE: o cluster do suspeito quarentenado ficou "limpo"?
        //                  (zero outros suspeitos remanescentes no mesmo líder)
        //                  → +10 (eliminou ameaça e nenhuma outra surgiu)
        //                  → -2  (limpeza parcial — outros suspeitos persistem,
        //                         o atacante real pode ser outro ou são múltiplos)
        //      DO_NOTHING: o suspeito ainda destaca?
        //                  → +1   (calmou sozinho — era ruído, omissão correta)
        //                  → -2   (persistiu em SUSPECT_LOW — omissão duvidosa)
        //                  → -5   (escalou pra SUSPECT_HIGH — omissão custosa)
        //    Limitação reconhecida: QUARANTINE em nó inocente recebe +reward se
        //    cluster já estava calmo (não-observável localmente). Aceita como
        //    bias defensivo (security-first): em IIoT, falso positivo é menos
        //    grave que falso negativo. Threat model documentado no paper.
        auto& attackerSys = intuitiveEngine->getAttackerSystem();
        for (auto& prev : lastAttackerDecisions) {
            const Ipv6Address& suspect = prev.first;
            AttackerState  pState     = prev.second.state;
            AttackerAction pAction    = prev.second.action;
            Ipv6Address    prevLeader = prev.second.leader;

            bool suspectPersists = (suspects.count(suspect) > 0);
            AttackerState nextState = suspectPersists
                ? AttackerDualSystem::stateFromZScore(suspects[suspect])
                : ATK_CLEAR;

            double reward;
            if (pAction == ATK_QUARANTINE) {
                int othersInCluster = 0;
                for (const auto& sl : suspectToLeader) {
                    if (sl.first == suspect) continue;
                    if (sl.second == prevLeader) othersInCluster++;
                }
                reward = (othersInCluster == 0) ? +10.0 : -2.0;
            } else { // ATK_DO_NOTHING
                if (!suspectPersists) {
                    reward = +1.0;
                } else {
                    reward = (nextState == ATK_SUSPECT_HIGH) ? -5.0 : -2.0;
                }
            }

            attackerSys.updateQ(pState, pAction, reward, nextState);

            NS_LOG_INFO("ATK_REWARD: suspect=" << suspect
                        << " state=" << AttackerStateNames[pState]
                        << " action=" << AttackerActionNames[pAction]
                        << " reward=" << reward
                        << " persisted=" << suspectPersists
                        << " nextState=" << AttackerStateNames[nextState]);
        }
        lastAttackerDecisions.clear();

        // 4) Decidir por suspeito atual via DualSystem (atacante).
        for (const auto& s : suspects) {
            const Ipv6Address& suspect = s.first;
            double z = s.second;
            AttackerState state = AttackerDualSystem::stateFromZScore(z);

            // Já está em quarentena? Pular pra evitar comando redundante.
            if (globallyQuarantined.count(suspect) > 0) continue;

            AttackerAction action = attackerSys.selectAction(state);
            Ipv6Address bestLeader = suspectToLeader[suspect];

            if (action == ATK_QUARANTINE) snap.actionsAttackerQuarantine++;
            else                          snap.actionsAttackerDoNothing++;

            NS_LOG_INFO("ATK_DECISION: suspect=" << suspect
                        << " z=" << z
                        << " state=" << AttackerStateNames[state]
                        << " action=" << AttackerActionNames[action]);

            if (action == ATK_QUARANTINE) {
                uint32_t maxCount = 0;
                {
                    auto lit = leaderSourceCounts.find(bestLeader);
                    if (lit != leaderSourceCounts.end()) {
                        auto sit = lit->second.find(suspect);
                        if (sit != lit->second.end()) maxCount = sit->second;
                    }
                }
                if (maxCount > 0) {
                    // Fase 2.5 — smart quarantine: checar redundância de capabilities
                    // antes de remover o suspeito. Se o suspeito carrega cap única
                    // do cluster, tenta importar doador de outro cluster.
                    auto missing = capsLostIfRemoved(bestLeader, suspect);
                    auto fullUnion    = getClusterCapabilityUnion(bestLeader, Ipv6Address::GetAny());
                    auto withoutCaps  = getClusterCapabilityUnion(bestLeader, suspect);
                    if (missing.empty()) {
                        snap.smartRedundancyOk++;
                        NS_LOG_INFO("SMART_QUARANTINE: suspect=" << suspect
                                    << " leader=" << bestLeader
                                    << " redundancy_ok no_transfer_needed"
                                    << " | cluster_caps=" << serializeCapabilities(&fullUnion)
                                    << " caps_after=" << serializeCapabilities(&withoutCaps));
                    } else {
                        auto donor = findCapabilityDonor(missing, bestLeader, suspect);
                        if (donor.found) {
                            bool ok = transferDonorToCluster(donor.donor, donor.donorLeader, bestLeader);
                            if (ok) snap.smartTransferOk++;
                            NS_LOG_INFO("SMART_QUARANTINE: suspect=" << suspect
                                        << " leader=" << bestLeader
                                        << " missing_caps=" << serializeCapabilities(&missing)
                                        << " donor=" << donor.donor
                                        << " donor_from=" << donor.donorLeader
                                        << " covered=" << donor.coveredCount << "/" << missing.size()
                                        << " sim=" << donor.similarityToRecv
                                        << " transfer=" << (ok ? "OK" : "FAIL"));
                        } else {
                            snap.smartTransferNoDonor++;
                            NS_LOG_INFO("SMART_QUARANTINE: suspect=" << suspect
                                        << " leader=" << bestLeader
                                        << " missing_caps=" << serializeCapabilities(&missing)
                                        << " no_donor_found — quarantining anyway (capability gap will persist)");
                        }
                    }
                    sendQuarantineOrder(bestLeader, suspect);
                    globallyQuarantined[suspect] = Simulator::Now().GetSeconds();
                }
            }

            PendingDecision pd{state, action, bestLeader};
            lastAttackerDecisions[suspect] = pd;
        }

        // 4) Decaimento de ε do ramo atacante apenas quando houve suspeitos no ciclo.
        attackerSys.decayEpsilonIfActive((int)suspects.size());

        // 5) Janela consumida: limpar contadores acumulados para a próxima rodada.
        leaderSourceCounts.clear();
    }

    // ============================================================
    // Fase 2.5 — smart quarantine (capability-aware)
    // ============================================================
    // PROPRIEDADE OPERACIONAL: estes helpers só disparam o caminho de
    // transferência (findCapabilityDonor → transferDonorToCluster) em cenários
    // raros sob a configuração padrão. Motivo: SIMILARITY_THRESHOLD = 0.95 em
    // NodeApplication.cc força clusters de capabilities virtualmente idênticas
    // (sim = |∩|/sqrt(|A|*|B|) >= 0.95 só é alcançável com >95% de overlap),
    // o que torna a remoção de qualquer membro preservar todas as caps do
    // cluster por construção. capsLostIfRemoved retorna vazio em ~100% dos
    // smoke tests, e a quarentena segue direto pra sendQuarantineOrder.
    //
    // Mantido como rede de segurança defensiva para:
    //   (a) cenários onde SIMILARITY_THRESHOLD seja relaxado experimentalmente
    //   (b) clustering esparso pós-falhas múltiplas (não aplicável em
    //       detective-v1 que não tem failures, mas relevante pra extensões)
    //   (c) capability files sintéticos pra testes específicos
    //
    // O caminho foi validado em runtime via teste forçado com threshold 0.80
    // e capabilities específicas (ver detective_v1_state.md). Lógica espelha
    // o REALLOCATE de órfãos do synapt (mesmo padrão de addClusterMember/
    // setMyLeader/memberCount).
    // ============================================================

    std::vector<capabilities> NodeAPApplication::getClusterCapabilityUnion(
            Ipv6Address leader, Ipv6Address excludeNode) const {
        std::set<capabilities> unionSet;
        for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
            Ptr<NodeApplication> app = DynamicCast<NodeApplication>(
                this->networkNodes.Get(j)->GetApplication(0));
            if(!app || !app->isNodeAlive()) continue;
            Ipv6Address addr = app->GetNodeIpAddress();
            if(addr == excludeNode) continue;
            if(app->getMyLeader() != leader) continue;
            for(capabilities c : app->getNodeCapabilities()){
                unionSet.insert(c);
            }
        }
        return std::vector<capabilities>(unionSet.begin(), unionSet.end());
    }

    std::vector<capabilities> NodeAPApplication::capsLostIfRemoved(
            Ipv6Address leader, Ipv6Address suspect) const {
        auto withSuspect    = getClusterCapabilityUnion(leader, Ipv6Address::GetAny());
        auto withoutSuspect = getClusterCapabilityUnion(leader, suspect);
        std::set<capabilities> withoutSet(withoutSuspect.begin(), withoutSuspect.end());
        std::vector<capabilities> lost;
        for(capabilities c : withSuspect){
            if(withoutSet.count(c) == 0) lost.push_back(c);
        }
        return lost;
    }

    NodeAPApplication::DonorChoice NodeAPApplication::findCapabilityDonor(
            const std::vector<capabilities>& missingCaps,
            Ipv6Address receiverLeader,
            Ipv6Address suspectToExclude) const {
        DonorChoice best{Ipv6Address::GetAny(), Ipv6Address::GetAny(), 0, 0.0, false};
        if(missingCaps.empty()) return best;

        // Pré-compute fingerprint do cluster receptor (caps atuais sem o suspeito)
        // pra desempate por similaridade.
        auto recvCapsVec = getClusterCapabilityUnion(receiverLeader, suspectToExclude);
        std::set<capabilities> missingSet(missingCaps.begin(), missingCaps.end());

        for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
            Ptr<NodeApplication> app = DynamicCast<NodeApplication>(
                this->networkNodes.Get(j)->GetApplication(0));
            if(!app || !app->isNodeAlive()) continue;

            Ipv6Address candAddr = app->GetNodeIpAddress();
            Ipv6Address candLeader = app->getMyLeader();

            // Filtros básicos:
            if(candAddr == suspectToExclude) continue;     // não é o suspeito
            if(candLeader == receiverLeader) continue;     // já está no cluster receptor
            if(clusterInfoMap.count(candAddr) > 0) continue;  // é líder de algum cluster — não pode ser doado
            if(globallyQuarantined.count(candAddr) > 0) continue;  // está quarentenado em outro lugar
            if(candLeader == Ipv6Address::GetAny()) continue;  // órfão sem cluster

            // Cobre alguma das missing caps?
            auto candCaps = app->getNodeCapabilities();
            int covered = 0;
            for(capabilities c : candCaps){
                if(missingSet.count(c) > 0) covered++;
            }
            if(covered == 0) continue;

            // Doar este nó deixaria o cluster de origem sem alguma capability?
            auto donorClusterLost = capsLostIfRemoved(candLeader, candAddr);
            if(!donorClusterLost.empty()) continue;  // não é doador safe

            // Score: cobre mais caps > similaridade maior.
            double sim = capabilitiesSimilarity(&candCaps, &recvCapsVec);
            bool better = false;
            if(covered > best.coveredCount) better = true;
            else if(covered == best.coveredCount && sim > best.similarityToRecv) better = true;

            if(better){
                best.donor              = candAddr;
                best.donorLeader        = candLeader;
                best.coveredCount       = covered;
                best.similarityToRecv   = sim;
                best.found              = true;
            }
        }
        return best;
    }

    bool NodeAPApplication::transferDonorToCluster(Ipv6Address donor,
                                                    Ipv6Address oldLeader,
                                                    Ipv6Address newLeader){
        Ptr<NodeApplication> donorApp = nullptr, oldLeaderApp = nullptr, newLeaderApp = nullptr;
        for(uint32_t j = 0; j < this->networkNodes.GetN(); j++){
            Ptr<NodeApplication> app = DynamicCast<NodeApplication>(
                this->networkNodes.Get(j)->GetApplication(0));
            if(!app) continue;
            if(app->GetNodeIpAddress() == donor)     donorApp     = app;
            if(app->GetNodeIpAddress() == oldLeader) oldLeaderApp = app;
            if(app->GetNodeIpAddress() == newLeader) newLeaderApp = app;
        }
        if(!donorApp || !oldLeaderApp || !newLeaderApp) return false;

        oldLeaderApp->removeClusterMember(donor);
        newLeaderApp->addClusterMember(donor);
        donorApp->setMyLeader(newLeader);

        // Ajustar memberCount nos dois clusters
        auto oit = clusterInfoMap.find(oldLeader);
        if(oit != clusterInfoMap.end() && oit->second.memberCount > 0) oit->second.memberCount--;
        auto nit = clusterInfoMap.find(newLeader);
        if(nit != clusterInfoMap.end()) nit->second.memberCount++;

        return true;
    }
}