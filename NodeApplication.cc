#include "NodeApplication.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/ipv6.h"
#include "ns3/lr-wpan-net-device.h"
#include "ns3/lr-wpan-spectrum-value-helper.h"
#include "ns3/spectrum-value.h"

#include "MyTag.h"
#include "constants.h"

#include <memory>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Contaski_V1_Nodes");

// Definição do threshold de saturação (estático, compartilhado entre todos os nós).
// Configurável via NodeApplication::setFloodSaturationThreshold (CLI em contaski.cc).
uint64_t nr2::NodeApplication::FLOOD_SATURATION_THRESHOLD = 500;

namespace nr2{

    // ADICIONADO: Limiar de similaridade conforme Figura 3 do artigo
    // S1 = Fraco:  0.65 - 0.82
    // S2 = Médio:  0.82 - 1.00
    // S3 = Forte:  1.00
    // NOTA: Usando 0.87 para formar clusters mais homogêneos
    // Com 0.65, nós com apenas capacidades básicas em comum entram no mesmo cluster
    const double SIMILARITY_THRESHOLD = 0.95;

    Ipv6Address NodeApplication::GetNodeIpAddress(){
        Ptr <Node> PtrNode = this->GetNode();
        Ptr<Ipv6> ipv6 = PtrNode->GetObject<Ipv6> ();
        Ipv6InterfaceAddress iaddr = ipv6->GetAddress(1, 0);
        Ipv6Address ipAddr = iaddr.GetAddress();

        return ipAddr;
    }

    int NodeApplication::sendMessageHelper(MessageTypes type, Ipv6Address addr, uint8_t* buffer, int size){
        uint16_t port = 2020;
        int status;
        Inet6SocketAddress remote = Inet6SocketAddress(addr, port);
        /*status = this->m_socket->Connect(remote);
        if(status == -1){
            NS_LOG_INFO("Could not bind socket");

            return status;
        }*/

        Ptr<Packet> pack = Create<Packet>(buffer, size);
        MyTag tag;
        tag.SetSimpleValue(type);
        pack->AddPacketTag(tag);
        
        status = this->m_socket->SendTo(pack, 0, remote);

        if(status == -1){
            NS_LOG_INFO(this->GetNodeIpAddress() << "Could not send package");
        }

        NS_LOG_INFO("N: MS (" << this->GetNodeIpAddress() << ", " << addr << ", " << status << ")");

        return status;
    }

    void NodeApplication::sendBroadcastMessageHelper(MessageTypes type, uint8_t* buffer, int size){
        for (auto addr:this->allNodesAddrs){
            auto buf= new uint8_t[size];
            std::memcpy(buf, buffer, size);
            Simulator::Schedule(MilliSeconds(2.0),&NodeApplication::sendMessageHelper, this, type, addr, buf, size);
            //this->sendMessageHelper(type, addr, buffer, size);
        }
    }

    void NodeApplication::setup(capabilitiesVector cap){
        this->m_node = GetNodeIpAddress();
        this->m_tid = ns3::UdpSocketFactory::GetTypeId();
        this->m_socket = this->GetNode()->GetObject<Socket>();

        this->neighList = new std::map<Ipv6Address, int>;
        this->clusterList = new std::map<Ipv6Address, int>;
        this->neighCapabilities = new std::map<Ipv6Address, capabilitiesVector>;
        this->neighSimilatiries = new std::vector< std::pair<double, Ipv6Address>* >;
        this->clusterCapabilities = new capabilitiesVector();

        this->capabilities = new capabilitiesVector(cap);

        this->isLeader = false;

        this->alive = true;
        this->heartbeatInterval = 5.0;  // Heartbeat a cada 30 segundos
        this->myLeader = Ipv6Address();  // Sem líder até eleição

        this->floodAttack = nullptr;
        this->isCompromised = false;
        this->attackStartTime = 0.0;
        this->totalFloodReceived = 0;
    }

    TypeId NodeApplication::GetTypeId(){
        static TypeId tid = TypeId ("ns3::NodeApplication")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<NodeApplication>()
            .AddAttribute ("Protocol", "The type of protocol to use. This should be "
                   "a subclass of ns3::SocketFactory",
                   TypeIdValue (UdpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&NodeApplication::m_tid),
                   // This should check for SocketFactory as a parent
                   MakeTypeIdChecker ())
            ;

        return tid;
    }

    void NodeApplication::StartApplication(){
        // If socket is not created yet
        if(!this->m_socket){
            // Create socket
            auto netdev = this->GetNode()->GetDevice(2);
            
            this->m_socket = Socket::CreateSocket(GetNode(), m_tid);
            this->m_socket->BindToNetDevice(netdev);
            
            this->m_socket->SetAllowBroadcast(true);
            this->m_socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny (), 2020));
            this->m_socket->Listen();
            this->m_socket->SetRecvCallback(MakeCallback (&NodeApplication::recvCallback, this));
        }

        // Run beaconing
        //this->beacon();
        Simulator::ScheduleNow(&NodeApplication::beacon, this);

        // Disseminate capabilities
        //this->disseminateCapabilities();
        Simulator::Schedule( (Seconds(60.0) - Simulator::Now()) , &NodeApplication::disseminateCapabilities, this);

        // Calculate similarities
        //this->similarityCalculation();
        Simulator::Schedule( (Seconds(90.5) - Simulator::Now()),&NodeApplication::similarityCalculation, this);
    }

    void NodeApplication::StopApplication(){
        this->alive = false;
        if(this->floodAttack) this->floodAttack->stop();
        this->m_socket->Close();
    }

    void NodeApplication::recvCallback(Ptr<Socket> socket){
        if(!this->alive) return;
        Ptr<Packet> packet;
        Address from;
        Ipv6Address fromIP;
        MyTag tag;
        
        while((packet = socket->RecvFrom(from))){
            fromIP = Inet6SocketAddress::ConvertFrom(from).GetIpv6();
            packet->PeekPacketTag(tag);
            uint8_t *buffer = new uint8_t[packet->GetSize()];
	  	    packet->CopyData (buffer, packet->GetSize());

            // Fase 2 — quarentena local: dropar pacotes de origens bloqueadas
            // antes de qualquer processamento. Ordens vindas do AP (QuarantineOrder)
            // ainda devem passar — assumimos que o AP não está em blocklist.
            if (this->quarantinedSources.count(fromIP) > 0 &&
                tag.GetSimpleValue() != MessageTypes::QuarantineOrder) {
                delete[] buffer;
                continue;
            }

            // Contador de tráfego entrante por origem (consumido pelo líder no heartbeat).
            this->incomingPacketCount[fromIP]++;

            switch (tag.GetSimpleValue()){
                case MessageTypes::Beacon:{
                    string s = string(buffer, buffer+packet->GetSize());
                    int neighReceived = atoi(s.c_str());

                    if(neighReceived > (*this->neighList)[fromIP])
                        (*this->neighList)[fromIP] = neighReceived;

                    //NS_LOG_INFO("N: BR " << this->GetNodeIpAddress() << " <- " << fromIP << " (" << neighReceived << ")");
                    break;
                }
                
                case MessageTypes::CapabilityDissemination:
                {
                    capabilitiesVector *cap = parseCapabilities( std::string((char*)buffer) );
                    (*this->neighCapabilities)[fromIP] = *cap;

                    NS_LOG_INFO("N: C " << this->GetNodeIpAddress() << " <- " << fromIP << " (" << serializeCapabilities(cap) << ")");
                    break;
                }
                case MessageTypes::LeaderToCluster:{
                    // Perform task
                    string sTask = string(buffer, buffer+packet->GetSize());
                    this->performTask(sTask);
                    break;
                }
                case MessageTypes::TaskDispatch:{
                    // If i'm the leader
                    if (this->isLeader) {
                        //NS_LOG_INFO("Task received by leader");
                        string sTask = string(buffer, buffer+packet->GetSize());
                        this->dispatchTaskToCluster(sTask);
                    }
                    
                    break;
                }
                
                case MessageTypes::FloodPacket:
                    // Pacote de flood recebido — já foi contabilizado em
                    // incomingPacketCount (para Z-score do AnomalyDetector).
                    // Modelo de saturação: se ESTE nó é líder e o total acumulado
                    // de FloodPackets ultrapassa o threshold, simula a sobrecarga
                    // do hardware (NS-3 não modela exaustão de recurso por default)
                    // e marca o líder como morto. Membros saudáveis do cluster
                    // viram órfãos e entram no pipeline de recuperação do synapt
                    // (REALLOCATE/RECLUSTER no AP::processOrphansIntuitively).
                    if(this->isLeader){
                        this->totalFloodReceived++;
                        if(this->totalFloodReceived >= FLOOD_SATURATION_THRESHOLD){
                            NS_LOG_INFO("LEADER_DOWN: " << this->GetNodeIpAddress()
                                        << " saturado por flood (recv=" << this->totalFloodReceived
                                        << " >= threshold=" << FLOOD_SATURATION_THRESHOLD
                                        << ") at t=" << Simulator::Now().GetSeconds());
                            this->alive = false;
                            if(this->floodAttack) this->floodAttack->stop();
                            delete[] buffer;
                            return;
                        }
                    }
                    break;

                case MessageTypes::QuarantineOrder:{
                    // AP → líder: ordem de quarentena de uma origem suspeita.
                    // Payload: representação textual do IPv6 alvo (Ipv6Address::Print()).
                    if (!this->isLeader) break;  // só líderes aplicam quarentena
                    std::string targetStr = std::string((char*)buffer);
                    Ipv6Address target(targetStr.c_str());
                    this->quarantineSource(target);
                    NS_LOG_INFO("N: QUARANTINE applied by leader " << this->GetNodeIpAddress()
                                << " on " << target << " (ordered by AP)");
                    break;
                }

                case MessageTypes::ForceReelection:{
                    // v2 — AP → membro: força re-eleição excluindo um líder específico
                    // (que foi quarentenado por flodar o AP).
                    // Payload: IP do líder banido.
                    // Comportamento: blacklista o IP, limpa myLeader, re-roda
                    // tiebreakLeader. Se eleito, vira líder novo.
                    std::string banStr = std::string((char*)buffer);
                    Ipv6Address banned(banStr.c_str());
                    this->blacklistedLeaders.insert(banned);
                    // Remove o líder banido das estruturas locais
                    if (this->clusterList) this->clusterList->erase(banned);
                    if (this->neighList)   this->neighList->erase(banned);
                    if (this->neighCapabilities) this->neighCapabilities->erase(banned);
                    NS_LOG_INFO("N: FORCE_REELECTION received by " << this->GetNodeIpAddress()
                                << " — banned=" << banned << ", re-running election");
                    // Re-rodar eleição com o blacklist em vigor
                    Simulator::ScheduleNow(&NodeApplication::reelectLeader, this);
                    break;
                }

                default:
                    break;
            }

            delete[] buffer;
        }
    }

    void NodeApplication::beacon(){
        if(!this->alive) return;
        int neighSize = this->neighList->size();
        string buffer = std::to_string(neighSize);
        Ipv6Address addr = Ipv6Address("FF02::1");

        //this->sendBroadcastMessageHelper(MessageTypes::Beacon, (uint8_t*)buffer.c_str(), buffer.length()+1);
        this->sendMessageHelper(MessageTypes::Beacon, addr, (uint8_t*)buffer.c_str(), buffer.size()+1);
        //NS_LOG_INFO("N: BS " << this->GetNodeIpAddress() << " (" << buffer << ")");

        if ((Seconds(60.0) - Simulator::Now()) > Seconds(0.0)) {
            Simulator::Schedule(Seconds(0.5), &NodeApplication::beacon, this);
        }
    }

    void NodeApplication::disseminateCapabilities(){
        if(!this->alive) return;
        auto serializedCap = serializeCapabilities(this->capabilities);
        Ipv6Address addr = Ipv6Address("FF02::1");

        //this->sendBroadcastMessageHelper(MessageTypes::CapabilityDissemination, (uint8_t*)serializedCap.c_str(), serializedCap.size()+1);
        this->sendMessageHelper(MessageTypes::CapabilityDissemination, addr, (uint8_t*)serializedCap.c_str(), serializedCap.size()+1);

        if ((Seconds(90.0) - Simulator::Now()) > Seconds(0.0)) {
            Simulator::Schedule(Seconds(0.5), &NodeApplication::disseminateCapabilities, this);
        }
    }

    void NodeApplication::similarityCalculation(){
        if(!this->alive) return;
        //NS_LOG_INFO("N: S " << this->GetNodeIpAddress() << " at " << Simulator::Now().GetSeconds());

        for (auto const& neigh: *this->neighCapabilities){
            auto neighCap = neigh.second;
            
            // CORRIGIDO: Usar capabilitiesSimilarity (Equação 1 do artigo)
            // ao invés de capabilitiesSimilarityUFD
            double sim = capabilitiesSimilarity(this->capabilities, &neighCap);

            //auto pair = make_pair(sim, neigh.first);
            auto pair = new std::pair<double, Ipv6Address>(sim, neigh.first);
            this->neighSimilatiries->emplace_back(pair);
        }

        Simulator::ScheduleNow(&NodeApplication::doClustering, this);
    }

    void NodeApplication::doClustering(){
        if(!this->alive) return;
        //float mode = this->getSimilarityMode();
        std::sort(this->neighSimilatiries->begin(), this->neighSimilatiries->end());
        //double maxSim = (* --this->neighSimilatiries->end())->first;
        //double maxSim = 1.0;  // REMOVIDO: Não mais usado

        //Filter in nodes between mode and 1
        for (auto it = this->neighSimilatiries->begin(); it != this->neighSimilatiries->end(); it++){
            // CORRIGIDO: Usar SIMILARITY_THRESHOLD (0.65) ao invés de comparar com maxSim = 1.0
            // Antes: double sim = std::abs((*it)->first - maxSim); if(sim < 0.000001)
            if((*it)->first >= SIMILARITY_THRESHOLD){
                try{
                    //Join them into the cluster
                    (*this->clusterList)[(*it)->second] = this->neighList->at((*it)->second);
                }catch(...){
                    NS_LOG_INFO("N: " << this->GetNodeIpAddress() << " could not join " << (*it)->second << " to cluster");
                }
            }
        }

        //Select leader
        this->selectAndRegisterLeader();
    }

    float NodeApplication::getSimilarityMode(){
        std::sort(this->neighSimilatiries->begin(), this->neighSimilatiries->end());

        float current = (* this->neighSimilatiries->begin())->first;
        float mode = current;

        int count = 1;
        int countMode = 1;

        for (auto it = this->neighSimilatiries->begin()++; it != this->neighSimilatiries->end(); it++){
            if( (*it)->first == current){
                if(count > countMode){
                    countMode = count;
                    mode = current;
                }
            }else{
                if(count > countMode){
                    countMode = count;
                    mode = current;
                }

                count = 1;
                current = (*it)->first;
            }
        }
        
        return mode;
    }

    void NodeApplication::selectAndRegisterLeader(){
        if(!this->alive) return;
        Ipv6Address leader = tiebreakLeader();

        // Todo nó registra seu líder eleito (relação exclusiva 1:1)
        this->myLeader = leader;

        if( leader == this->GetNodeIpAddress()){
            NS_LOG_INFO("N: LS " << this->GetNodeIpAddress());

            //If i'm leader, increase tx power so AP can be reached
            Ptr<LrWpanNetDevice> nodenetdev = DynamicCast<LrWpanNetDevice>(this->GetNode()->GetDevice(1));
		    auto phy = nodenetdev->GetPhy();
		    LrWpanSpectrumValueHelper svh;
		    Ptr<SpectrumValue> psd = svh.CreateTxPowerSpectralDensity (10, 11);
		    phy->SetTxPowerSpectralDensity(psd);

            //this->registerLeader();
            Simulator::Schedule(Seconds(90.5+this->delay) - Now(), &NodeApplication::registerLeader, this);
            this->isLeader = true;


            /*float mode = this->getSimilarityMode();
            auto it = std::find_if( this->neighSimilatiries->begin(), this->neighSimilatiries->end(),
                [&mode](const std::pair<float, Ipv6Address>* element){
                    return element->first == mode;
                }
            );

            capabilitiesSimilarity(this->capabilities, &((*this->neighCapabilities)[(*it)->second]), this->clusterCapabilities);*/
            this->clusterCapabilities = this->capabilities;

            // Agendar heartbeat periódico após registro
            Simulator::Schedule(Seconds(90.5+this->delay+5.0) - Now(), &NodeApplication::sendHeartbeat, this);
        }
   }

    void NodeApplication::reelectLeader(){
        if(!this->alive) return;
        bool wasLeaderBefore = this->isLeader;

        Ipv6Address newLeader = tiebreakLeader();
        this->myLeader = newLeader;

        if(newLeader == this->GetNodeIpAddress()){
            // Eleito como novo líder. Se já era líder antes, nada de novo a fazer
            // (improvável — o líder banido não é quem está re-elegendo).
            // Se não era líder antes, virar líder agora com timing imediato.
            if(!wasLeaderBefore){
                NS_LOG_INFO("N: LS (RE-ELECT) " << this->GetNodeIpAddress());

                // Aumentar potência TX
                Ptr<LrWpanNetDevice> nodenetdev = DynamicCast<LrWpanNetDevice>(this->GetNode()->GetDevice(1));
                auto phy = nodenetdev->GetPhy();
                LrWpanSpectrumValueHelper svh;
                Ptr<SpectrumValue> psd = svh.CreateTxPowerSpectralDensity(10, 11);
                phy->SetTxPowerSpectralDensity(psd);

                this->isLeader = true;
                this->clusterCapabilities = this->capabilities;

                // Registrar imediatamente no AP
                Simulator::ScheduleNow(&NodeApplication::registerLeader, this);

                // Iniciar heartbeat imediatamente (próximo em 5s)
                Simulator::Schedule(Seconds(this->heartbeatInterval),
                                    &NodeApplication::sendHeartbeat, this);
            }
        } else {
            NS_LOG_INFO("N: RE-ELECTED myLeader=" << newLeader
                        << " (caller=" << this->GetNodeIpAddress() << ")");
        }
    }

    Ipv6Address NodeApplication::tiebreakLeader(){
        Ipv6Address ipv6 = this->GetNodeIpAddress();
        Ipv6Address selectedLeader;

        // v2 — remover líderes banidos (por ForceReelection) antes da eleição.
        // Garante que um líder atacante quarentenado pelo AP NÃO seja re-eleito
        // pelo seu próprio cluster. Aplicação aqui é defensiva — também removemos
        // do clusterList no handler do ForceReelection, mas refazemos aqui caso
        // alguma estrutura tenha sido reconstruída entre eventos.
        for (const auto& banned : this->blacklistedLeaders) {
            this->clusterList->erase(banned);
        }

        // CORRIGIDO: Usar tamanho do cluster (clusterList->size()) ao invés de neighList->size()
        // Isso garante consistência: todos os nós no cluster usam a mesma métrica
        (*this->clusterList)[ipv6] = this->neighList->size();

        /*auto leader = std::max(this->clusterList->begin(), this->clusterList->end(),
        [](std::map<Ipv6Address, int>::iterator it1, std::map<Ipv6Address, int>::iterator it2 ){
            return it1->second > it2->second;
        });*/
        auto leader = std::max_element(this->clusterList->begin(), this->clusterList->end(),
            [](std::pair<Ipv6Address, int> it1, std::pair<Ipv6Address, int> it2 ){
                return it1.second < it2.second;
            }
        );

        int maxNeigh = leader->second;

        std::map<Ipv6Address, int> *leaderCandidates = new map<Ipv6Address, int>;

        std::copy_if(this->clusterList->begin(), this->clusterList->end(),
            std::inserter(*leaderCandidates, leaderCandidates->end() ),
            [maxNeigh](std::pair<Ipv6Address, int> a){
                return a.second == maxNeigh;
            }
        );


        if( leaderCandidates->size() == 0){
            selectedLeader = leader->first;
        }else if(leaderCandidates->size() == 1){
            selectedLeader = (*leaderCandidates->begin()).first;
        }else{
            //Tiebreak
            auto tiebraker = new std::map<Ipv6Address, int>;
            
            for(auto candidate: *leaderCandidates) {
                if(candidate.first == ipv6){
                    // Próprio nó: usar capacidades locais
                    (*tiebraker)[candidate.first] = this->capabilities->size();
                } else {
                    // Vizinho: buscar em neighCapabilities
                    auto it = this->neighCapabilities->find(candidate.first);
                    if(it != this->neighCapabilities->end()){
                        (*tiebraker)[candidate.first] = it->second.size();
                    } else {
                        (*tiebraker)[candidate.first] = 0;
                    }
                }
            }
            
            /*Ipv6Address maiorIp;
            int maiorCap = 0;
            for(auto lCand : tiebraker){
                if(lCand.second>maiorCap){
                    maiorCap = lCand.second;
                    maiorIp = lCand.first;
                }
            }
            return maiorIp;*/
            /*auto leader2 = std::max( tiebraker->begin(), tiebraker->end(),
                [](std::map<Ipv6Address, int>::iterator it1, std::map<Ipv6Address, int>::iterator it2 ){
                    return it1->second < it2->second;
                }
            );*/
            // CORRIGIDO: Usar tiebraker ao invés de clusterList para desempate por capacidades
            auto leader2 = std::max_element(tiebraker->begin(), tiebraker->end(),
                [](std::pair<Ipv6Address, int> a, std::pair<Ipv6Address, int> b){
                    return a.second < b.second;
                }
            );
            
            int maxCap = leader2->second;
            
            // Filtrar todos com máximo de capacidades
            std::vector<Ipv6Address> finalCandidates;
            for(auto& c : *tiebraker){
                if(c.second == maxCap){
                    finalCandidates.push_back(c.first);
                }
            }
            
            // Desempate final por menor IP
            if(finalCandidates.size() == 1){
                selectedLeader = finalCandidates[0];
            } else {
                std::sort(finalCandidates.begin(), finalCandidates.end(),
                    [](const Ipv6Address& a, const Ipv6Address& b){
                        uint8_t bufA[16], bufB[16];
                        a.GetBytes(bufA);
                        b.GetBytes(bufB);
                        return memcmp(bufA, bufB, 16) < 0;
                    }
                );
                selectedLeader = finalCandidates[0];
            }
            
            delete tiebraker;
        }

        NS_LOG_INFO("N: " << ipv6 << " CLSize " << this->clusterList->size() << " elects " << selectedLeader);
        
        delete leaderCandidates;
        
        return selectedLeader;
   }

    void NodeApplication::registerLeader(){
        if(!this->alive) return;
        NS_LOG_INFO("N: LR " << this->GetNodeIpAddress() << " at " << Now().GetSeconds());
        Simulator::ScheduleNow(&NodeApplication::sendMessageHelper, this, MessageTypes::LeaderRegister, this->apAddress, (uint8_t*)0, 0 );
        //this->sendMessageHelper(MessageTypes::LeaderRegister, this->apAddress, 0, 0);
    }

   void NodeApplication::setAPAddress(Ipv6Address ip){
       this->apAddress = ip;
   }

    void NodeApplication::dispatchTaskToCluster(string sTask){
        if(!this->alive) return;
        auto task = new Task(sTask);
        auto taskCap = task->getCapabilities();
        
        std::sort(this->capabilities->begin(), this->capabilities->end());
        std::sort(taskCap->begin(), taskCap->end());

        //Check if cluster can perform the task
        if( 
            std::includes(this->capabilities->begin(), this->capabilities->end(),
                taskCap->begin(), taskCap->end()
            )
        ){
            this->sendMessageHelper(MessageTypes::TaskAccept, this->apAddress, 0, 0);

            NS_LOG_INFO("N: LA " << this->GetNodeIpAddress() << ", " << task->getTid() << ", " << Simulator::Now().GetSeconds());

            for (auto node : *this->clusterList){
                this->sendMessageHelper(MessageTypes::LeaderToCluster, node.first,
                    (uint8_t*) sTask.c_str(), sTask.size()+1);
            }
        }
    }

    void NodeApplication::performTask(string sTask){
        auto task = new Task(sTask);
        Simulator::Schedule(Seconds(task->getDuration()), &NodeApplication::nullFunction, this);
    }

    void NodeApplication::nullFunction(){
    }

    void NodeApplication::setAllNodesAddrs(std::vector<Ipv6Address> addrs){
        this->allNodesAddrs = addrs;
    }

    void NodeApplication::setDelay(double delay){
        this->delay = delay;
    }

    int NodeApplication::getClusterSize(){
        if(this->clusterList){
            return this->clusterList->size();
        }
        return 0;
    }

    void NodeApplication::sendHeartbeat(){
        if(!this->alive || !this->isLeader) return;

        // Heartbeat ao AP — formato estendido (Fase 2):
        //   "currentMembers,initialMembers|src1=cnt1;src2=cnt2;..."
        // A parte após o '|' lista pacotes recebidos por origem desde o último
        // heartbeat. Usamos '=' como separador entre IP e contagem porque IPv6
        // contém ':' (não pode ser usado como delimitador).
        uint32_t currentMembers = this->clusterList ? this->clusterList->size() : 0;
        std::stringstream ss;
        ss << currentMembers << "," << currentMembers << "|";
        bool first = true;
        for (const auto& e : this->incomingPacketCount) {
            if (!first) ss << ";";
            ss << e.first << "=" << e.second;
            first = false;
        }
        std::string data = ss.str();

        this->sendMessageHelper(MessageTypes::HeartbeatReport, this->apAddress,
                                (uint8_t*)data.c_str(), data.size() + 1);

        // Reset por intervalo — próxima janela parte de zero.
        this->incomingPacketCount.clear();

        // Reagendar próximo heartbeat
        Simulator::Schedule(Seconds(this->heartbeatInterval), &NodeApplication::sendHeartbeat, this);
    }

    std::vector<Ipv6Address> NodeApplication::getClusterMembers(){
        std::vector<Ipv6Address> members;
        if(this->clusterList){
            for(const auto& entry : *this->clusterList){
                members.push_back(entry.first);
            }
        }
        return members;
    }

    void NodeApplication::addClusterMember(Ipv6Address member){
        if(this->clusterList){
            (*this->clusterList)[member] = 0;
        }
    }

    void NodeApplication::removeClusterMember(Ipv6Address member){
        if(this->clusterList){
            this->clusterList->erase(member);
        }
    }

    void NodeApplication::clearClusterMembers(){
        if(this->clusterList){
            this->clusterList->clear();
        }
    }

    capabilitiesVector NodeApplication::getNodeCapabilities() const {
        if(this->capabilities){
            return *this->capabilities;
        }
        return capabilitiesVector();
    }

    void NodeApplication::becomeLeader(Ipv6Address apAddr){
        this->isLeader = true;
        this->apAddress = apAddr;
        this->clusterCapabilities = this->capabilities;
        this->myLeader = this->GetNodeIpAddress();  // Líder de si mesmo

        // Limpar clusterList anterior e preparar para novos seguidores
        if(this->clusterList){
            this->clusterList->clear();
        }

        // Aumentar potência TX para alcançar o AP (mesmo que na eleição original)
        Ptr<LrWpanNetDevice> nodenetdev = DynamicCast<LrWpanNetDevice>(this->GetNode()->GetDevice(1));
        if(nodenetdev){
            auto phy = nodenetdev->GetPhy();
            LrWpanSpectrumValueHelper svh;
            Ptr<SpectrumValue> psd = svh.CreateTxPowerSpectralDensity(10, 11);
            phy->SetTxPowerSpectralDensity(psd);
        }

        NS_LOG_INFO("N: BecomeLeader " << this->GetNodeIpAddress() << " at " << Now().GetSeconds());
    }

    // ============================================================
    // UDP Flood — delegado ao módulo FloodAttack
    // ============================================================

    void NodeApplication::setAttackParams(double startTime, double rate, uint32_t payloadSize){
        this->isCompromised = true;
        this->attackStartTime = startTime;

        // Criar módulo de flood (instanciado apenas quando o nó é comprometido)
        this->floodAttack = new FloodAttack(this->m_socket, this->GetNodeIpAddress());
        this->floodAttack->configure(rate, payloadSize);

        // Agendar início do flood
        double now = Simulator::Now().GetSeconds();
        double delayToStart = startTime - now;
        if(delayToStart > 0){
            Simulator::Schedule(Seconds(delayToStart), &NodeApplication::startFlood, this);
        }
    }

    void NodeApplication::startFlood(){
        if(!this->alive || !this->floodAttack) return;

        // Alvo depende do papel do atacante:
        //   Líder comprometido  → flood o AP
        //   Membro comprometido → flood o seu líder
        Ipv6Address target;
        std::string role;
        if(this->isLeader){
            target = this->apAddress;
            role = "LEADER";
        } else {
            target = this->myLeader;
            role = "MEMBER";
        }

        // Verificação local pré-ataque (atacante "consciente"):
        //   Sanity check mínimo: o nó comprometido só ataca se o resultado da
        //   sua eleição local for um líder concreto (não-degenerado). Não tenta
        //   distinguir cluster ativo de cluster real-idle — essa distinção não
        //   é observável localmente, e clusters idle são fenômeno normal do
        //   protocolo (presente em sectional e synapt). Atacante cujo target é
        //   ghost-leader registrado-zero não é filtrado aqui; será reportado
        //   nas métricas como "ataque sem efeito observado pelo AP" (analogia
        //   direta com cluster idle que não conclui tarefa em sectional/synapt).
        if(!this->isLeader){
            if(target == Ipv6Address::GetAny() || target == this->GetNodeIpAddress()){
                NS_LOG_INFO("FLOOD_ABORT: " << this->GetNodeIpAddress()
                            << " (MEMBER) — sem líder válido (target=" << target << ")");
                return;
            }
        }

        NS_LOG_INFO("FLOOD_TRIGGER: Node " << this->GetNodeIpAddress()
                    << " (" << role << ") → target " << target
                    << " t=" << Simulator::Now().GetSeconds());

        this->floodAttack->start(target);
    }
}