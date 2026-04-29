#include "FloodAttack.h"

NS_LOG_COMPONENT_DEFINE("FloodAttack");

namespace nr2 {

    FloodAttack::FloodAttack(Ptr<Socket> socket, Ipv6Address nodeAddr)
        : socket(socket), nodeAddr(nodeAddr), rate(50.0), payloadSize(64), active(false) {
    }

    void FloodAttack::configure(double rate, uint32_t payloadSize){
        this->rate = rate;
        this->payloadSize = payloadSize;
    }

    void FloodAttack::start(Ipv6Address target){
        if(target.IsAny()){
            NS_LOG_INFO("FLOOD_SKIP: " << nodeAddr << " — alvo inválido");
            return;
        }
        if(target == nodeAddr){
            NS_LOG_INFO("FLOOD_SKIP: " << nodeAddr << " — não pode flodar a si mesmo");
            return;
        }

        this->target = target;
        this->active = true;

        NS_LOG_INFO("FLOOD_START: " << nodeAddr
                    << " flooding " << target
                    << " rate=" << rate << " pkts/s"
                    << " payload=" << payloadSize << "B"
                    << " t=" << Simulator::Now().GetSeconds());

        sendPacket();
    }

    void FloodAttack::stop(){
        active = false;
    }

    void FloodAttack::sendPacket(){
        if(!active) return;

        // Criar pacote com payload de lixo e tag FloodPacket
        std::vector<uint8_t> junk(payloadSize, 0xAA);
        Ptr<Packet> pack = Create<Packet>(junk.data(), junk.size());
        MyTag tag;
        tag.SetSimpleValue(MessageTypes::FloodPacket);
        pack->AddPacketTag(tag);

        Inet6SocketAddress remote(target, 2020);
        socket->SendTo(pack, 0, remote);

        // Reagendar próximo pacote
        double interval = 1.0 / rate;
        Simulator::Schedule(Seconds(interval), &FloodAttack::sendPacket, this);
    }

} // namespace nr2