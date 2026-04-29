#pragma once

/**
 * FloodAttack — Módulo de ataque UDP Flood isolado
 * ==================================================
 * Encapsula toda a lógica de envio de flood.
 * Instanciado opcionalmente por NodeApplication quando o nó é comprometido.
 * Não altera clustering, beacon, similaridade ou qualquer outra lógica do nó.
 */

#include "ns3/core-module.h"
#include "ns3/socket.h"
#include "ns3/ipv6-address.h"
#include "MyTag.h"
#include "constants.h"

using namespace ns3;

namespace nr2 {

    class FloodAttack {
    public:
        FloodAttack(Ptr<Socket> socket, Ipv6Address nodeAddr);

        // Configurar parâmetros do flood
        void configure(double rate, uint32_t payloadSize);

        // Iniciar flood contra um alvo específico
        void start(Ipv6Address target);

        // Parar o flood (chamado em StopApplication)
        void stop();

        bool isActive() const { return active; }

    private:
        void sendPacket();

        Ptr<Socket>     socket;
        Ipv6Address     nodeAddr;       // IP do nó atacante (para log)
        Ipv6Address     target;         // IP do alvo
        double          rate;           // pkts/s
        uint32_t        payloadSize;    // bytes por pacote
        bool            active;
    };

} // namespace nr2