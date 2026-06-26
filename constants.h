#pragma once

namespace nr2{
    enum MessageTypes{TaskDispatch, TaskAccept, LeaderRegister, CapabilityDissemination, LeaderToCluster, Beacon,
        // Novos tipos para o Aprendizado Intuitivo
        HeartbeatReport,        // Nó líder → AP: relatório periódico de saúde do cluster
        ReassignOrder,          // AP → nó órfão: ordem de realocação para novo cluster
        NewLeaderElection,      // AP → cluster: ordem de re-eleição de líder
        // Ataque UDP Flood
        FloodPacket,            // Pacote de ataque UDP flood (insider threat)
        // Pipeline de defesa contra atacante (v1)
        QuarantineOrder,        // AP → líder: ordem de quarentena de uma origem suspeita
        // Pipeline de defesa contra líder atacante (v2)
        ForceReelection         // AP → membros do cluster: forçar re-eleição excluindo líder atual
    };
}