#include <RakPeerInterface.h>
#include <RakPeer.h>

using namespace RakNet;

class RakPeerMod : public RakPeer
{
public:
    void SetOfflinePingResponseV2(RakString msg)
    {
        this->rakPeerMutexes[offlinePingResponse_Mutex].Lock();
        this->offlinePingResponse.Reset();
        this->offlinePingResponse.Write(msg);
        this->rakPeerMutexes[offlinePingResponse_Mutex].Unlock();
    }
};

int main()
{
    RakPeerInterface *peerInterface = RakPeerInterface::GetInstance();
    SocketDescriptor sd(static_cast<unsigned short>(std::abs(static_cast<long>(peerInterface->Get64BitUniqueRandomNumber() / 0x38d7ea4c68000))), 0);
    peerInterface->SetMaximumIncomingConnections(10);

    RakPeerMod *moddedRakPeer = static_cast<RakPeerMod *>(peerInterface);
    RakString response("Different-Peer-for-response");
    moddedRakPeer->SetOfflinePingResponseV2(response);
    response.FreeMemory();

    peerInterface->Startup(10, &sd, 1);
    while (1);
}
