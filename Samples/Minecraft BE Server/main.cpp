#include <RakPeerInterface.h>
#include <RakPeer.h>

using namespace RakNet;

class MyRakPeer : public RakPeer
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
    SocketDescriptor sd(19132, 0);
    peerInterface->SetMaximumIncomingConnections(10);
    MyRakPeer *myPeer = static_cast<MyRakPeer *>(peerInterface);
    RakString response("MCPE;Dedicated Server;390;1.14.60;0;10;13253860892328930865;Bedrock level;Survival");
    myPeer->SetOfflinePingResponseV2(response);
    response.FreeMemory();
    peerInterface->Startup(10, &sd, 1);
    while (1);
}
