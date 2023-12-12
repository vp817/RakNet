/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// \file
//

#define CAT_NEUTER_EXPORT /* Neuter dllimport for libcat */

#include "RakNetDefines.h"
#include "RakPeer.h"
#include "RakNetTypes.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <ctime>
#include <cctype> // toupper
#include <string.h>
#include "GetTime.h"
#include "MessageIdentifiers.h"
#include "DS_HuffmanEncodingTree.h"
#include "Rand.h"
#include "PluginInterface2.h"
#include "StringCompressor.h"
#include "StringTable.h"
#include "NetworkIDObject.h"
#include "RakNetTypes.h"
#include "DR_SHA1.h"
#include "RakSleep.h"
#include "RakAssert.h"
#include <random>
#include <algorithm>
#include "RakNetVersion.h"
#include "NetworkIDManager.h"
#include "gettimeofday.h"
#include "SignaledEvent.h"
#include "SuperFastHash.h"
#include "RakAlloca.h"
#include "WSAStartupSingleton.h"

#ifdef USE_THREADED_SEND
#include "SendToThread.h"
#endif

#ifdef CAT_AUDIT
#define CAT_AUDIT_PRINTF(...) std::printf(__VA_ARGS__)
#else
#define CAT_AUDIT_PRINTF(...)
#endif

#if !defined(__APPLE__) && !defined(__APPLE_CC__)
#include <cstdlib> // malloc
#endif

namespace RakNet
{
	RAK_THREAD_DECLARATION(UpdateNetworkLoop);
	RAK_THREAD_DECLARATION(RecvFromLoop);
	RAK_THREAD_DECLARATION(UDTConnect);
}

#define REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE 8

static const int NUM_MTU_SIZES = 3;

static const int mtuSizes[NUM_MTU_SIZES] = {MAXIMUM_MTU_SIZE, 1200, 576};

using namespace RakNet;

static RakNetRandom rnr;

static const unsigned int MAX_OFFLINE_DATA_LENGTH = 400;

static const uint8_t OFFLINE_MESSAGE_DATA_ID[16] = {0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78};

STATIC_FACTORY_DEFINITIONS(RakPeerInterface, RakPeer)

// Constructor
RakPeer::RakPeer()
{
#if LIBCAT_SECURITY == 1
	// Encryption and security
	CAT_AUDIT_PRINTF("AUDIT: Initializing RakPeer security flags: using_security = false, server_handshake = null, cookie_jar = null\n");
	_using_security = false;
	_server_handshake = 0;
	_cookie_jar = 0;
#endif

	StringCompressor::AddReference();
	RakNet::StringTable::AddReference();
	WSAStartupSingleton::AddRef();

	defaultMTUSize = mtuSizes[NUM_MTU_SIZES - 1];
	trackFrequencyTable = false;
	maximumIncomingConnections = 0;
	maximumNumberOfPeers = 0;
	remoteSystemList = 0;
	activeSystemList = 0;
	activeSystemListSize = 0;
	remoteSystemLookup = 0;
	bytesSentPerSecond = bytesReceivedPerSecond = 0;
	endThreads = true;
	isMainLoopThreadActive = false;
	incomingDatagramEventHandler = 0;

#if defined(GET_TIME_SPIKE_LIMIT) && GET_TIME_SPIKE_LIMIT > 0
	occasionalPing = true;
#else
	occasionalPing = false;
#endif
	allowInternalRouting = false;
	for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
		ipList[i] = UNASSIGNED_SYSTEM_ADDRESS;
	allowConnectionResponseIPMigration = false;
	incomingPasswordLength = 0;
	splitMessageProgressInterval = 0;
	unreliableTimeout = 1000;
	maxOutgoingBPS = 0;
	firstExternalID = UNASSIGNED_SYSTEM_ADDRESS;
	myGuid = UNASSIGNED_RAKNET_GUID;
	userUpdateThreadPtr = 0;
	userUpdateThreadData = 0;

#ifdef _DEBUG
	// Wait longer to disconnect in debug so I don't get disconnected while tracing
	defaultTimeoutTime = 30000;
#else
	defaultTimeoutTime = 10000;
#endif

#ifdef _DEBUG
	_packetloss = 0.0;
	_minExtraPing = 0;
	_extraPingVariance = 0;
#endif

	bufferedCommands.SetPageSize(sizeof(BufferedCommandStruct) * 16);
	socketQueryOutput.SetPageSize(sizeof(SocketQueryOutput) * 8);

	packetAllocationPoolMutex.Lock();
	packetAllocationPool.SetPageSize(sizeof(DataStructures::MemoryPool<Packet>::MemoryWithPage) * 32);
	packetAllocationPoolMutex.Unlock();

	remoteSystemIndexPool.SetPageSize(sizeof(DataStructures::MemoryPool<RemoteSystemIndex>::MemoryWithPage) * 32);

	GenerateGUID();

	quitAndDataEvents.InitEvent();
	limitConnectionFrequencyFromTheSameIP = false;
	ResetSendReceipt();
}

// Destructor
RakPeer::~RakPeer()
{
	Shutdown(0, 0);

	ClearBanList();

	StringCompressor::RemoveReference();
	RakNet::StringTable::RemoveReference();
	WSAStartupSingleton::Deref();

	quitAndDataEvents.CloseEvent();

#if LIBCAT_SECURITY == 1
	// Encryption and security
	CAT_AUDIT_PRINTF("AUDIT: Deleting RakPeer security objects, handshake = %x, cookie jar = %x\n", _server_handshake, _cookie_jar);
	if (_server_handshake)
		RakNet::OP_DELETE(_server_handshake, _FILE_AND_LINE_);
	if (_cookie_jar)
		RakNet::OP_DELETE(_cookie_jar, _FILE_AND_LINE_);
#endif
}

Packet *RakPeer::AllocPacket(unsigned dataSize, const char *file, unsigned int line)
{
	RakNet::Packet *p;
	packetAllocationPoolMutex.Lock();
	p = packetAllocationPool.Allocate(file, line);
	packetAllocationPoolMutex.Unlock();
	p = new ((void *)p) Packet;
	p->data = (uint8_t *)rakMalloc_Ex(dataSize, file, line);
	p->length = dataSize;
	p->bitSize = BYTES_TO_BITS(dataSize);
	p->deleteData = true;
	p->guid = UNASSIGNED_RAKNET_GUID;
	p->wasGeneratedLocally = false;
	return p;
}

Packet *RakPeer::AllocPacket(unsigned dataSize, uint8_t *data, const char *file, unsigned int line)
{
	RakNet::Packet *p;
	packetAllocationPoolMutex.Lock();
	p = packetAllocationPool.Allocate(file, line);
	packetAllocationPoolMutex.Unlock();
	p = new ((void *)p) Packet;
	RakAssert(p);
	p->data = data;
	p->length = dataSize;
	p->bitSize = BYTES_TO_BITS(dataSize);
	p->deleteData = true;
	p->guid = UNASSIGNED_RAKNET_GUID;
	p->wasGeneratedLocally = false;
	return p;
}

StartupResult RakPeer::Startup(unsigned int maxConnections, SocketDescriptor *socketDescriptors, unsigned socketDescriptorCount, int threadPriority)
{
	if (IsActive())
		return RAKNET_ALREADY_STARTED;

	if (myGuid.g == 0)
	{
		GenerateGUID();

		if (myGuid.g == 0)
		{
			return COULD_NOT_GENERATE_GUID;
		}
	}

	if (threadPriority == -99999)
	{
#ifdef _WIN32
		threadPriority = 0;
#else
		threadPriority = 1000;
#endif
	}

	FillIPList();

	if (myGuid == UNASSIGNED_RAKNET_GUID)
	{
		rnr.SeedMT(GenerateSeedFromGuid());
	}

	RakAssert(socketDescriptors && socketDescriptorCount >= 1);

	if (socketDescriptors == 0 || socketDescriptorCount < 1)
		return INVALID_SOCKET_DESCRIPTORS;

	RakAssert(maxConnections > 0);

	if (maxConnections <= 0)
		return INVALID_MAX_CONNECTIONS;

	DerefAllSockets();

	int i;
	for (i = 0; i < socketDescriptorCount; i++)
	{
		RakNetSocket2 *r2 = RakNetSocket2Allocator::AllocRNS2();
		r2->SetUserConnectionSocketIndex(i);
#if defined(__native_client__)
		NativeClientBindParameters ncbp;
		RNS2_NativeClient *nativeClientSocket = (RNS2_NativeClient *)r2;
		ncbp.eventHandler = this;
		ncbp.forceHostAddress = (char *)socketDescriptors[i].hostAddress;
		ncbp.is_ipv6 = socketDescriptors[i].socketFamily == AF_INET6;
		ncbp.nativeClientInstance = socketDescriptors[i].chromeInstance;
		ncbp.port = socketDescriptors[i].port;
		nativeClientSocket->Bind(&ncbp, _FILE_AND_LINE_);
#elif defined(WINDOWS_STORE_RT)
		RNS2BindResult br;
		((RNS2_WindowsStore8 *)r2)->SetRecvEventHandler(this);
		br = ((RNS2_WindowsStore8 *)r2)->Bind(ref new Platform::String());
		if (br != BR_SUCCESS)
		{
			RakNetSocket2Allocator::DeallocRNS2(r2);
			DerefAllSockets();
			return SOCKET_FAILED_TO_BIND;
		}
#else
		if (r2->IsBerkleySocket())
		{
			RNS2_BerkleyBindParameters bbp;
			bbp.port = socketDescriptors[i].port;
			bbp.hostAddress = (char *)socketDescriptors[i].hostAddress;
			bbp.addressFamily = socketDescriptors[i].socketFamily;
			bbp.type = SOCK_DGRAM;
			bbp.protocol = socketDescriptors[i].extraSocketOptions;
			bbp.nonBlockingSocket = false;
			bbp.setBroadcast = true;
			bbp.setIPHdrIncl = false;
			bbp.doNotFragment = false;
			bbp.pollingThreadPriority = threadPriority;
			bbp.eventHandler = this;
			bbp.remotePortRakNetWasStartedOn_PS3_PS4_PSP2 = socketDescriptors[i].remotePortRakNetWasStartedOn_PS3_PSP2;
			RNS2BindResult br = ((RNS2_Berkley *)r2)->Bind(&bbp, _FILE_AND_LINE_);

			auto deallocSocket = [&] {
				RakNetSocket2Allocator::DeallocRNS2(r2);
				DerefAllSockets();
			};

			if (
#if RAKNET_SUPPORT_IPV6 == 0
				socketDescriptors[i].socketFamily != AF_INET ||
#endif
				br == BR_REQUIRES_RAKNET_SUPPORT_IPV6_DEFINE)
			{
				deallocSocket();
				return SOCKET_FAMILY_NOT_SUPPORTED;
			}
			else if (br == BR_FAILED_TO_BIND_SOCKET)
			{
				deallocSocket();
				return SOCKET_PORT_ALREADY_IN_USE;
			}
			else if (br == BR_FAILED_SEND_TEST)
			{
				deallocSocket();
				return SOCKET_FAILED_TEST_SEND;
			}
			else
			{
				RakAssert(br == BR_SUCCESS);
			}
		}
		else
		{
			RakAssert("TODO - Socket is not BerkleySocket" && 0);
		}
#endif

		socketList.Push(r2, _FILE_AND_LINE_);
	}

#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
	for (i = 0; i < socketDescriptorCount; i++)
	{
		if (socketList[i]->IsBerkleySocket())
			((RNS2_Berkley *)socketList[i])->CreateRecvPollingThread(threadPriority);
	}
#endif

	for (i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
	{
		if (ipList[i] == UNASSIGNED_SYSTEM_ADDRESS)
			break;
#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
		if (socketList[0]->IsBerkleySocket())
		{
			unsigned short port = ((RNS2_Berkley *)socketList[0])->GetBoundAddress().GetPort();
			ipList[i].SetPortHostOrder(port);
		}
#endif
	}

	if (maximumNumberOfPeers == 0)
	{
		if (maximumIncomingConnections > maxConnections)
			maximumIncomingConnections = maxConnections;

		maximumNumberOfPeers = maxConnections;

		remoteSystemList = RakNet::OP_NEW_ARRAY<RemoteSystemStruct>(maximumNumberOfPeers, _FILE_AND_LINE_);
		remoteSystemLookup = RakNet::OP_NEW_ARRAY<RemoteSystemIndex *>((unsigned int)maximumNumberOfPeers * REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE, _FILE_AND_LINE_);
		activeSystemList = RakNet::OP_NEW_ARRAY<RemoteSystemStruct *>(maximumNumberOfPeers, _FILE_AND_LINE_);

		for (i = 0; i < maximumNumberOfPeers; i++)
		{
			remoteSystemList[i].isActive = false;
			remoteSystemList[i].systemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystemList[i].guid = UNASSIGNED_RAKNET_GUID;
			remoteSystemList[i].myExternalSystemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystemList[i].connectMode = RemoteSystemStruct::NO_ACTION;
			remoteSystemList[i].MTUSize = defaultMTUSize;
			remoteSystemList[i].remoteSystemIndex = (SystemIndex)i;
#ifdef _DEBUG
			remoteSystemList[i].reliabilityLayer.ApplyNetworkSimulator(_packetloss, _minExtraPing, _extraPingVariance);
#endif

			// All entries in activeSystemList have valid pointers all the time.
			activeSystemList[i] = &remoteSystemList[i];
		}

		for (unsigned int i = 0; i < (unsigned int)maximumNumberOfPeers * REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE; i++)
		{
			remoteSystemLookup[i] = 0;
		}
	}

	if (endThreads)
	{
		updateCycleIsRunning = false;
		endThreads = false;
		firstExternalID = UNASSIGNED_SYSTEM_ADDRESS;

		ClearBufferedCommands();
		ClearBufferedPackets();
		ClearSocketQueryOutput();

		if (isMainLoopThreadActive == false)
		{
#if RAKPEER_USER_THREADED != 1

			int errorCode;

			errorCode = RakNet::RakThread::Create(UpdateNetworkLoop, this, threadPriority);

			if (errorCode != 0)
			{
				Shutdown(0, 0);
				return FAILED_TO_CREATE_NETWORK_THREAD;
			}
#endif // RAKPEER_USER_THREADED!=1
		}

#if RAKPEER_USER_THREADED != 1
		while (isMainLoopThreadActive == false)
			RakSleep(10);
#endif // RAKPEER_USER_THREADED!=1
	}

	for (i = 0; i < pluginListTS.Size(); i++)
	{
		pluginListTS[i]->OnRakPeerStartup();
	}

	for (i = 0; i < pluginListNTS.Size(); i++)
	{
		pluginListNTS[i]->OnRakPeerStartup();
	}

#ifdef USE_THREADED_SEND
	RakNet::SendToThread::AddRef();
#endif

	return RAKNET_STARTED;
}

bool RakPeer::InitializeSecurity(const char *public_key, const char *private_key, bool bRequireClientKey)
{
#if LIBCAT_SECURITY == 1
	if (endThreads == false)
		return false;

	// Copy client public key requirement flag
	_require_client_public_key = bRequireClientKey;

	if (_server_handshake)
	{
		CAT_AUDIT_PRINTF("AUDIT: Deleting old server_handshake %x\n", _server_handshake);
		RakNet::OP_DELETE(_server_handshake, _FILE_AND_LINE_);
	}
	if (_cookie_jar)
	{
		CAT_AUDIT_PRINTF("AUDIT: Deleting old cookie jar %x\n", _cookie_jar);
		RakNet::OP_DELETE(_cookie_jar, _FILE_AND_LINE_);
	}

	_server_handshake = RakNet::OP_NEW<cat::ServerEasyHandshake>(_FILE_AND_LINE_);
	_cookie_jar = RakNet::OP_NEW<cat::CookieJar>(_FILE_AND_LINE_);

	CAT_AUDIT_PRINTF("AUDIT: Created new server_handshake %x\n", _server_handshake);
	CAT_AUDIT_PRINTF("AUDIT: Created new cookie jar %x\n", _cookie_jar);
	CAT_AUDIT_PRINTF("AUDIT: Running _server_handshake->Initialize()\n");

	if (_server_handshake->Initialize(public_key, private_key))
	{
		CAT_AUDIT_PRINTF("AUDIT: Successfully initialized, filling cookie jar with goodies, storing public key and setting using security flag to true\n");

		_server_handshake->FillCookieJar(_cookie_jar);

		memcpy(my_public_key, public_key, sizeof(my_public_key));

		_using_security = true;
		return true;
	}

	CAT_AUDIT_PRINTF("AUDIT: Failure to initialize so deleting server handshake and cookie jar; also setting using_security flag = false\n");

	RakNet::OP_DELETE(_server_handshake, _FILE_AND_LINE_);
	_server_handshake = 0;
	RakNet::OP_DELETE(_cookie_jar, _FILE_AND_LINE_);
	_cookie_jar = 0;
	_using_security = false;
	return false;
#else
	(void)public_key;
	(void)private_key;
	(void)bRequireClientKey;

	return false;
#endif
}

void RakPeer::DisableSecurity(void)
{
#if LIBCAT_SECURITY == 1
	CAT_AUDIT_PRINTF("AUDIT: DisableSecurity() called, so deleting _server_handshake %x and cookie_jar %x\n", _server_handshake, _cookie_jar);
	RakNet::OP_DELETE(_server_handshake, _FILE_AND_LINE_);
	_server_handshake = 0;
	RakNet::OP_DELETE(_cookie_jar, _FILE_AND_LINE_);
	_cookie_jar = 0;

	_using_security = false;
#endif
}

void RakPeer::AddToSecurityExceptionList(const char *ip)
{
	securityExceptionMutex.Lock();
	securityExceptionList.Insert(RakString(ip), _FILE_AND_LINE_);
	securityExceptionMutex.Unlock();
}

void RakPeer::RemoveFromSecurityExceptionList(const char *ip)
{
	if (securityExceptionList.Size() == 0)
		return;

	if (ip == 0)
	{
		securityExceptionMutex.Lock();
		securityExceptionList.Clear(false, _FILE_AND_LINE_);
		securityExceptionMutex.Unlock();
	}
	else
	{
		unsigned i = 0;
		securityExceptionMutex.Lock();
		while (i < securityExceptionList.Size())
		{
			if (securityExceptionList[i].IPAddressMatch(ip))
			{
				securityExceptionList[i] = securityExceptionList[securityExceptionList.Size() - 1];
				securityExceptionList.RemoveAtIndex(securityExceptionList.Size() - 1);
			}
			else
				i++;
		}
		securityExceptionMutex.Unlock();
	}
}

bool RakPeer::IsInSecurityExceptionList(const char *ip)
{
	if (securityExceptionList.Size() == 0)
		return false;

	unsigned i = 0;
	securityExceptionMutex.Lock();
	for (; i < securityExceptionList.Size(); i++)
	{
		if (securityExceptionList[i].IPAddressMatch(ip))
		{
			securityExceptionMutex.Unlock();
			return true;
		}
	}
	securityExceptionMutex.Unlock();
	return false;
}

void RakPeer::SetMaximumIncomingConnections(unsigned short numberAllowed)
{
	maximumIncomingConnections = numberAllowed;
}

unsigned int RakPeer::GetMaximumIncomingConnections(void) const
{
	return maximumIncomingConnections;
}

unsigned short RakPeer::NumberOfConnections(void) const
{
	DataStructures::List<SystemAddress> addresses;
	DataStructures::List<RakNetGUID> guids;
	GetSystemList(addresses, guids);
	return (unsigned short)addresses.Size();
}

void RakPeer::SetIncomingPassword(const char *passwordData, int passwordDataLength)
{
	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;

	if (passwordDataLength > 0)
		memcpy(incomingPassword, passwordData, passwordDataLength);
	incomingPasswordLength = (uint8_t)passwordDataLength;
}

void RakPeer::GetIncomingPassword(char *passwordData, int *passwordDataLength)
{
	if (passwordData == 0)
	{
		*passwordDataLength = incomingPasswordLength;
		return;
	}

	if (*passwordDataLength > incomingPasswordLength)
		*passwordDataLength = incomingPasswordLength;

	if (*passwordDataLength > 0)
		memcpy(passwordData, incomingPassword, *passwordDataLength);
}

ConnectionAttemptResult RakPeer::Connect(const char *host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime)
{
	// If endThreads is true here you didn't call Startup() first.
	if (host == 0 || endThreads || connectionSocketIndex >= socketList.Size())
		return INVALID_PARAMETER;

	RakAssert(remotePort != 0);

	connectionSocketIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);

	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;

	return SendConnectionRequest(host, remotePort, passwordData, passwordDataLength, publicKey, connectionSocketIndex, 0, sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
}

ConnectionAttemptResult RakPeer::ConnectWithSocket(const char *host, unsigned short remotePort, const char *passwordData, int passwordDataLength, RakNetSocket2 *socket, PublicKey *publicKey, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime)
{
	if (host == 0 || endThreads || socket == 0)
		return INVALID_PARAMETER;

	if (passwordDataLength > 255)
		passwordDataLength = 255;

	if (passwordData == 0)
		passwordDataLength = 0;

	return SendConnectionRequest(host, remotePort, passwordData, passwordDataLength, publicKey, 0, 0, sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime, socket);
}

void RakPeer::Shutdown(unsigned int blockDuration, uint8_t orderingChannel, PacketPriority disconnectionNotificationPriority)
{
	unsigned i, j;
	bool anyActive;
	RakNet::TimeMS startWaitingTime;
	RakNet::TimeMS time;
	unsigned int systemListSize = maximumNumberOfPeers;

	if (blockDuration > 0)
	{
		for (i = 0; i < systemListSize; i++)
		{
			if (remoteSystemList[i].isActive)
				NotifyAndFlagForShutdown(remoteSystemList[i].systemAddress, false, orderingChannel, disconnectionNotificationPriority);
		}

		time = RakNet::GetTimeMS();
		startWaitingTime = time;
		while (time - startWaitingTime < blockDuration)
		{
			anyActive = false;
			for (j = 0; j < systemListSize; j++)
			{
				if (remoteSystemList[j].isActive)
				{
					anyActive = true;
					break;
				}
			}

			if (anyActive == false)
				break;

			RakSleep(15);
			time = RakNet::GetTimeMS();
		}
	}
	for (i = 0; i < pluginListTS.Size(); i++)
	{
		pluginListTS[i]->OnRakPeerShutdown();
	}
	for (i = 0; i < pluginListNTS.Size(); i++)
	{
		pluginListNTS[i]->OnRakPeerShutdown();
	}

	activeSystemListSize = 0;

	quitAndDataEvents.SetEvent();

	endThreads = true;

#if RAKPEER_USER_THREADED != 1

#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
	for (i = 0; i < socketList.Size(); i++)
	{
		if (socketList[i]->IsBerkleySocket())
		{
			((RNS2_Berkley *)socketList[i])->SignalStopRecvPollingThread();
		}
	}
#endif

	while (isMainLoopThreadActive)
	{
		endThreads = true;
		RakSleep(15);
	}

#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
	for (i = 0; i < socketList.Size(); i++)
	{
		if (socketList[i]->IsBerkleySocket())
		{
			((RNS2_Berkley *)socketList[i])->BlockOnStopRecvPollingThread();
		}
	}
#endif

#endif // RAKPEER_USER_THREADED!=1

	for (i = 0; i < systemListSize; i++)
	{
		remoteSystemList[i].isActive = false;

		RakAssert(remoteSystemList[i].MTUSize <= MAXIMUM_MTU_SIZE);
		remoteSystemList[i].reliabilityLayer.Reset(false, remoteSystemList[i].MTUSize, false);
		remoteSystemList[i].rakNetSocket = 0;
	}

	maximumNumberOfPeers = 0;

	packetReturnMutex.Lock();
	for (i = 0; i < packetReturnQueue.Size(); i++)
		DeallocatePacket(packetReturnQueue[i]);
	packetReturnQueue.Clear(_FILE_AND_LINE_);
	packetReturnMutex.Unlock();
	packetAllocationPoolMutex.Lock();
	packetAllocationPool.Clear(_FILE_AND_LINE_);
	packetAllocationPoolMutex.Unlock();

	DerefAllSockets();

	ClearBufferedCommands();
	ClearBufferedPackets();
	ClearSocketQueryOutput();
	bytesSentPerSecond = bytesReceivedPerSecond = 0;

	ClearRequestedConnectionList();

	RemoteSystemStruct *temp = remoteSystemList;
	remoteSystemList = 0;
	RakNet::OP_DELETE_ARRAY(temp, _FILE_AND_LINE_);
	RakNet::OP_DELETE_ARRAY(activeSystemList, _FILE_AND_LINE_);
	activeSystemList = 0;

	ClearRemoteSystemLookup();

#ifdef USE_THREADED_SEND
	RakNet::SendToThread::Deref();
#endif

	ResetSendReceipt();
}

inline bool RakPeer::IsActive(void) const
{
	return endThreads == false;
}

bool RakPeer::GetConnectionList(SystemAddress *remoteSystems, unsigned short *numberOfSystems) const
{
	if (numberOfSystems == 0)
		return false;

	if (remoteSystemList == 0 || endThreads == true)
	{
		if (numberOfSystems)
			*numberOfSystems = 0;
		return false;
	}

	DataStructures::List<SystemAddress> addresses;
	DataStructures::List<RakNetGUID> guids;
	GetSystemList(addresses, guids);
	if (remoteSystems)
	{
		unsigned short i;
		for (i = 0; i < *numberOfSystems && i < addresses.Size(); i++)
			remoteSystems[i] = addresses[i];
		*numberOfSystems = i;
	}
	else
	{
		*numberOfSystems = (unsigned short)addresses.Size();
	}
	return true;
}

uint32_t RakPeer::GetNextSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	uint32_t retVal = sendReceiptSerial;
	sendReceiptSerialMutex.Unlock();
	return retVal;
}

uint32_t RakPeer::IncrementNextSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	uint32_t returned = sendReceiptSerial;
	if (++sendReceiptSerial == 0)
		sendReceiptSerial = 1;
	sendReceiptSerialMutex.Unlock();
	return returned;
}

uint32_t RakPeer::Send(const char *data, const int length, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber)
{
#ifdef _DEBUG
	RakAssert(data && length > 0);
#endif
	RakAssert(!(reliability >= NUMBER_OF_RELIABILITIES || reliability < 0));
	RakAssert(!(priority > NUMBER_OF_PRIORITIES || priority < 0));
	RakAssert(!(orderingChannel >= NUMBER_OF_ORDERED_STREAMS));

	if (data == 0 || length < 0)
		return 0;

	if (remoteSystemList == 0 || endThreads == true)
		return 0;

	if (broadcast == false && systemIdentifier.IsUndefined())
		return 0;

	uint32_t usedSendReceipt;
	if (forceReceiptNumber != 0)
		usedSendReceipt = forceReceiptNumber;
	else
		usedSendReceipt = IncrementNextSendReceipt();

	if (broadcast == false && IsLoopbackAddress(systemIdentifier, true))
	{
		SendLoopback(data, length);

		if (reliability >= UNRELIABLE_WITH_ACK_RECEIPT)
		{
			char buff[5];
			buff[0] = ID_SND_RECEIPT_ACKED;
			sendReceiptSerialMutex.Lock();
			memcpy(buff + 1, &sendReceiptSerial, 4);
			sendReceiptSerialMutex.Unlock();
			SendLoopback(buff, 5);
		}

		return usedSendReceipt;
	}

	SendBuffered(data, length * 8, priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);

	return usedSendReceipt;
}

void RakPeer::SendLoopback(const char *data, const int length)
{
	if (data == 0 || length < 0)
		return;

	Packet *packet = AllocPacket(length, _FILE_AND_LINE_);
	memcpy(packet->data, data, length);
	packet->systemAddress = GetLoopbackAddress();
	packet->guid = myGuid;
	PushBackPacket(packet, false);
}

uint32_t RakPeer::Send(const RakNet::BitStream *bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber)
{
#ifdef _DEBUG
	RakAssert(bitStream->GetNumberOfBytesUsed() > 0);
#endif

	RakAssert(!(reliability >= NUMBER_OF_RELIABILITIES || reliability < 0));
	RakAssert(!(priority > NUMBER_OF_PRIORITIES || priority < 0));
	RakAssert(!(orderingChannel >= NUMBER_OF_ORDERED_STREAMS));

	if (bitStream->GetNumberOfBytesUsed() == 0)
		return 0;

	if (remoteSystemList == 0 || endThreads == true)
		return 0;

	if (broadcast == false && systemIdentifier.IsUndefined())
		return 0;

	uint32_t usedSendReceipt;
	if (forceReceiptNumber != 0)
		usedSendReceipt = forceReceiptNumber;
	else
		usedSendReceipt = IncrementNextSendReceipt();

	if (broadcast == false && IsLoopbackAddress(systemIdentifier, true))
	{
		SendLoopback((const char *)bitStream->GetData(), bitStream->GetNumberOfBytesUsed());
		if (reliability >= UNRELIABLE_WITH_ACK_RECEIPT)
		{
			char buff[5];
			buff[0] = ID_SND_RECEIPT_ACKED;
			sendReceiptSerialMutex.Lock();
			memcpy(buff + 1, &sendReceiptSerial, 4);
			sendReceiptSerialMutex.Unlock();
			SendLoopback(buff, 5);
		}
		return usedSendReceipt;
	}

	SendBuffered((const char *)bitStream->GetData(), bitStream->GetNumberOfBitsUsed(), priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);

	return usedSendReceipt;
}

uint32_t RakPeer::SendList(const char **data, const int *lengths, const int numParameters, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber)
{
#ifdef _DEBUG
	RakAssert(data);
#endif

	if (data == 0 || lengths == 0)
		return 0;

	if (remoteSystemList == 0 || endThreads == true)
		return 0;

	if (numParameters == 0)
		return 0;

	if (lengths == 0)
		return 0;

	if (broadcast == false && systemIdentifier.IsUndefined())
		return 0;

	uint32_t usedSendReceipt;
	if (forceReceiptNumber != 0)
		usedSendReceipt = forceReceiptNumber;
	else
		usedSendReceipt = IncrementNextSendReceipt();

	SendBufferedList(data, lengths, numParameters, priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);

	return usedSendReceipt;
}

Packet *RakPeer::Receive(void)
{
	if (!(IsActive()))
		return nullptr;

	RakNet::Packet *packet = nullptr;
	PluginReceiveResult pluginResult;

	int offset;
	unsigned int i;

	for (i = 0; i < pluginListTS.Size(); ++i)
	{
		pluginListTS[i]->Update();
	}
	for (i = 0; i < pluginListNTS.Size(); ++i)
	{
		pluginListNTS[i]->Update();
	}

	do
	{
		packetReturnMutex.Lock();
		if (packetReturnQueue.IsEmpty())
			packet = nullptr;
		else
			packet = packetReturnQueue.Pop();
		packetReturnMutex.Unlock();
		if (packet == nullptr)
			return nullptr;

		if ((packet->length >= sizeof(uint8_t) + sizeof(RakNet::Time)) &&
			((uint8_t)packet->data[0] == ID_TIMESTAMP))
		{
			offset = sizeof(uint8_t);
			ShiftIncomingTimestamp(packet->data + offset, packet->systemAddress);
		}

		CallPluginCallbacks(pluginListTS, packet);
		CallPluginCallbacks(pluginListNTS, packet);

		auto callPluginOnReceive = [&] (auto plugin) {
			pluginResult = plugin->OnReceive(packet);
			if (pluginResult == RR_STOP_PROCESSING_AND_DEALLOCATE)
			{
				DeallocatePacket(packet);
				packet = nullptr;
				return true;
			}
			else if (pluginResult == RR_STOP_PROCESSING)
			{
				packet = nullptr;
				return true;
			}
			return false;
		};

		for (i = 0; i < pluginListTS.Size(); ++i)
		{
			if (callPluginOnReceive(pluginListTS[i]))
			{
				break;
			}
		}

		for (i = 0; i < pluginListNTS.Size(); ++i)
		{
			if (callPluginOnReceive(pluginListTS[i]))
			{
				break;
			}
		}

	} while (packet == nullptr);

#ifdef _DEBUG
	RakAssert(packet->data);
#endif

	return packet;
}

void RakPeer::DeallocatePacket(Packet *packet)
{
	if (packet == nullptr)
		return;

	if (packet->deleteData)
	{
		rakFree_Ex(packet->data, _FILE_AND_LINE_);
		packet->~Packet();
		packetAllocationPoolMutex.Lock();
		packetAllocationPool.Release(packet, _FILE_AND_LINE_);
		packetAllocationPoolMutex.Unlock();
	}
	else
	{
		rakFree_Ex(packet, _FILE_AND_LINE_);
	}
}

unsigned int RakPeer::GetMaximumNumberOfPeers(void) const
{
	return maximumNumberOfPeers;
}

void RakPeer::CloseConnection(const AddressOrGUID target, bool sendDisconnectionNotification, uint8_t orderingChannel, PacketPriority disconnectionNotificationPriority)
{
	CloseConnectionInternal(target, sendDisconnectionNotification, false, orderingChannel, disconnectionNotificationPriority);

	// 12/14/09 Return ID_CONNECTION_LOST when calling CloseConnection with sendDisconnectionNotification==false, elsewise it is never returned
	if (sendDisconnectionNotification == false && GetConnectionState(target) == IS_CONNECTED)
	{
		Packet *packet = AllocPacket(sizeof(char), _FILE_AND_LINE_);
		packet->data[0] = ID_CONNECTION_LOST; // DeadConnection
		packet->guid = target.rakNetGuid == UNASSIGNED_RAKNET_GUID ? GetGuidFromSystemAddress(target.systemAddress) : target.rakNetGuid;
		packet->systemAddress = target.systemAddress == UNASSIGNED_SYSTEM_ADDRESS ? GetSystemAddressFromGuid(target.rakNetGuid) : target.systemAddress;
		packet->systemAddress.systemIndex = (SystemIndex)GetIndexFromSystemAddress(packet->systemAddress);
		packet->guid.systemIndex = packet->systemAddress.systemIndex;
		packet->wasGeneratedLocally = true; // else processed twice
		AddPacketToProducer(packet);
	}
}

void RakPeer::CancelConnectionAttempt(const SystemAddress target)
{
	unsigned int i = 0;

	requestedConnectionQueueMutex.Lock();
	while (i < requestedConnectionQueue.Size())
	{
		if (requestedConnectionQueue[i]->systemAddress == target)
		{
#if LIBCAT_SECURITY == 1
			CAT_AUDIT_PRINTF("AUDIT: Deleting requestedConnectionQueue %i client_handshake %x\n", i, requestedConnectionQueue[i]->client_handshake);
			RakNet::OP_DELETE(requestedConnectionQueue[i]->client_handshake, _FILE_AND_LINE_);
#endif
			RakNet::OP_DELETE(requestedConnectionQueue[i], _FILE_AND_LINE_);
			requestedConnectionQueue.RemoveAtIndex(i);
			break;
		}
		else
			i++;
	}
	requestedConnectionQueueMutex.Unlock();
}

ConnectionState RakPeer::GetConnectionState(const AddressOrGUID systemIdentifier)
{
	if (systemIdentifier.systemAddress != UNASSIGNED_SYSTEM_ADDRESS)
	{
		requestedConnectionQueueMutex.Lock();
		for (unsigned int i = 0; i < requestedConnectionQueue.Size(); i++)
		{
			if (requestedConnectionQueue[i]->systemAddress == systemIdentifier.systemAddress)
			{
				requestedConnectionQueueMutex.Unlock();
				return IS_PENDING;
			}
		}
		requestedConnectionQueueMutex.Unlock();
	}

	int index;
	if (systemIdentifier.systemAddress != UNASSIGNED_SYSTEM_ADDRESS)
	{
		index = GetIndexFromSystemAddress(systemIdentifier.systemAddress, false);
	}
	else
	{
		index = GetIndexFromGuid(systemIdentifier.rakNetGuid);
	}

	if (index == -1)
		return IS_NOT_CONNECTED;

	if (remoteSystemList[index].isActive == false)
		return IS_DISCONNECTED;

	ConnectionState result = IS_NOT_CONNECTED;

	switch (remoteSystemList[index].connectMode)
	{
	case RemoteSystemStruct::DISCONNECT_ASAP:
		result = IS_DISCONNECTING;
		break;
	case RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY:
		result = IS_SILENTLY_DISCONNECTING;
		break;
	case RemoteSystemStruct::DISCONNECT_ON_NO_ACK:
		result = IS_DISCONNECTING;
		break;
	case RemoteSystemStruct::REQUESTED_CONNECTION:
	case RemoteSystemStruct::HANDLING_CONNECTION_REQUEST:
	case RemoteSystemStruct::UNVERIFIED_SENDER:
		result = IS_CONNECTING;
		break;
	case RemoteSystemStruct::CONNECTED:
		result = IS_CONNECTED;
		break;
	default:
		result = IS_NOT_CONNECTED;
		break;
	}

	return result;
}

int RakPeer::GetIndexFromSystemAddress(const SystemAddress systemAddress) const
{
	return GetIndexFromSystemAddress(systemAddress, false);
}

SystemAddress RakPeer::GetSystemAddressFromIndex(unsigned int index)
{
	if (index < maximumNumberOfPeers)
		if (remoteSystemList[index].isActive && remoteSystemList[index].connectMode == RakPeer::RemoteSystemStruct::CONNECTED) // Don't give the user players that aren't fully connected, since sends will fail
			return remoteSystemList[index].systemAddress;

	return UNASSIGNED_SYSTEM_ADDRESS;
}

RakNetGUID RakPeer::GetGUIDFromIndex(unsigned int index)
{
	if (index < maximumNumberOfPeers)
		if (remoteSystemList[index].isActive && remoteSystemList[index].connectMode == RakPeer::RemoteSystemStruct::CONNECTED) // Don't give the user players that aren't fully connected, since sends will fail
			return remoteSystemList[index].guid;

	return UNASSIGNED_RAKNET_GUID;
}

void RakPeer::GetSystemList(DataStructures::List<SystemAddress> &addresses, DataStructures::List<RakNetGUID> &guids) const
{
	addresses.Clear(false, _FILE_AND_LINE_);
	guids.Clear(false, _FILE_AND_LINE_);

	if (remoteSystemList == 0 || endThreads == true)
		return;

	for (unsigned int i = 0; i < activeSystemListSize; ++i)
	{
		if ((activeSystemList[i])->isActive &&
			(activeSystemList[i])->connectMode == RakPeer::RemoteSystemStruct::CONNECTED)
		{
			addresses.Push((activeSystemList[i])->systemAddress, _FILE_AND_LINE_);
			guids.Push((activeSystemList[i])->guid, _FILE_AND_LINE_);
		}
	}
}

void RakPeer::AddToBanList(const char *IP, RakNet::TimeMS milliseconds)
{
	unsigned index;
	RakNet::TimeMS time = RakNet::GetTimeMS();

	if (IP == 0 || IP[0] == 0 || strlen(IP) > 15)
		return;

	index = 0;

	banListMutex.Lock();

	for (; index < banList.Size(); index++)
	{
		if (strcmp(IP, banList[index]->IP) == 0)
		{
			// Already in the ban list.  Just update the time
			if (milliseconds == 0)
				banList[index]->timeout = 0; // Infinite
			else
				banList[index]->timeout = time + milliseconds;
			banListMutex.Unlock();
			return;
		}
	}

	banListMutex.Unlock();

	BanStruct *banStruct = RakNet::OP_NEW<BanStruct>(_FILE_AND_LINE_);
	banStruct->IP = (char *)rakMalloc_Ex(16, _FILE_AND_LINE_);
	if (milliseconds == 0)
		banStruct->timeout = 0; // Infinite
	else
		banStruct->timeout = time + milliseconds;
	strcpy(banStruct->IP, IP);
	banListMutex.Lock();
	banList.Insert(banStruct, _FILE_AND_LINE_);
	banListMutex.Unlock();
}

void RakPeer::RemoveFromBanList(const char *IP)
{
	unsigned index;
	BanStruct *temp;

	if (IP == 0 || IP[0] == 0 || strlen(IP) > 15)
		return;

	index = 0;
	temp = 0;

	banListMutex.Lock();

	for (; index < banList.Size(); index++)
	{
		if (strcmp(IP, banList[index]->IP) == 0)
		{
			temp = banList[index];
			banList[index] = banList[banList.Size() - 1];
			banList.RemoveAtIndex(banList.Size() - 1);
			break;
		}
	}

	banListMutex.Unlock();

	if (temp)
	{
		rakFree_Ex(temp->IP, _FILE_AND_LINE_);
		RakNet::OP_DELETE(temp, _FILE_AND_LINE_);
	}
}

void RakPeer::ClearBanList(void)
{
	unsigned index = 0;
	banListMutex.Lock();

	for (; index < banList.Size(); index++)
	{
		rakFree_Ex(banList[index]->IP, _FILE_AND_LINE_);
		RakNet::OP_DELETE(banList[index], _FILE_AND_LINE_);
	}

	banList.Clear(false, _FILE_AND_LINE_);

	banListMutex.Unlock();
}

void RakPeer::SetLimitIPConnectionFrequency(bool b)
{
	limitConnectionFrequencyFromTheSameIP = b;
}

bool RakPeer::IsBanned(const char *IP)
{
	unsigned banListIndex, characterIndex;
	RakNet::TimeMS time;
	BanStruct *temp;

	if (IP == 0 || IP[0] == 0 || strlen(IP) > 15)
		return false;

	banListIndex = 0;

	if (banList.Size() == 0)
		return false; // Skip the mutex if possible

	time = RakNet::GetTimeMS();

	banListMutex.Lock();

	bool matchFound = false;

	while (banListIndex < banList.Size())
	{
		if (banList[banListIndex]->timeout > 0 && banList[banListIndex]->timeout < time)
		{
			// Delete expired ban
			temp = banList[banListIndex];
			banList[banListIndex] = banList[banList.Size() - 1];
			banList.RemoveAtIndex(banList.Size() - 1);
			rakFree_Ex(temp->IP, _FILE_AND_LINE_);
			RakNet::OP_DELETE(temp, _FILE_AND_LINE_);
		}
		else
		{
			characterIndex = 0;

			while (!matchFound)
			{
				if (banList[banListIndex]->IP[characterIndex] == IP[characterIndex])
				{
					// Equal characters

					if (IP[characterIndex] == 0)
					{
						banListMutex.Unlock();
						// End of the string and the strings match

						matchFound = true;
						break;
					}

					characterIndex++;
				}

				else
				{
					if (banList[banListIndex]->IP[characterIndex] == 0 || IP[characterIndex] == 0)
					{
						// End of one of the strings
						break;
					}

					// Characters do not match
					if (banList[banListIndex]->IP[characterIndex] == '*')
					{
						banListMutex.Unlock();

						// Domain is banned.
						matchFound = true;
						break;
					}

					// Characters do not match and it is not a *
					break;
				}
			}

			banListIndex++;
		}
	}

	banListMutex.Unlock();

	return matchFound;
}

void RakPeer::Ping(const SystemAddress target)
{
	PingInternal(target, false, UNRELIABLE);
}

bool RakPeer::Ping(const char *host, unsigned short remotePort, bool onlyReplyOnAcceptingConnections, unsigned connectionSocketIndex)
{
	if (host == 0)
		return false;

	// If this assert hits then Startup wasn't called or the call failed.
	RakAssert(connectionSocketIndex < socketList.Size());

	RakNet::BitStream bitStream(sizeof(uint8_t) + sizeof(RakNet::Time));
	if (onlyReplyOnAcceptingConnections)
		bitStream.Write<MessageID>(ID_UNCONNECTED_PING_OPEN_CONNECTIONS);
	else
		bitStream.Write<MessageID>(ID_UNCONNECTED_PING);

	bitStream.Write<RakNet::Time>(RakNet::GetTime());

	bitStream.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));

	bitStream.Write<RakNetGUID>(GetMyGUID());

	// No timestamp for 255.255.255.255
	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);

	RNS2_SendParameters bsp;
	bsp.data = (char *)bitStream.GetData();
	bsp.length = bitStream.GetNumberOfBytesUsed();
	bsp.systemAddress.FromStringExplicitPort(host, remotePort, socketList[realIndex]->GetBoundAddress().GetIPVersion());
	if (bsp.systemAddress == UNASSIGNED_SYSTEM_ADDRESS)
		return false;
	bsp.systemAddress.FixForIPVersion(socketList[realIndex]->GetBoundAddress());
	for (unsigned i = 0; i < pluginListNTS.Size(); i++)
		pluginListNTS[i]->OnDirectSocketSend((const char *)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), bsp.systemAddress);
	socketList[realIndex]->Send(&bsp, _FILE_AND_LINE_);

	return true;
}

int RakPeer::GetAveragePing(const AddressOrGUID systemIdentifier)
{
	int sum, quantity;
	RemoteSystemStruct *remoteSystem = GetRemoteSystem(systemIdentifier, false, false);

	if (remoteSystem == 0)
		return -1;

	for (sum = 0, quantity = 0; quantity < PING_TIMES_ARRAY_SIZE; quantity++)
	{
		if (remoteSystem->pingAndClockDifferential[quantity].pingTime == 65535)
			break;
		else
			sum += remoteSystem->pingAndClockDifferential[quantity].pingTime;
	}

	if (quantity > 0)
		return sum / quantity;
	else
		return -1;
}

int RakPeer::GetLastPing(const AddressOrGUID systemIdentifier) const
{
	RemoteSystemStruct *remoteSystem = GetRemoteSystem(systemIdentifier, false, false);

	if (remoteSystem == 0)
		return -1;

	if (remoteSystem->pingAndClockDifferentialWriteIndex == 0)
		return remoteSystem->pingAndClockDifferential[PING_TIMES_ARRAY_SIZE - 1].pingTime;
	else
		return remoteSystem->pingAndClockDifferential[remoteSystem->pingAndClockDifferentialWriteIndex - 1].pingTime;
}

int RakPeer::GetLowestPing(const AddressOrGUID systemIdentifier) const
{
	RemoteSystemStruct *remoteSystem = GetRemoteSystem(systemIdentifier, false, false);

	if (remoteSystem == 0)
		return -1;

	return remoteSystem->lowestPing;
}

void RakPeer::SetOccasionalPing(bool doPing)
{
	occasionalPing = doPing;
}

RakNet::Time RakPeer::GetClockDifferential(const AddressOrGUID systemIdentifier)
{
	RemoteSystemStruct *remoteSystem = GetRemoteSystem(systemIdentifier, false, false);
	if (remoteSystem == 0)
		return 0;
	return GetClockDifferentialInt(remoteSystem);
}

RakNet::Time RakPeer::GetClockDifferentialInt(RemoteSystemStruct *remoteSystem) const
{
	int counter, lowestPingSoFar;
	RakNet::Time clockDifferential;

	lowestPingSoFar = 65535;

	clockDifferential = 0;

	for (counter = 0; counter < PING_TIMES_ARRAY_SIZE; counter++)
	{
		if (remoteSystem->pingAndClockDifferential[counter].pingTime == 65535)
			break;

		if (remoteSystem->pingAndClockDifferential[counter].pingTime < lowestPingSoFar)
		{
			clockDifferential = remoteSystem->pingAndClockDifferential[counter].clockDifferential;
			lowestPingSoFar = remoteSystem->pingAndClockDifferential[counter].pingTime;
		}
	}

	return clockDifferential;
}

void RakPeer::SetOfflinePingResponse(const char *data, const unsigned int length)
{
	RakAssert(length < 400);

	rakPeerMutexes[offlinePingResponse_Mutex].Lock();
	offlinePingResponse.Reset();

	if (data && length > 0)
		offlinePingResponse.Write(data, length);

	rakPeerMutexes[offlinePingResponse_Mutex].Unlock();
}

void RakPeer::GetOfflinePingResponse(char **data, unsigned int *length)
{
	rakPeerMutexes[offlinePingResponse_Mutex].Lock();
	*data = (char *)offlinePingResponse.GetData();
	*length = (int)offlinePingResponse.GetNumberOfBytesUsed();
	rakPeerMutexes[offlinePingResponse_Mutex].Unlock();
}

SystemAddress RakPeer::GetInternalID(const SystemAddress systemAddress, const int index) const
{
	if (systemAddress == UNASSIGNED_SYSTEM_ADDRESS)
	{
		return ipList[index];
	}
	else
	{
		RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(systemAddress, false, true);
		if (remoteSystem == 0)
			return UNASSIGNED_SYSTEM_ADDRESS;

		return remoteSystem->theirInternalSystemAddress[index];
	}
}

void RakPeer::SetInternalID(SystemAddress systemAddress, int index)
{
	RakAssert(index >= 0 && index < MAXIMUM_NUMBER_OF_INTERNAL_IDS);
	ipList[index] = systemAddress;
}

SystemAddress RakPeer::GetExternalID(const SystemAddress target) const
{
	unsigned i;
	SystemAddress inactiveExternalId;

	inactiveExternalId = UNASSIGNED_SYSTEM_ADDRESS;

	if (target == UNASSIGNED_SYSTEM_ADDRESS)
		return firstExternalID;

	// First check for active connection with this systemAddress
	for (i = 0; i < maximumNumberOfPeers; i++)
	{
		if (remoteSystemList[i].systemAddress == target)
		{
			if (remoteSystemList[i].isActive)
				return remoteSystemList[i].myExternalSystemAddress;
			else if (remoteSystemList[i].myExternalSystemAddress != UNASSIGNED_SYSTEM_ADDRESS)
				inactiveExternalId = remoteSystemList[i].myExternalSystemAddress;
		}
	}

	return inactiveExternalId;
}

const RakNetGUID RakPeer::GetMyGUID(void) const
{
	return myGuid;
}

SystemAddress RakPeer::GetMyBoundAddress(const int socketIndex)
{
	DataStructures::List<RakNetSocket2 *> sockets;
	GetSockets(sockets);
	if (sockets.Size() > 0)
		return sockets[socketIndex]->GetBoundAddress();
	else
		return UNASSIGNED_SYSTEM_ADDRESS;
}

const RakNetGUID &RakPeer::GetGuidFromSystemAddress(const SystemAddress input) const
{
	if (input == UNASSIGNED_SYSTEM_ADDRESS)
		return myGuid;

	if (input.systemIndex != (SystemIndex)-1 && input.systemIndex < maximumNumberOfPeers && remoteSystemList[input.systemIndex].systemAddress == input)
		return remoteSystemList[input.systemIndex].guid;

	for (unsigned int i = 0; i < maximumNumberOfPeers; i++)
	{
		if (remoteSystemList[i].systemAddress == input)
		{
			// Set the systemIndex so future lookups will be fast
			remoteSystemList[i].guid.systemIndex = (SystemIndex)i;

			return remoteSystemList[i].guid;
		}
	}

	return UNASSIGNED_RAKNET_GUID;
}

unsigned int RakPeer::GetSystemIndexFromGuid(const RakNetGUID input) const
{
	if (input == UNASSIGNED_RAKNET_GUID)
		return (unsigned int)-1;

	if (input == myGuid)
		return (unsigned int)-1;

	if (input.systemIndex != (SystemIndex)-1 && input.systemIndex < maximumNumberOfPeers && remoteSystemList[input.systemIndex].guid == input)
		return input.systemIndex;

	unsigned int i;
	for (i = 0; i < maximumNumberOfPeers; i++)
	{
		if (remoteSystemList[i].guid == input)
		{
			// Set the systemIndex so future lookups will be fast
			remoteSystemList[i].guid.systemIndex = (SystemIndex)i;

			return i;
		}
	}

	return (unsigned int)-1;
}

SystemAddress RakPeer::GetSystemAddressFromGuid(const RakNetGUID input) const
{
	if (input == UNASSIGNED_RAKNET_GUID)
		return UNASSIGNED_SYSTEM_ADDRESS;

	if (input == myGuid)
		return GetInternalID(UNASSIGNED_SYSTEM_ADDRESS);

	if (input.systemIndex != (SystemIndex)-1 && input.systemIndex < maximumNumberOfPeers && remoteSystemList[input.systemIndex].guid == input)
		return remoteSystemList[input.systemIndex].systemAddress;

	unsigned int i;
	for (i = 0; i < maximumNumberOfPeers; i++)
	{
		if (remoteSystemList[i].guid == input)
		{
			// Set the systemIndex so future lookups will be fast
			remoteSystemList[i].guid.systemIndex = (SystemIndex)i;

			return remoteSystemList[i].systemAddress;
		}
	}

	return UNASSIGNED_SYSTEM_ADDRESS;
}

bool RakPeer::GetClientPublicKeyFromSystemAddress(const SystemAddress input, char *client_public_key) const
{
#if LIBCAT_SECURITY == 1
	if (input == UNASSIGNED_SYSTEM_ADDRESS)
		return false;

	char *copy_source = 0;

	if (input.systemIndex != (SystemIndex)-1 && input.systemIndex < maximumNumberOfPeers && remoteSystemList[input.systemIndex].systemAddress == input)
	{
		copy_source = remoteSystemList[input.systemIndex].client_public_key;
	}
	else
	{
		for (unsigned int i = 0; i < maximumNumberOfPeers; i++)
		{
			if (remoteSystemList[i].systemAddress == input)
			{
				copy_source = remoteSystemList[i].client_public_key;
				break;
			}
		}
	}

	if (copy_source)
	{
		// Verify that at least one byte in the public key is non-zero to indicate that the key was received
		for (int ii = 0; ii < cat::EasyHandshake::PUBLIC_KEY_BYTES; ++ii)
		{
			if (copy_source[ii] != 0)
			{
				memcpy(client_public_key, copy_source, cat::EasyHandshake::PUBLIC_KEY_BYTES);
				return true;
			}
		}
	}

#else
	(void)input;
	(void)client_public_key;
#endif

	return false;
}

void RakPeer::SetTimeoutTime(RakNet::TimeMS timeMS, const SystemAddress target)
{
	if (target == UNASSIGNED_SYSTEM_ADDRESS)
	{
		defaultTimeoutTime = timeMS;

		unsigned i;
		for (i = 0; i < maximumNumberOfPeers; i++)
		{
			if (remoteSystemList[i].isActive)
			{
				if (remoteSystemList[i].isActive)
					remoteSystemList[i].reliabilityLayer.SetTimeoutTime(timeMS);
			}
		}
	}
	else
	{
		RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(target, false, true);

		if (remoteSystem != 0)
			remoteSystem->reliabilityLayer.SetTimeoutTime(timeMS);
	}
}

RakNet::TimeMS RakPeer::GetTimeoutTime(const SystemAddress target)
{
	if (target == UNASSIGNED_SYSTEM_ADDRESS)
	{
		return defaultTimeoutTime;
	}
	else
	{
		RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(target, false, true);

		if (remoteSystem != 0)
			remoteSystem->reliabilityLayer.GetTimeoutTime();
	}
	return defaultTimeoutTime;
}

int RakPeer::GetMTUSize(const SystemAddress target) const
{
	if (target != UNASSIGNED_SYSTEM_ADDRESS)
	{
		RemoteSystemStruct *rss = GetRemoteSystemFromSystemAddress(target, false, true);
		if (rss)
			return rss->MTUSize;
	}
	return defaultMTUSize;
}

unsigned int RakPeer::GetNumberOfAddresses(void)
{

	if (IsActive() == false)
	{
		FillIPList();
	}

	int i = 0;

	while (ipList[i] != UNASSIGNED_SYSTEM_ADDRESS)
		i++;

	return i;
}

const char *RakPeer::GetLocalIP(unsigned int index)
{
	if (IsActive() == false)
	{
		FillIPList();
	}

	static char str[128];
	ipList[index].ToString(false, str);
	return str;
}

bool RakPeer::IsLocalIP(const char *ip)
{
	if (ip == 0 || ip[0] == 0)
		return false;

	if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "localhost") == 0)
		return true;

	int num = GetNumberOfAddresses();
	int i;
	for (i = 0; i < num; i++)
	{
		if (strcmp(ip, GetLocalIP(i)) == 0)
			return true;
	}

	return false;
}

void RakPeer::AllowConnectionResponseIPMigration(bool allow)
{
	allowConnectionResponseIPMigration = allow;
}

bool RakPeer::AdvertiseSystem(const char *host, unsigned short remotePort, const char *data, int dataLength, unsigned connectionSocketIndex)
{
	RakNet::BitStream bs;
	bs.Write<MessageID>(ID_ADVERTISE_SYSTEM);
	bs.WriteAlignedBytes((const uint8_t *)data, dataLength);
	return SendOutOfBand(host, remotePort, (const char *)bs.GetData(), bs.GetNumberOfBytesUsed(), connectionSocketIndex);
}

void RakPeer::SetSplitMessageProgressInterval(int interval)
{
	RakAssert(interval >= 0);
	splitMessageProgressInterval = interval;
	for (unsigned short i = 0; i < maximumNumberOfPeers; i++)
		remoteSystemList[i].reliabilityLayer.SetSplitMessageProgressInterval(splitMessageProgressInterval);
}

int RakPeer::GetSplitMessageProgressInterval(void) const
{
	return splitMessageProgressInterval;
}

void RakPeer::SetUnreliableTimeout(RakNet::TimeMS timeoutMS)
{
	unreliableTimeout = timeoutMS;
	for (unsigned short i = 0; i < maximumNumberOfPeers; i++)
		remoteSystemList[i].reliabilityLayer.SetUnreliableTimeout(unreliableTimeout);
}

void RakPeer::SendTTL(const char *host, unsigned short remotePort, int ttl, unsigned connectionSocketIndex)
{
#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
	char fakeData[2];
	fakeData[0] = 0;
	fakeData[1] = 1;
	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);
	if (socketList[realIndex]->IsBerkleySocket())
	{
		RNS2_SendParameters bsp;
		bsp.data = (char *)fakeData;
		bsp.length = 2;
		bsp.systemAddress.FromStringExplicitPort(host, remotePort, socketList[realIndex]->GetBoundAddress().GetIPVersion());
		bsp.systemAddress.FixForIPVersion(socketList[realIndex]->GetBoundAddress());
		bsp.ttl = ttl;
		unsigned i;
		for (i = 0; i < pluginListNTS.Size(); i++)
			pluginListNTS[i]->OnDirectSocketSend((const char *)bsp.data, BYTES_TO_BITS(bsp.length), bsp.systemAddress);
		socketList[realIndex]->Send(&bsp, _FILE_AND_LINE_);
	}
#endif
}

void RakPeer::AttachPlugin(PluginInterface2 *plugin)
{
	bool isNotThreadsafe = plugin->UsesReliabilityLayer();
	if (isNotThreadsafe)
	{
		if (pluginListNTS.GetIndexOf(plugin) == MAX_UNSIGNED_LONG)
		{
			plugin->SetRakPeerInterface(this);
			plugin->OnAttach();
			pluginListNTS.Insert(plugin, _FILE_AND_LINE_);
		}
	}
	else
	{
		if (pluginListTS.GetIndexOf(plugin) == MAX_UNSIGNED_LONG)
		{
			plugin->SetRakPeerInterface(this);
			plugin->OnAttach();
			pluginListTS.Insert(plugin, _FILE_AND_LINE_);
		}
	}
}

void RakPeer::DetachPlugin(PluginInterface2 *plugin)
{
	if (plugin == 0)
		return;

	unsigned int index;

	bool isNotThreadsafe = plugin->UsesReliabilityLayer();
	if (isNotThreadsafe)
	{
		index = pluginListNTS.GetIndexOf(plugin);
		if (index != MAX_UNSIGNED_LONG)
		{
			// Unordered list so delete from end for speed
			pluginListNTS[index] = pluginListNTS[pluginListNTS.Size() - 1];
			pluginListNTS.RemoveFromEnd();
		}
	}
	else
	{
		index = pluginListTS.GetIndexOf(plugin);
		if (index != MAX_UNSIGNED_LONG)
		{
			// Unordered list so delete from end for speed
			pluginListTS[index] = pluginListTS[pluginListTS.Size() - 1];
			pluginListTS.RemoveFromEnd();
		}
	}
	plugin->OnDetach();
	plugin->SetRakPeerInterface(0);
}

void RakPeer::PushBackPacket(Packet *packet, bool pushAtHead)
{
	if (packet == nullptr)
		return;

	unsigned i;
	for (i = 0; i < pluginListTS.Size(); i++)
		pluginListTS[i]->OnPushBackPacket((const char *)packet->data, packet->bitSize, packet->systemAddress);
	for (i = 0; i < pluginListNTS.Size(); i++)
		pluginListNTS[i]->OnPushBackPacket((const char *)packet->data, packet->bitSize, packet->systemAddress);

	packetReturnMutex.Lock();
	if (pushAtHead)
		packetReturnQueue.PushAtHead(packet, 0, _FILE_AND_LINE_);
	else
		packetReturnQueue.Push(packet, _FILE_AND_LINE_);
	packetReturnMutex.Unlock();
}

void RakPeer::ChangeSystemAddress(RakNetGUID guid, const SystemAddress &systemAddress)
{
	BufferedCommandStruct *bcs;

	bcs = bufferedCommands.Allocate(_FILE_AND_LINE_);
	bcs->data = 0;
	bcs->systemIdentifier.systemAddress = systemAddress;
	bcs->systemIdentifier.rakNetGuid = guid;
	bcs->command = BufferedCommandStruct::BCS_CHANGE_SYSTEM_ADDRESS;
	bufferedCommands.Push(bcs);
}

Packet *RakPeer::AllocatePacket(unsigned dataSize)
{
	return AllocPacket(dataSize, _FILE_AND_LINE_);
}

RakNetSocket2 *RakPeer::GetSocket(const SystemAddress target)
{
	// Send a query to the thread to get the socket, and return when we got it
	BufferedCommandStruct *bcs;
	bcs = bufferedCommands.Allocate(_FILE_AND_LINE_);
	bcs->command = BufferedCommandStruct::BCS_GET_SOCKET;
	bcs->systemIdentifier = target;
	bcs->data = 0;
	bufferedCommands.Push(bcs);

	// Block up to one second to get the socket, although it should actually take virtually no time
	SocketQueryOutput *sqo;
	RakNet::TimeMS stopWaiting = RakNet::GetTimeMS() + 1000;
	DataStructures::List<RakNetSocket2 *> output;
	while (RakNet::GetTimeMS() < stopWaiting)
	{
		if (isMainLoopThreadActive == false)
			return 0;

		RakSleep(0);

		sqo = socketQueryOutput.Pop();
		if (sqo)
		{
			output = sqo->sockets;
			sqo->sockets.Clear(false, _FILE_AND_LINE_);
			socketQueryOutput.Deallocate(sqo, _FILE_AND_LINE_);
			if (output.Size())
				return output[0];
			break;
		}
	}
	return 0;
}

void RakPeer::GetSockets(DataStructures::List<RakNetSocket2 *> &sockets)
{
	sockets.Clear(false, _FILE_AND_LINE_);

	// Send a query to the thread to get the socket, and return when we got it
	BufferedCommandStruct *bcs;

	bcs = bufferedCommands.Allocate(_FILE_AND_LINE_);
	bcs->command = BufferedCommandStruct::BCS_GET_SOCKET;
	bcs->systemIdentifier = UNASSIGNED_SYSTEM_ADDRESS;
	bcs->data = 0;
	bufferedCommands.Push(bcs);

	// Block up to one second to get the socket, although it should actually take virtually no time
	SocketQueryOutput *sqo;
	while (1)
	{
		if (isMainLoopThreadActive == false)
			return;

		RakSleep(0);

		sqo = socketQueryOutput.Pop();
		if (sqo)
		{
			sockets = sqo->sockets;
			sqo->sockets.Clear(false, _FILE_AND_LINE_);
			socketQueryOutput.Deallocate(sqo, _FILE_AND_LINE_);
			return;
		}
	}
	return;
}

void RakPeer::ReleaseSockets(DataStructures::List<RakNetSocket2 *> &sockets)
{
	sockets.Clear(false, _FILE_AND_LINE_);
}

void RakPeer::ApplyNetworkSimulator(float packetloss, unsigned short minExtraPing, unsigned short extraPingVariance)
{
#ifdef _DEBUG
	if (remoteSystemList)
	{
		unsigned short i;
		for (i = 0; i < maximumNumberOfPeers; i++)
			// for (i=0; i < remoteSystemListSize; i++)
			remoteSystemList[i].reliabilityLayer.ApplyNetworkSimulator(packetloss, minExtraPing, extraPingVariance);
	}

	_packetloss = packetloss;
	_minExtraPing = minExtraPing;
	_extraPingVariance = extraPingVariance;
#endif
}

void RakPeer::SetPerConnectionOutgoingBandwidthLimit(unsigned maxBitsPerSecond)
{
	maxOutgoingBPS = maxBitsPerSecond;
}

bool RakPeer::IsNetworkSimulatorActive(void)
{
#ifdef _DEBUG
	return _packetloss > 0 || _minExtraPing > 0 || _extraPingVariance > 0;
#else
	return false;
#endif
}

void RakPeer::WriteOutOfBandHeader(RakNet::BitStream *bitStream)
{
	bitStream->Write<MessageID>(ID_OUT_OF_BAND_INTERNAL);
	bitStream->Write<RakNetGUID>(myGuid);
	bitStream->WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
}

void RakPeer::SetUserUpdateThread(void (*_userUpdateThreadPtr)(RakPeerInterface *, void *), void *_userUpdateThreadData)
{
	userUpdateThreadPtr = _userUpdateThreadPtr;
	userUpdateThreadData = _userUpdateThreadData;
}

void RakPeer::SetIncomingDatagramEventHandler(bool (*_incomingDatagramEventHandler)(RNS2RecvStruct *))
{
	incomingDatagramEventHandler = _incomingDatagramEventHandler;
}

bool RakPeer::SendOutOfBand(const char *host, unsigned short remotePort, const char *data, BitSize_t dataLength, unsigned connectionSocketIndex)
{
	if (IsActive() == false)
		return false;

	if (host == 0 || host[0] == 0)
		return false;

	// If this assert hits then Startup wasn't called or the call failed.
	RakAssert(connectionSocketIndex < socketList.Size());

	// This is a security measure.  Don't send data longer than this value
	RakAssert(dataLength <= (MAX_OFFLINE_DATA_LENGTH + sizeof(uint8_t) + sizeof(RakNet::Time) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID)));

	if (host == 0)
		return false;

	// 34 bytes
	RakNet::BitStream bitStream;
	WriteOutOfBandHeader(&bitStream);

	if (dataLength > 0)
	{
		bitStream.Write(data, dataLength);
	}

	unsigned int realIndex = GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);

	RNS2_SendParameters bsp;
	bsp.data = (char *)bitStream.GetData();
	bsp.length = bitStream.GetNumberOfBytesUsed();
	bsp.systemAddress.FromStringExplicitPort(host, remotePort, socketList[realIndex]->GetBoundAddress().GetIPVersion());
	bsp.systemAddress.FixForIPVersion(socketList[realIndex]->GetBoundAddress());
	unsigned i;
	for (i = 0; i < pluginListNTS.Size(); i++)
		pluginListNTS[i]->OnDirectSocketSend((const char *)bsp.data, BYTES_TO_BITS(bsp.length), bsp.systemAddress);
	socketList[realIndex]->Send(&bsp, _FILE_AND_LINE_);

	return true;
}

RakNetStatistics *RakPeer::GetStatistics(const SystemAddress systemAddress, RakNetStatistics *rns)
{
	static RakNetStatistics staticStatistics;
	RakNetStatistics *systemStats;
	if (rns == 0)
		systemStats = &staticStatistics;
	else
		systemStats = rns;

	if (systemAddress == UNASSIGNED_SYSTEM_ADDRESS)
	{
		bool firstWrite = false;
		// Return a crude sum
		for (unsigned short i = 0; i < maximumNumberOfPeers; i++)
		{
			if (remoteSystemList[i].isActive)
			{
				RakNetStatistics rnsTemp;
				remoteSystemList[i].reliabilityLayer.GetStatistics(&rnsTemp);

				if (firstWrite == false)
				{
					memcpy(systemStats, &rnsTemp, sizeof(RakNetStatistics));
					firstWrite = true;
				}
				else
					(*systemStats) += rnsTemp;
			}
		}
		return systemStats;
	}
	else
	{
		RemoteSystemStruct *rss;
		rss = GetRemoteSystemFromSystemAddress(systemAddress, false, false);
		if (rss && endThreads == false)
		{
			rss->reliabilityLayer.GetStatistics(systemStats);
			return systemStats;
		}
	}

	return 0;
}

void RakPeer::GetStatisticsList(DataStructures::List<SystemAddress> &addresses, DataStructures::List<RakNetGUID> &guids, DataStructures::List<RakNetStatistics> &statistics)
{
	addresses.Clear(false, _FILE_AND_LINE_);
	guids.Clear(false, _FILE_AND_LINE_);
	statistics.Clear(false, _FILE_AND_LINE_);

	if (remoteSystemList == 0 || endThreads == true)
		return;

	unsigned int i;
	for (i = 0; i < activeSystemListSize; i++)
	{
		if ((activeSystemList[i])->isActive &&
			(activeSystemList[i])->connectMode == RakPeer::RemoteSystemStruct::CONNECTED)
		{
			addresses.Push((activeSystemList[i])->systemAddress, _FILE_AND_LINE_);
			guids.Push((activeSystemList[i])->guid, _FILE_AND_LINE_);
			RakNetStatistics rns;
			(activeSystemList[i])->reliabilityLayer.GetStatistics(&rns);
			statistics.Push(rns, _FILE_AND_LINE_);
		}
	}
}

bool RakPeer::GetStatistics(const unsigned int index, RakNetStatistics *rns)
{
	if (index < maximumNumberOfPeers && remoteSystemList[index].isActive)
	{
		remoteSystemList[index].reliabilityLayer.GetStatistics(rns);
		return true;
	}
	return false;
}

unsigned int RakPeer::GetReceiveBufferSize(void)
{
	unsigned int size;
	packetReturnMutex.Lock();
	size = packetReturnQueue.Size();
	packetReturnMutex.Unlock();
	return size;
}

int RakPeer::GetIndexFromSystemAddress(const SystemAddress systemAddress, bool calledFromNetworkThread) const
{
	unsigned i;

	if (systemAddress == UNASSIGNED_SYSTEM_ADDRESS)
		return -1;

	if (systemAddress.systemIndex != (SystemIndex)-1 && systemAddress.systemIndex < maximumNumberOfPeers && remoteSystemList[systemAddress.systemIndex].systemAddress == systemAddress && remoteSystemList[systemAddress.systemIndex].isActive)
		return systemAddress.systemIndex;

	if (calledFromNetworkThread)
	{
		return GetRemoteSystemIndex(systemAddress);
	}
	else
	{
		// remoteSystemList in user and network thread
		for (i = 0; i < maximumNumberOfPeers; i++)
			if (remoteSystemList[i].isActive && remoteSystemList[i].systemAddress == systemAddress)
				return i;

		// If no active results found, try previously active results.
		for (i = 0; i < maximumNumberOfPeers; i++)
			if (remoteSystemList[i].systemAddress == systemAddress)
				return i;
	}

	return -1;
}

int RakPeer::GetIndexFromGuid(const RakNetGUID guid)
{
	unsigned i;

	if (guid == UNASSIGNED_RAKNET_GUID)
		return -1;

	if (guid.systemIndex != (SystemIndex)-1 && guid.systemIndex < maximumNumberOfPeers && remoteSystemList[guid.systemIndex].guid == guid && remoteSystemList[guid.systemIndex].isActive)
		return guid.systemIndex;

	// remoteSystemList in user and network thread
	for (i = 0; i < maximumNumberOfPeers; i++)
		if (remoteSystemList[i].isActive && remoteSystemList[i].guid == guid)
			return i;

	// If no active results found, try previously active results.
	for (i = 0; i < maximumNumberOfPeers; i++)
		if (remoteSystemList[i].guid == guid)
			return i;

	return -1;
}

#if LIBCAT_SECURITY == 1
bool RakPeer::GenerateConnectionRequestChallenge(RequestedConnectionStruct *rcs, PublicKey *publicKey)
{
	CAT_AUDIT_PRINTF("AUDIT: In GenerateConnectionRequestChallenge()\n");

	rcs->client_handshake = 0;
	rcs->publicKeyMode = PKM_INSECURE_CONNECTION;

	if (!publicKey)
		return true;

	switch (publicKey->publicKeyMode)
	{
	default:
	case PKM_INSECURE_CONNECTION:
		break;

	case PKM_ACCEPT_ANY_PUBLIC_KEY:
		CAT_OBJCLR(rcs->remote_public_key);
		rcs->client_handshake = RakNet::OP_NEW<cat::ClientEasyHandshake>(_FILE_AND_LINE_);

		rcs->publicKeyMode = PKM_ACCEPT_ANY_PUBLIC_KEY;
		break;

	case PKM_USE_TWO_WAY_AUTHENTICATION:
		if (publicKey->myPublicKey == 0 || publicKey->myPrivateKey == 0 ||
			publicKey->remoteServerPublicKey == 0)
		{
			return false;
		}

		rcs->client_handshake = RakNet::OP_NEW<cat::ClientEasyHandshake>(_FILE_AND_LINE_);
		memcpy(rcs->remote_public_key, publicKey->remoteServerPublicKey, cat::EasyHandshake::PUBLIC_KEY_BYTES);

		if (!rcs->client_handshake->Initialize(publicKey->remoteServerPublicKey) ||
			!rcs->client_handshake->SetIdentity(publicKey->myPublicKey, publicKey->myPrivateKey) ||
			!rcs->client_handshake->GenerateChallenge(rcs->handshakeChallenge))
		{
			CAT_AUDIT_PRINTF("AUDIT: Failure initializing new client_handshake object with identity for this RequestedConnectionStruct\n");
			RakNet::OP_DELETE(rcs->client_handshake, _FILE_AND_LINE_);
			rcs->client_handshake = 0;
			return false;
		}

		CAT_AUDIT_PRINTF("AUDIT: Success initializing new client handshake object with identity for this RequestedConnectionStruct -- pre-generated challenge\n");

		rcs->publicKeyMode = PKM_USE_TWO_WAY_AUTHENTICATION;
		break;

	case PKM_USE_KNOWN_PUBLIC_KEY:
		if (publicKey->remoteServerPublicKey == 0)
			return false;

		rcs->client_handshake = RakNet::OP_NEW<cat::ClientEasyHandshake>(_FILE_AND_LINE_);
		memcpy(rcs->remote_public_key, publicKey->remoteServerPublicKey, cat::EasyHandshake::PUBLIC_KEY_BYTES);

		if (!rcs->client_handshake->Initialize(publicKey->remoteServerPublicKey) ||
			!rcs->client_handshake->GenerateChallenge(rcs->handshakeChallenge))
		{
			CAT_AUDIT_PRINTF("AUDIT: Failure initializing new client_handshake object for this RequestedConnectionStruct\n");
			RakNet::OP_DELETE(rcs->client_handshake, _FILE_AND_LINE_);
			rcs->client_handshake = 0;
			return false;
		}

		CAT_AUDIT_PRINTF("AUDIT: Success initializing new client handshake object for this RequestedConnectionStruct -- pre-generated challenge\n");

		rcs->publicKeyMode = PKM_USE_KNOWN_PUBLIC_KEY;
		break;
	}

	return true;
}
#endif

ConnectionAttemptResult RakPeer::SendConnectionRequest(const char *host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime)
{
	RakAssert(passwordDataLength <= 256);
	RakAssert(remotePort != 0);
	SystemAddress systemAddress;
	if (!systemAddress.FromStringExplicitPort(host, remotePort, socketList[connectionSocketIndex]->GetBoundAddress().GetIPVersion()))
		return CANNOT_RESOLVE_DOMAIN_NAME;

	// Already connected?
	if (GetRemoteSystemFromSystemAddress(systemAddress, false, true))
		return ALREADY_CONNECTED_TO_ENDPOINT;

	RequestedConnectionStruct *rcs = RakNet::OP_NEW<RequestedConnectionStruct>(_FILE_AND_LINE_);

	rcs->systemAddress = systemAddress;
	rcs->nextRequestTime = RakNet::GetTimeMS();
	rcs->requestsMade = 0;
	rcs->data = 0;
	rcs->socket = 0;
	rcs->extraData = extraData;
	rcs->socketIndex = connectionSocketIndex;
	rcs->actionToTake = RequestedConnectionStruct::CONNECT;
	rcs->sendConnectionAttemptCount = sendConnectionAttemptCount;
	rcs->timeBetweenSendConnectionAttemptsMS = timeBetweenSendConnectionAttemptsMS;
	memcpy(rcs->outgoingPassword, passwordData, passwordDataLength);
	rcs->outgoingPasswordLength = (uint8_t)passwordDataLength;
	rcs->timeoutTime = timeoutTime;

#if LIBCAT_SECURITY == 1
	CAT_AUDIT_PRINTF("AUDIT: In SendConnectionRequest()\n");
	if (!GenerateConnectionRequestChallenge(rcs, publicKey))
		return SECURITY_INITIALIZATION_FAILED;
#else
	(void)publicKey;
#endif

	// Return false if already pending, else push on queue
	unsigned int i = 0;
	requestedConnectionQueueMutex.Lock();
	for (; i < requestedConnectionQueue.Size(); i++)
	{
		if (requestedConnectionQueue[i]->systemAddress == systemAddress)
		{
			requestedConnectionQueueMutex.Unlock();
			RakNet::OP_DELETE(rcs, _FILE_AND_LINE_);
			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
		}
	}
	requestedConnectionQueue.Push(rcs, _FILE_AND_LINE_);
	requestedConnectionQueueMutex.Unlock();

	return CONNECTION_ATTEMPT_STARTED;
}

ConnectionAttemptResult RakPeer::SendConnectionRequest(const char *host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime, RakNetSocket2 *socket)
{
	RakAssert(passwordDataLength <= 256);
	SystemAddress systemAddress;
	systemAddress.FromStringExplicitPort(host, remotePort);

	// Already connected?
	if (GetRemoteSystemFromSystemAddress(systemAddress, false, true))
		return ALREADY_CONNECTED_TO_ENDPOINT;

	RequestedConnectionStruct *rcs = RakNet::OP_NEW<RequestedConnectionStruct>(_FILE_AND_LINE_);

	rcs->systemAddress = systemAddress;
	rcs->nextRequestTime = RakNet::GetTimeMS();
	rcs->requestsMade = 0;
	rcs->data = 0;
	rcs->socket = 0;
	rcs->extraData = extraData;
	rcs->socketIndex = connectionSocketIndex;
	rcs->actionToTake = RequestedConnectionStruct::CONNECT;
	rcs->sendConnectionAttemptCount = sendConnectionAttemptCount;
	rcs->timeBetweenSendConnectionAttemptsMS = timeBetweenSendConnectionAttemptsMS;
	memcpy(rcs->outgoingPassword, passwordData, passwordDataLength);
	rcs->outgoingPasswordLength = (uint8_t)passwordDataLength;
	rcs->timeoutTime = timeoutTime;
	rcs->socket = socket;

#if LIBCAT_SECURITY == 1
	if (!GenerateConnectionRequestChallenge(rcs, publicKey))
		return SECURITY_INITIALIZATION_FAILED;
#else
	(void)publicKey;
#endif

	// Return false if already pending, else push on queue
	unsigned int i = 0;
	requestedConnectionQueueMutex.Lock();
	for (; i < requestedConnectionQueue.Size(); i++)
	{
		if (requestedConnectionQueue[i]->systemAddress == systemAddress)
		{
			requestedConnectionQueueMutex.Unlock();
			RakNet::OP_DELETE(rcs, _FILE_AND_LINE_);
			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
		}
	}
	requestedConnectionQueue.Push(rcs, _FILE_AND_LINE_);
	requestedConnectionQueueMutex.Unlock();

	return CONNECTION_ATTEMPT_STARTED;
}

void RakPeer::ValidateRemoteSystemLookup(void) const
{
}

RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystem(const AddressOrGUID systemIdentifier, bool calledFromNetworkThread, bool onlyActive) const
{
	if (systemIdentifier.rakNetGuid != UNASSIGNED_RAKNET_GUID)
		return GetRemoteSystemFromGUID(systemIdentifier.rakNetGuid, onlyActive);
	else
		return GetRemoteSystemFromSystemAddress(systemIdentifier.systemAddress, calledFromNetworkThread, onlyActive);
}

RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromSystemAddress(const SystemAddress systemAddress, bool calledFromNetworkThread, bool onlyActive) const
{
	unsigned i;

	if (systemAddress == UNASSIGNED_SYSTEM_ADDRESS)
		return 0;

	if (calledFromNetworkThread)
	{
		unsigned int index = GetRemoteSystemIndex(systemAddress);
		if (index != (unsigned int)-1)
		{
			if (onlyActive == false || remoteSystemList[index].isActive == true)
			{
				RakAssert(remoteSystemList[index].systemAddress == systemAddress);
				return remoteSystemList + index;
			}
		}
	}
	else
	{
		int deadConnectionIndex = -1;

		// Active connections take priority.  But if there are no active connections, return the first systemAddress match found
		for (i = 0; i < maximumNumberOfPeers; i++)
		{
			if (remoteSystemList[i].systemAddress == systemAddress)
			{
				if (remoteSystemList[i].isActive)
					return remoteSystemList + i;
				else if (deadConnectionIndex == -1)
					deadConnectionIndex = i;
			}
		}

		if (deadConnectionIndex != -1 && onlyActive == false)
			return remoteSystemList + deadConnectionIndex;
	}

	return 0;
}

RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromGUID(const RakNetGUID guid, bool onlyActive) const
{
	if (guid == UNASSIGNED_RAKNET_GUID)
		return 0;

	unsigned i;
	for (i = 0; i < maximumNumberOfPeers; i++)
	{
		if (remoteSystemList[i].guid == guid && (onlyActive == false || remoteSystemList[i].isActive))
		{
			return remoteSystemList + i;
		}
	}
	return 0;
}

void RakPeer::ParseConnectionRequestPacket(RakPeer::RemoteSystemStruct *remoteSystem, const SystemAddress &systemAddress, const char *data, int byteSize)
{
	RakNet::BitStream bs((uint8_t *)data, byteSize, false);
	bs.IgnoreBytes(sizeof(MessageID));
	RakNetGUID guid;
	bs.Read<RakNetGUID>(guid);
	RakNet::Time incomingTimestamp;
	bs.Read<RakNet::Time>(incomingTimestamp);
	uint8_t doSecurity;
	bs.Read<uint8_t>(doSecurity);

#if LIBCAT_SECURITY == 1
	uint8_t doClientKey;
	if (_using_security)
	{
		// Ignore message on bad state
		if (doSecurity != 1 || !remoteSystem->reliabilityLayer.GetAuthenticatedEncryption())
			return;

		// Validate client proof of key
		uint8_t proof[cat::EasyHandshake::PROOF_BYTES];
		bs.ReadAlignedBytes(proof, sizeof(proof));
		if (!remoteSystem->reliabilityLayer.GetAuthenticatedEncryption()->ValidateProof(proof, sizeof(proof)))
		{
			remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
			return;
		}

		CAT_OBJCLR(remoteSystem->client_public_key);

		bs.Read<uint8_t>(doClientKey);

		// Check if client wants to prove identity
		if (doClientKey == 1)
		{
			// Read identity proof
			uint8_t ident[cat::EasyHandshake::IDENTITY_BYTES];
			bs.ReadAlignedBytes(ident, sizeof(ident));

			// If we are listening to these proofs,
			if (_require_client_public_key)
			{
				// Validate client identity
				if (!_server_handshake->VerifyInitiatorIdentity(remoteSystem->answer, ident, remoteSystem->client_public_key))
				{
					RakNet::BitStream bitStream;
					bitStream.Write<MessageID>(ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY); // Report an error since the client is not providing an identity when it is necessary to connect
					bitStream.Write<uint8_t>(2);									  // Indicate client identity is invalid
					SendImmediate((char *)bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), IMMEDIATE_PRIORITY, RELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);
					remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
					return;
				}
			}

			// Otherwise ignore the client public key
		}
		else
		{
			// If no client key was provided but it is required,
			if (_require_client_public_key)
			{
				RakNet::BitStream bitStream;
				bitStream.Write<MessageID>(ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY); // Report an error since the client is not providing an identity when it is necessary to connect
				bitStream.Write<uint8_t>(1);									  // Indicate client identity is missing
				SendImmediate((char *)bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), IMMEDIATE_PRIORITY, RELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);
				remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
				return;
			}
		}
	}
#endif // LIBCAT_SECURITY

	uint8_t *password = bs.GetData() + BITS_TO_BYTES(bs.GetReadOffset());
	int passwordLength = byteSize - BITS_TO_BYTES(bs.GetReadOffset());
	if (incomingPasswordLength != passwordLength ||
		memcmp(password, incomingPassword, incomingPasswordLength) != 0)
	{
		CAT_AUDIT_PRINTF("AUDIT: Invalid password\n");
		// This one we only send once since we don't care if it arrives.
		RakNet::BitStream bitStream;
		bitStream.Write<MessageID>(ID_INVALID_PASSWORD);
		bitStream.Write<RakNetGUID>(GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
		SendImmediate((char *)bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), IMMEDIATE_PRIORITY, RELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);
		remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
		return;
	}

	remoteSystem->connectMode = RemoteSystemStruct::HANDLING_CONNECTION_REQUEST;

	OnConnectionRequest(remoteSystem, incomingTimestamp);
}

void RakPeer::OnConnectionRequest(RakPeer::RemoteSystemStruct *remoteSystem, RakNet::Time incomingTimestamp)
{
	RakNet::BitStream bitStream;
	bitStream.Write<MessageID>(ID_CONNECTION_REQUEST_ACCEPTED);
	bitStream.Write<SystemAddress>(remoteSystem->systemAddress);
	SystemIndex systemIndex = (SystemIndex)GetIndexFromSystemAddress(remoteSystem->systemAddress, true);
	RakAssert(systemIndex != 65535);
	bitStream.Write<SystemIndex>(systemIndex);
	for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
		bitStream.Write<SystemAddress>(ipList[i]);
	bitStream.Write<RakNet::Time>(incomingTimestamp);
	bitStream.Write<RakNet::Time>(RakNet::GetTime());

	SendImmediate((char *)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE_ORDERED, 0, remoteSystem->systemAddress, false, false, RakNet::GetTimeUS(), 0);
}

void RakPeer::NotifyAndFlagForShutdown(const SystemAddress systemAddress, bool performImmediate, uint8_t orderingChannel, PacketPriority disconnectionNotificationPriority)
{
	RakNet::BitStream temp(sizeof(uint8_t));
	temp.Write<MessageID>(ID_DISCONNECTION_NOTIFICATION);
	if (performImmediate)
	{
		SendImmediate((char *)temp.GetData(), temp.GetNumberOfBitsUsed(), disconnectionNotificationPriority, RELIABLE_ORDERED, orderingChannel, systemAddress, false, false, RakNet::GetTimeUS(), 0);
		RemoteSystemStruct *rss = GetRemoteSystemFromSystemAddress(systemAddress, true, true);
		rss->connectMode = RemoteSystemStruct::DISCONNECT_ASAP;
	}
	else
	{
		SendBuffered((const char *)temp.GetData(), temp.GetNumberOfBitsUsed(), disconnectionNotificationPriority, RELIABLE_ORDERED, orderingChannel, systemAddress, false, RemoteSystemStruct::DISCONNECT_ASAP, 0);
	}
}

unsigned int RakPeer::GetNumberOfRemoteInitiatedConnections(void) const
{
	if (remoteSystemList == 0 || endThreads == true)
		return 0;

	unsigned int numberOfIncomingConnections;
	numberOfIncomingConnections = 0;
	unsigned int i;
	for (i = 0; i < activeSystemListSize; i++)
	{
		if ((activeSystemList[i])->isActive &&
			(activeSystemList[i])->connectMode == RakPeer::RemoteSystemStruct::CONNECTED &&
			(activeSystemList[i])->weInitiatedTheConnection == false)
		{
			numberOfIncomingConnections++;
		}
	}
	return numberOfIncomingConnections;
}

RakPeer::RemoteSystemStruct *RakPeer::AssignSystemAddressToRemoteSystemList(const SystemAddress systemAddress, RemoteSystemStruct::ConnectMode connectionMode, RakNetSocket2 *incomingRakNetSocket, bool *thisIPConnectedRecently, SystemAddress bindingAddress, int incomingMTU, RakNetGUID guid, bool useSecurity)
{
	RemoteSystemStruct *remoteSystem;
	unsigned i, j, assignedIndex;
	RakNet::TimeMS time = RakNet::GetTimeMS();
#ifdef _DEBUG
	RakAssert(systemAddress != UNASSIGNED_SYSTEM_ADDRESS);
#endif

	if (limitConnectionFrequencyFromTheSameIP)
	{
		if (IsLoopbackAddress(systemAddress, false) == false)
		{
			for (i = 0; i < maximumNumberOfPeers; i++)
			{
				if (remoteSystemList[i].isActive == true &&
					remoteSystemList[i].systemAddress.EqualsExcludingPort(systemAddress) &&
					time >= remoteSystemList[i].connectionTime &&
					time - remoteSystemList[i].connectionTime < 100)
				{
					// 4/13/09 Attackers can flood ID_OPEN_CONNECTION_REQUEST and use up all available connection slots
					// Ignore connection attempts if this IP address connected within the last 100 milliseconds
					*thisIPConnectedRecently = true;
					ValidateRemoteSystemLookup();
					return 0;
				}
			}
		}
	}

	// Don't use a different port than what we received on
	bindingAddress.CopyPort(incomingRakNetSocket->GetBoundAddress());

	*thisIPConnectedRecently = false;
	for (assignedIndex = 0; assignedIndex < maximumNumberOfPeers; assignedIndex++)
	{
		if (remoteSystemList[assignedIndex].isActive == false)
		{
			remoteSystem = remoteSystemList + assignedIndex;
			ReferenceRemoteSystem(systemAddress, assignedIndex);
			remoteSystem->MTUSize = defaultMTUSize;
			remoteSystem->guid = guid;
			remoteSystem->isActive = true; // This one line causes future incoming packets to go through the reliability layer
			// Reserve this reliability layer for ourselves.
			if (incomingMTU > remoteSystem->MTUSize)
				remoteSystem->MTUSize = incomingMTU;
			RakAssert(remoteSystem->MTUSize <= MAXIMUM_MTU_SIZE);
			remoteSystem->reliabilityLayer.Reset(true, remoteSystem->MTUSize, useSecurity);
			remoteSystem->reliabilityLayer.SetSplitMessageProgressInterval(splitMessageProgressInterval);
			remoteSystem->reliabilityLayer.SetUnreliableTimeout(unreliableTimeout);
			remoteSystem->reliabilityLayer.SetTimeoutTime(defaultTimeoutTime);
			AddToActiveSystemList(assignedIndex);
			if (incomingRakNetSocket->GetBoundAddress() == bindingAddress)
			{
				remoteSystem->rakNetSocket = incomingRakNetSocket;
			}
			else
			{
				char str[256];
				bindingAddress.ToString(true, str);
				unsigned int ipListIndex, foundIndex = (unsigned int)-1;

				for (ipListIndex = 0; ipListIndex < MAXIMUM_NUMBER_OF_INTERNAL_IDS; ipListIndex++)
				{
					if (ipList[ipListIndex] == UNASSIGNED_SYSTEM_ADDRESS)
						break;

					if (bindingAddress.EqualsExcludingPort(ipList[ipListIndex]))
					{
						foundIndex = ipListIndex;
						break;
					}
				}

				if (1 || foundIndex == (unsigned int)-1)
				{
					remoteSystem->rakNetSocket = incomingRakNetSocket;
				}
			}

			for (j = 0; j < (unsigned)PING_TIMES_ARRAY_SIZE; j++)
			{
				remoteSystem->pingAndClockDifferential[j].pingTime = 65535;
				remoteSystem->pingAndClockDifferential[j].clockDifferential = 0;
			}

			remoteSystem->connectMode = connectionMode;
			remoteSystem->pingAndClockDifferentialWriteIndex = 0;
			remoteSystem->lowestPing = 65535;
			remoteSystem->nextPingTime = 0; // Ping immediately
			remoteSystem->weInitiatedTheConnection = false;
			remoteSystem->connectionTime = time;
			remoteSystem->myExternalSystemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystem->lastReliableSend = time;

#ifdef _DEBUG
			int indexLoopupCheck = GetIndexFromSystemAddress(systemAddress, true);
			if ((int)indexLoopupCheck != (int)assignedIndex)
			{
				RakAssert((int)indexLoopupCheck == (int)assignedIndex);
			}
#endif

			return remoteSystem;
		}
	}

	return 0;
}

void RakPeer::ShiftIncomingTimestamp(uint8_t *data, const SystemAddress &systemAddress) const
{
#ifdef _DEBUG
	RakAssert(IsActive());
	RakAssert(data);
#endif

	RakNet::BitStream timeBS(data, sizeof(RakNet::Time), false);
	RakNet::Time encodedTimestamp;
	timeBS.Read<RakNet::Time>(encodedTimestamp);

	encodedTimestamp = encodedTimestamp - GetBestClockDifferential(systemAddress);
	timeBS.SetWriteOffset(0);
	timeBS.Write<RakNet::Time>(encodedTimestamp);
}

RakNet::Time RakPeer::GetBestClockDifferential(const SystemAddress systemAddress) const
{
	RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress(systemAddress, true, true);

	if (remoteSystem == 0)
		return 0;

	return GetClockDifferentialInt(remoteSystem);
}

unsigned int RakPeer::RemoteSystemLookupHashIndex(const SystemAddress &sa) const
{
	return SystemAddress::ToInteger(sa) % ((unsigned int)maximumNumberOfPeers * REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE);
}

void RakPeer::ReferenceRemoteSystem(const SystemAddress &sa, unsigned int remoteSystemListIndex)
{
	SystemAddress oldAddress = remoteSystemList[remoteSystemListIndex].systemAddress;
	if (oldAddress != UNASSIGNED_SYSTEM_ADDRESS)
	{
		if (GetRemoteSystem(oldAddress) == &remoteSystemList[remoteSystemListIndex])
			DereferenceRemoteSystem(oldAddress);
	}
	DereferenceRemoteSystem(sa);

	remoteSystemList[remoteSystemListIndex].systemAddress = sa;

	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *rsi;
	rsi = remoteSystemIndexPool.Allocate(_FILE_AND_LINE_);
	if (remoteSystemLookup[hashIndex] == 0)
	{
		rsi->next = 0;
		rsi->index = remoteSystemListIndex;
		remoteSystemLookup[hashIndex] = rsi;
	}
	else
	{
		RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
		while (cur->next != 0)
		{
			cur = cur->next;
		}

		rsi = remoteSystemIndexPool.Allocate(_FILE_AND_LINE_);
		rsi->next = 0;
		rsi->index = remoteSystemListIndex;
		cur->next = rsi;
	}

	RakAssert(GetRemoteSystemIndex(sa) == remoteSystemListIndex);
}

void RakPeer::DereferenceRemoteSystem(const SystemAddress &sa)
{
	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
	RemoteSystemIndex *last = 0;
	while (cur != 0)
	{
		if (remoteSystemList[cur->index].systemAddress == sa)
		{
			if (last == 0)
			{
				remoteSystemLookup[hashIndex] = cur->next;
			}
			else
			{
				last->next = cur->next;
			}
			remoteSystemIndexPool.Release(cur, _FILE_AND_LINE_);
			break;
		}
		last = cur;
		cur = cur->next;
	}
}

unsigned int RakPeer::GetRemoteSystemIndex(const SystemAddress &sa) const
{
	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
	while (cur != 0)
	{
		if (remoteSystemList[cur->index].systemAddress == sa)
			return cur->index;
		cur = cur->next;
	}
	return (unsigned int)-1;
}

RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystem(const SystemAddress &sa) const
{
	unsigned int remoteSystemIndex = GetRemoteSystemIndex(sa);
	if (remoteSystemIndex == (unsigned int)-1)
		return 0;
	return remoteSystemList + remoteSystemIndex;
}

void RakPeer::ClearRemoteSystemLookup(void)
{
	remoteSystemIndexPool.Clear(_FILE_AND_LINE_);
	RakNet::OP_DELETE_ARRAY(remoteSystemLookup, _FILE_AND_LINE_);
	remoteSystemLookup = 0;
}

void RakPeer::AddToActiveSystemList(unsigned int remoteSystemListIndex)
{
	activeSystemList[activeSystemListSize++] = remoteSystemList + remoteSystemListIndex;
}

void RakPeer::RemoveFromActiveSystemList(const SystemAddress &sa)
{
	unsigned int i;
	for (i = 0; i < activeSystemListSize; i++)
	{
		RemoteSystemStruct *rss = activeSystemList[i];
		if (rss->systemAddress == sa)
		{
			activeSystemList[i] = activeSystemList[activeSystemListSize - 1];
			activeSystemListSize--;
			return;
		}
	}
	RakAssert("activeSystemList invalid, entry not found in RemoveFromActiveSystemList. Ensure that AddToActiveSystemList and RemoveFromActiveSystemList are called by the same thread." && 0);
}

bool RakPeer::IsLoopbackAddress(const AddressOrGUID &systemIdentifier, bool matchPort) const
{
	if (systemIdentifier.rakNetGuid != UNASSIGNED_RAKNET_GUID)
		return systemIdentifier.rakNetGuid == myGuid;

	for (int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS && ipList[i] != UNASSIGNED_SYSTEM_ADDRESS; i++)
	{
		if (matchPort)
		{
			if (ipList[i] == systemIdentifier.systemAddress)
				return true;
		}
		else
		{
			if (ipList[i].EqualsExcludingPort(systemIdentifier.systemAddress))
				return true;
		}
	}

	return (matchPort == true && systemIdentifier.systemAddress == firstExternalID) ||
		   (matchPort == false && systemIdentifier.systemAddress.EqualsExcludingPort(firstExternalID));
}

SystemAddress RakPeer::GetLoopbackAddress(void) const
{
	return ipList[0];
}

bool RakPeer::AllowIncomingConnections(void) const
{
	return GetNumberOfRemoteInitiatedConnections() < GetMaximumIncomingConnections();
}

void RakPeer::DeallocRNS2RecvStruct(RNS2RecvStruct *s, const char *file, unsigned int line)
{
	bufferedPacketsFreePoolMutex.Lock();
	bufferedPacketsFreePool.Push(s, file, line);
	bufferedPacketsFreePoolMutex.Unlock();
}

RNS2RecvStruct *RakPeer::AllocRNS2RecvStruct(const char *file, unsigned int line)
{
	bufferedPacketsFreePoolMutex.Lock();
	if (bufferedPacketsFreePool.Size() > 0)
	{
		RNS2RecvStruct *s = bufferedPacketsFreePool.Pop();
		bufferedPacketsFreePoolMutex.Unlock();
		return s;
	}
	else
	{
		bufferedPacketsFreePoolMutex.Unlock();
		return RakNet::OP_NEW<RNS2RecvStruct>(file, line);
	}
}

void RakPeer::ClearBufferedPackets(void)
{
	bufferedPacketsFreePoolMutex.Lock();
	while (bufferedPacketsFreePool.Size() > 0)
		RakNet::OP_DELETE(bufferedPacketsFreePool.Pop(), _FILE_AND_LINE_);
	bufferedPacketsFreePoolMutex.Unlock();

	bufferedPacketsQueueMutex.Lock();
	while (bufferedPacketsQueue.Size() > 0)
		RakNet::OP_DELETE(bufferedPacketsQueue.Pop(), _FILE_AND_LINE_);
	bufferedPacketsQueueMutex.Unlock();
}

void RakPeer::SetupBufferedPackets(void)
{
}

void RakPeer::PushBufferedPacket(RNS2RecvStruct *p)
{
	bufferedPacketsQueueMutex.Lock();
	bufferedPacketsQueue.Push(p, _FILE_AND_LINE_);
	bufferedPacketsQueueMutex.Unlock();
}

RNS2RecvStruct *RakPeer::PopBufferedPacket(void)
{
	bufferedPacketsQueueMutex.Lock();
	if (bufferedPacketsQueue.Size() > 0)
	{
		RNS2RecvStruct *s = bufferedPacketsQueue.Pop();
		bufferedPacketsQueueMutex.Unlock();
		return s;
	}
	bufferedPacketsQueueMutex.Unlock();
	return 0;
}

void RakPeer::PingInternal(const SystemAddress target, bool performImmediate, PacketReliability reliability)
{
	if (IsActive() == false)
		return;

	RakNet::BitStream bitStream(sizeof(uint8_t) + sizeof(RakNet::Time));
	bitStream.Write<MessageID>(ID_CONNECTED_PING);
	bitStream.Write<RakNet::Time>(RakNet::GetTime());
	if (performImmediate)
		SendImmediate((char *)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, reliability, 0, target, false, false, RakNet::GetTimeUS(), 0);
	else
		Send(&bitStream, IMMEDIATE_PRIORITY, reliability, 0, target, false);
}

void RakPeer::CloseConnectionInternal(const AddressOrGUID &systemIdentifier, bool sendDisconnectionNotification, bool performImmediate, uint8_t orderingChannel, PacketPriority disconnectionNotificationPriority)
{
#ifdef _DEBUG
	RakAssert(orderingChannel < 32);
#endif

	if (systemIdentifier.IsUndefined())
		return;

	if (remoteSystemList == 0 || endThreads == true)
		return;

	SystemAddress target;
	if (systemIdentifier.systemAddress != UNASSIGNED_SYSTEM_ADDRESS)
	{
		target = systemIdentifier.systemAddress;
	}
	else
	{
		target = GetSystemAddressFromGuid(systemIdentifier.rakNetGuid);
	}

	if (target != UNASSIGNED_SYSTEM_ADDRESS && performImmediate)
		target.FixForIPVersion(socketList[0]->GetBoundAddress());

	if (sendDisconnectionNotification)
	{
		NotifyAndFlagForShutdown(target, performImmediate, orderingChannel, disconnectionNotificationPriority);
	}
	else
	{
		if (performImmediate)
		{
			unsigned int index = GetRemoteSystemIndex(target);
			if (index != (unsigned int)-1)
			{
				if (remoteSystemList[index].isActive)
				{
					RemoveFromActiveSystemList(target);

					remoteSystemList[index].isActive = false;
					remoteSystemList[index].guid = UNASSIGNED_RAKNET_GUID;

					RakAssert(remoteSystemList[index].MTUSize <= MAXIMUM_MTU_SIZE);
					remoteSystemList[index].reliabilityLayer.Reset(false, remoteSystemList[index].MTUSize, false);

					remoteSystemList[index].rakNetSocket = 0;
				}
			}
		}
		else
		{
			BufferedCommandStruct *bcs;
			bcs = bufferedCommands.Allocate(_FILE_AND_LINE_);
			bcs->command = BufferedCommandStruct::BCS_CLOSE_CONNECTION;
			bcs->systemIdentifier = target;
			bcs->data = 0;
			bcs->orderingChannel = orderingChannel;
			bcs->priority = disconnectionNotificationPriority;
			bufferedCommands.Push(bcs);
		}
	}
}

void RakPeer::SendBuffered(const char *data, BitSize_t numberOfBitsToSend, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, RemoteSystemStruct::ConnectMode connectionMode, uint32_t receipt)
{
	BufferedCommandStruct *bcs;

	bcs = bufferedCommands.Allocate(_FILE_AND_LINE_);
	bcs->data = (char *)rakMalloc_Ex((size_t)BITS_TO_BYTES(numberOfBitsToSend), _FILE_AND_LINE_); // Making a copy doesn't lose efficiency because I tell the reliability layer to use this allocation for its own copy
	if (bcs->data == 0)
	{
		notifyOutOfMemory(_FILE_AND_LINE_);
		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
		return;
	}

	RakAssert(!(reliability >= NUMBER_OF_RELIABILITIES || reliability < 0));
	RakAssert(!(priority > NUMBER_OF_PRIORITIES || priority < 0));
	RakAssert(!(orderingChannel >= NUMBER_OF_ORDERED_STREAMS));

	memcpy(bcs->data, data, (size_t)BITS_TO_BYTES(numberOfBitsToSend));
	bcs->numberOfBitsToSend = numberOfBitsToSend;
	bcs->priority = priority;
	bcs->reliability = reliability;
	bcs->orderingChannel = orderingChannel;
	bcs->systemIdentifier = systemIdentifier;
	bcs->broadcast = broadcast;
	bcs->connectionMode = connectionMode;
	bcs->receipt = receipt;
	bcs->command = BufferedCommandStruct::BCS_SEND;
	bufferedCommands.Push(bcs);

	if (priority == IMMEDIATE_PRIORITY)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		quitAndDataEvents.SetEvent();
	}
}

void RakPeer::SendBufferedList(const char **data, const int *lengths, const int numParameters, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, RemoteSystemStruct::ConnectMode connectionMode, uint32_t receipt)
{
	BufferedCommandStruct *bcs;
	unsigned int totalLength = 0;
	unsigned int lengthOffset;
	int i;
	for (i = 0; i < numParameters; i++)
	{
		if (lengths[i] > 0)
			totalLength += lengths[i];
	}
	if (totalLength == 0)
		return;

	char *dataAggregate;
	dataAggregate = (char *)rakMalloc_Ex((size_t)totalLength, _FILE_AND_LINE_); // Making a copy doesn't lose efficiency because I tell the reliability layer to use this allocation for its own copy
	if (dataAggregate == 0)
	{
		notifyOutOfMemory(_FILE_AND_LINE_);
		return;
	}
	for (i = 0, lengthOffset = 0; i < numParameters; i++)
	{
		if (lengths[i] > 0)
		{
			memcpy(dataAggregate + lengthOffset, data[i], lengths[i]);
			lengthOffset += lengths[i];
		}
	}

	if (broadcast == false && IsLoopbackAddress(systemIdentifier, true))
	{
		SendLoopback(dataAggregate, totalLength);
		rakFree_Ex(dataAggregate, _FILE_AND_LINE_);
		return;
	}

	RakAssert(!(reliability >= NUMBER_OF_RELIABILITIES || reliability < 0));
	RakAssert(!(priority > NUMBER_OF_PRIORITIES || priority < 0));
	RakAssert(!(orderingChannel >= NUMBER_OF_ORDERED_STREAMS));

	bcs = bufferedCommands.Allocate(_FILE_AND_LINE_);
	bcs->data = dataAggregate;
	bcs->numberOfBitsToSend = BYTES_TO_BITS(totalLength);
	bcs->priority = priority;
	bcs->reliability = reliability;
	bcs->orderingChannel = orderingChannel;
	bcs->systemIdentifier = systemIdentifier;
	bcs->broadcast = broadcast;
	bcs->connectionMode = connectionMode;
	bcs->receipt = receipt;
	bcs->command = BufferedCommandStruct::BCS_SEND;
	bufferedCommands.Push(bcs);

	if (priority == IMMEDIATE_PRIORITY)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		quitAndDataEvents.SetEvent();
	}
}

bool RakPeer::SendImmediate(char *data, BitSize_t numberOfBitsToSend, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, bool useCallerDataAllocation, RakNet::TimeUS currentTime, uint32_t receipt)
{
	unsigned *sendList;
	unsigned sendListSize;
	bool callerDataAllocationUsed;
	unsigned int remoteSystemIndex, sendListIndex; // Iterates into the list of remote systems
	callerDataAllocationUsed = false;

	sendListSize = 0;

	if (systemIdentifier.systemAddress != UNASSIGNED_SYSTEM_ADDRESS)
		remoteSystemIndex = GetIndexFromSystemAddress(systemIdentifier.systemAddress, true);
	else if (systemIdentifier.rakNetGuid != UNASSIGNED_RAKNET_GUID)
		remoteSystemIndex = GetSystemIndexFromGuid(systemIdentifier.rakNetGuid);
	else
		remoteSystemIndex = (unsigned int)-1;

	if (broadcast == false)
	{
		if (remoteSystemIndex == (unsigned int)-1)
		{
			return false;
		}

#if USE_ALLOCA == 1
		sendList = (unsigned *)alloca(sizeof(unsigned));
#else
		sendList = (unsigned *)rakMalloc_Ex(sizeof(unsigned), _FILE_AND_LINE_);
#endif

		if (remoteSystemList[remoteSystemIndex].isActive &&
			remoteSystemList[remoteSystemIndex].connectMode != RemoteSystemStruct::DISCONNECT_ASAP &&
			remoteSystemList[remoteSystemIndex].connectMode != RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY &&
			remoteSystemList[remoteSystemIndex].connectMode != RemoteSystemStruct::DISCONNECT_ON_NO_ACK)
		{
			sendList[0] = remoteSystemIndex;
			sendListSize = 1;
		}
	}
	else
	{
#if USE_ALLOCA == 1
		sendList = (unsigned *)alloca(sizeof(unsigned) * maximumNumberOfPeers);
#else
		sendList = (unsigned *)rakMalloc_Ex(sizeof(unsigned) * maximumNumberOfPeers, _FILE_AND_LINE_);
#endif

		unsigned int idx;
		for (idx = 0; idx < maximumNumberOfPeers; idx++)
		{
			if (remoteSystemIndex != (unsigned int)-1 && idx == remoteSystemIndex)
				continue;

			if (remoteSystemList[idx].isActive && remoteSystemList[idx].systemAddress != UNASSIGNED_SYSTEM_ADDRESS)
				sendList[sendListSize++] = idx;
		}
	}

	if (sendListSize == 0)
	{
#if !defined(USE_ALLOCA)
		rakFree_Ex(sendList, _FILE_AND_LINE_);
#endif

		return false;
	}

	for (sendListIndex = 0; sendListIndex < sendListSize; sendListIndex++)
	{
		// Send may split the packet and thus deallocate data.  Don't assume data is valid if we use the callerAllocationData
		bool useData = useCallerDataAllocation && callerDataAllocationUsed == false && sendListIndex + 1 == sendListSize;
		remoteSystemList[sendList[sendListIndex]].reliabilityLayer.Send(data, numberOfBitsToSend, priority, reliability, orderingChannel, useData == false, remoteSystemList[sendList[sendListIndex]].MTUSize, currentTime, receipt);
		if (useData)
			callerDataAllocationUsed = true;

		if (reliability == RELIABLE ||
			reliability == RELIABLE_ORDERED ||
			reliability == RELIABLE_SEQUENCED ||
			reliability == RELIABLE_WITH_ACK_RECEIPT ||
			reliability == RELIABLE_ORDERED_WITH_ACK_RECEIPT
		)
			remoteSystemList[sendList[sendListIndex]].lastReliableSend = (RakNet::TimeMS)(currentTime / (RakNet::TimeUS)1000);
	}

#if !defined(USE_ALLOCA)
	rakFree_Ex(sendList, _FILE_AND_LINE_);
#endif

	return callerDataAllocationUsed;
}

void RakPeer::ResetSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	sendReceiptSerial = 1;
	sendReceiptSerialMutex.Unlock();
}

void RakPeer::OnConnectedPong(RakNet::Time sendPingTime, RakNet::Time sendPongTime, RemoteSystemStruct *remoteSystem)
{
	RakNet::Time ping;
	RakNet::Time time = RakNet::GetTime();
	if (time > sendPingTime)
		ping = time - sendPingTime;
	else
		ping = 0;

	remoteSystem->pingAndClockDifferential[remoteSystem->pingAndClockDifferentialWriteIndex].pingTime = (unsigned short)ping;
	remoteSystem->pingAndClockDifferential[remoteSystem->pingAndClockDifferentialWriteIndex].clockDifferential = sendPongTime - (time / 2 + sendPingTime / 2);

	if (remoteSystem->lowestPing == (unsigned short)-1 || remoteSystem->lowestPing > (int)ping)
		remoteSystem->lowestPing = (unsigned short)ping;

	if (++(remoteSystem->pingAndClockDifferentialWriteIndex) == (RakNet::Time)PING_TIMES_ARRAY_SIZE)
		remoteSystem->pingAndClockDifferentialWriteIndex = 0;
}

void RakPeer::ClearBufferedCommands(void)
{
	BufferedCommandStruct *bcs;

	while ((bcs = bufferedCommands.Pop()) != 0)
	{
		if (bcs->data)
			rakFree_Ex(bcs->data, _FILE_AND_LINE_);

		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
	}
	bufferedCommands.Clear(_FILE_AND_LINE_);
}

void RakPeer::ClearSocketQueryOutput(void)
{
	socketQueryOutput.Clear(_FILE_AND_LINE_);
}

void RakPeer::ClearRequestedConnectionList(void)
{
	DataStructures::Queue<RequestedConnectionStruct *> freeQueue;
	requestedConnectionQueueMutex.Lock();
	while (requestedConnectionQueue.Size())
		freeQueue.Push(requestedConnectionQueue.Pop(), _FILE_AND_LINE_);
	requestedConnectionQueueMutex.Unlock();
	unsigned i;
	for (i = 0; i < freeQueue.Size(); i++)
	{
#if LIBCAT_SECURITY == 1
		CAT_AUDIT_PRINTF("AUDIT: In ClearRequestedConnectionList(), Deleting freeQueue index %i client_handshake %x\n", i, freeQueue[i]->client_handshake);
		RakNet::OP_DELETE(freeQueue[i]->client_handshake, _FILE_AND_LINE_);
#endif
		RakNet::OP_DELETE(freeQueue[i], _FILE_AND_LINE_);
	}
}

inline void RakPeer::AddPacketToProducer(RakNet::Packet *p)
{
	packetReturnMutex.Lock();
	packetReturnQueue.Push(p, _FILE_AND_LINE_);
	packetReturnMutex.Unlock();
}

uint64_t RakPeerInterface::Get64BitUniqueRandomNumber(void)
{
	uint64_t g = 0;

#if defined(_WIN32)
	g = RakNet::GetTimeUS();
#else
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	g = static_cast<uint64_t>(tv.tv_sec) * 1000000 + static_cast<uint64_t>(tv.tv_usec);
#endif

	std::random_device rd;
	std::mt19937_64 gen(rd());
	std::uniform_int_distribution<uint64_t> dis;
	uint64_t randomValue = dis(gen);

#if defined(_WIN32)
	DWORD processId = GetCurrentProcessId();
#else
	pid_t processId = getpid();
#endif

	g ^= randomValue;
	g ^= processId;

	for (int i = 0; i < 9; ++i)
	{
		uint32_t diff4Bits = (uint32_t)((((g - randomValue) ^ RakNet::GetTimeUS()) << (randomValue >> i)) & 15);
		diff4Bits <<= 32 - 4;
		diff4Bits >>= i * 4;
		((char *)&g)[i] ^= diff4Bits;
	}

	return g;
}

void RakPeer::GenerateGUID(void)
{
	myGuid.g = Get64BitUniqueRandomNumber();
}

namespace RakNet
{
	bool ProcessOfflineNetworkPacket(SystemAddress systemAddress, const char *data, const int length, RakPeer *rakPeer, RakNetSocket2 *rakNetSocket, bool *isOfflineMessage, RakNet::TimeUS timeRead)
	{
		(void)timeRead;
		RakPeer::RemoteSystemStruct *remoteSystem;
		RakNet::Packet *packet;
		unsigned i;

		char str1[64];
		systemAddress.ToString(false, str1);
		if (rakPeer->IsBanned(str1))
		{
			for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
				rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length * 8, systemAddress);

			RakNet::BitStream bs;
			bs.Write<MessageID>(ID_CONNECTION_BANNED);
			bs.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
			bs.Write<RakNetGUID>(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));

			RNS2_SendParameters bsp;
			bsp.data = (char *)bs.GetData();
			bsp.length = bs.GetNumberOfBytesUsed();
			bsp.systemAddress = systemAddress;
			for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
				rakPeer->pluginListNTS[i]->OnDirectSocketSend((char *)bs.GetData(), bs.GetNumberOfBitsUsed(), systemAddress);
			rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

			return true;
		}

		// The reason for all this is that the reliability layer has no way to tell between offline messages that arrived late for a player that is now connected,
		// and a regular encoding. So I insert OFFLINE_MESSAGE_DATA_ID into the stream, the encoding of which is essentially impossible to hit by chance
		if (length <= 2)
		{
			*isOfflineMessage = true;
		}
		else if (
			((uint8_t)data[0] == ID_UNCONNECTED_PING ||
			 (uint8_t)data[0] == ID_UNCONNECTED_PING_OPEN_CONNECTIONS) &&
			length >= sizeof(uint8_t) + sizeof(RakNet::Time) + sizeof(OFFLINE_MESSAGE_DATA_ID))
		{
			*isOfflineMessage = memcmp(data + sizeof(uint8_t) + sizeof(RakNet::Time), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID)) == 0;
		}
		else if ((uint8_t)data[0] == ID_UNCONNECTED_PONG && (size_t)length >= sizeof(uint8_t) + sizeof(RakNet::TimeMS) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID))
		{
			*isOfflineMessage = memcmp(data + sizeof(uint8_t) + sizeof(RakNet::Time) + RakNetGUID::size(), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID)) == 0;
		}
		else if (
			(uint8_t)data[0] == ID_OUT_OF_BAND_INTERNAL &&
			(size_t)length >= sizeof(MessageID) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID))
		{
			*isOfflineMessage = memcmp(data + sizeof(MessageID) + RakNetGUID::size(), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID)) == 0;
		}
		else if (
			(
				(uint8_t)data[0] == ID_OPEN_CONNECTION_REPLY_1 ||
				(uint8_t)data[0] == ID_OPEN_CONNECTION_REPLY_2 ||
				(uint8_t)data[0] == ID_OPEN_CONNECTION_REQUEST_1 ||
				(uint8_t)data[0] == ID_OPEN_CONNECTION_REQUEST_2 ||
				(uint8_t)data[0] == ID_CONNECTION_ATTEMPT_FAILED ||
				(uint8_t)data[0] == ID_NO_FREE_INCOMING_CONNECTIONS ||
				(uint8_t)data[0] == ID_CONNECTION_BANNED ||
				(uint8_t)data[0] == ID_ALREADY_CONNECTED ||
				(uint8_t)data[0] == ID_IP_RECENTLY_CONNECTED) &&
			(size_t)length >= sizeof(MessageID) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID))
		{
			*isOfflineMessage = memcmp(data + sizeof(MessageID), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID)) == 0;
		}
		else if (((uint8_t)data[0] == ID_INCOMPATIBLE_PROTOCOL_VERSION &&
				  (size_t)length == sizeof(MessageID) * 2 + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID)))
		{
			*isOfflineMessage = memcmp(data + sizeof(MessageID) * 2, OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID)) == 0;
		}
		else
		{
			*isOfflineMessage = false;
		}

		if (*isOfflineMessage)
		{
			for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
				rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length * 8, systemAddress);

			// These are all messages from unconnected systems.  Messages here can be any size, but are never processed from connected systems.
			if (((uint8_t)data[0] == ID_UNCONNECTED_PING_OPEN_CONNECTIONS || (uint8_t)(data)[0] == ID_UNCONNECTED_PING) && length >= sizeof(uint8_t) + sizeof(RakNet::Time) + sizeof(OFFLINE_MESSAGE_DATA_ID))
			{
				if ((uint8_t)(data)[0] == ID_UNCONNECTED_PING ||
					rakPeer->AllowIncomingConnections()) // Open connections with players
				{
					RakNet::BitStream inBitStream((uint8_t *)data, length, false);
					inBitStream.IgnoreBits(8);
					RakNet::Time sendPingTime;
					inBitStream.Read<RakNet::Time>(sendPingTime);
					inBitStream.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
					RakNetGUID remoteGuid = UNASSIGNED_RAKNET_GUID;
					inBitStream.Read<RakNetGUID>(remoteGuid);

					RakNet::BitStream outBitStream;
					outBitStream.Write<MessageID>(ID_UNCONNECTED_PONG);
					outBitStream.Write<RakNet::Time>(sendPingTime);
					outBitStream.Write<RakNetGUID>(rakPeer->myGuid);
					outBitStream.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));

					rakPeer->rakPeerMutexes[RakPeer::offlinePingResponse_Mutex].Lock();
					outBitStream.Write((char *)rakPeer->offlinePingResponse.GetData(), rakPeer->offlinePingResponse.GetNumberOfBytesUsed());
					rakPeer->rakPeerMutexes[RakPeer::offlinePingResponse_Mutex].Unlock();

					unsigned i;
					for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
						rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)outBitStream.GetData(), outBitStream.GetNumberOfBytesUsed(), systemAddress);

					RNS2_SendParameters bsp;
					bsp.data = (char *)outBitStream.GetData();
					bsp.length = outBitStream.GetNumberOfBytesUsed();
					bsp.systemAddress = systemAddress;
					rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

					packet = rakPeer->AllocPacket(sizeof(MessageID), _FILE_AND_LINE_);
					packet->data[0] = data[0];
					packet->systemAddress = systemAddress;
					packet->guid = remoteGuid;
					packet->systemAddress.systemIndex = (SystemIndex)rakPeer->GetIndexFromSystemAddress(systemAddress, true);
					packet->guid.systemIndex = packet->systemAddress.systemIndex;
					rakPeer->AddPacketToProducer(packet);
				}
			}
			else if ((uint8_t)data[0] == ID_UNCONNECTED_PONG && (size_t)length >= sizeof(uint8_t) + sizeof(RakNet::Time) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID) && (size_t)length < sizeof(uint8_t) + sizeof(RakNet::Time) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID) + MAX_OFFLINE_DATA_LENGTH)
			{
				packet = rakPeer->AllocPacket((unsigned int)(length - sizeof(OFFLINE_MESSAGE_DATA_ID) - RakNetGUID::size() - sizeof(RakNet::Time) + sizeof(RakNet::TimeMS)), _FILE_AND_LINE_);
				RakNet::BitStream bsIn((uint8_t *)data, length, false);
				bsIn.IgnoreBytes(sizeof(uint8_t));
				RakNet::Time ping;
				bsIn.Read<RakNet::Time>(ping);
				bsIn.Read<RakNetGUID>(packet->guid);

				RakNet::BitStream bsOut((uint8_t *)packet->data, packet->length, false);
				bsOut.ResetWritePointer();
				bsOut.Write<MessageID>(ID_UNCONNECTED_PONG);
				RakNet::TimeMS pingMS = (RakNet::TimeMS)ping;
				bsOut.Write<RakNet::Time>(pingMS);
				bsOut.WriteAlignedBytes(
					(const uint8_t *)data + sizeof(uint8_t) + sizeof(RakNet::Time) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID),
					length - sizeof(uint8_t) - sizeof(RakNet::Time) - RakNetGUID::size() - sizeof(OFFLINE_MESSAGE_DATA_ID));

				packet->systemAddress = systemAddress;
				packet->systemAddress.systemIndex = (SystemIndex)rakPeer->GetIndexFromSystemAddress(systemAddress, true);
				packet->guid.systemIndex = packet->systemAddress.systemIndex;
				rakPeer->AddPacketToProducer(packet);
			}
			else if ((uint8_t)data[0] == ID_OUT_OF_BAND_INTERNAL &&
					 (size_t)length > sizeof(OFFLINE_MESSAGE_DATA_ID) + sizeof(MessageID) + RakNetGUID::size() &&
					 (size_t)length < MAX_OFFLINE_DATA_LENGTH + sizeof(OFFLINE_MESSAGE_DATA_ID) + sizeof(MessageID) + RakNetGUID::size())
			{
				unsigned int dataLength = (unsigned int)(length - sizeof(OFFLINE_MESSAGE_DATA_ID) - RakNetGUID::size() - sizeof(MessageID));
				RakAssert(dataLength < 1024);
				packet = rakPeer->AllocPacket(dataLength + 1, _FILE_AND_LINE_);
				RakAssert(packet->length < 1024);

				RakNet::BitStream bs2((uint8_t *)data, length, false);
				bs2.IgnoreBytes(sizeof(MessageID));
				bs2.Read<RakNetGUID>(packet->guid);

				if (data[sizeof(OFFLINE_MESSAGE_DATA_ID) + sizeof(MessageID) + RakNetGUID::size()] == ID_ADVERTISE_SYSTEM)
				{
					packet->length--;
					packet->bitSize = BYTES_TO_BITS(packet->length);
					packet->data[0] = ID_ADVERTISE_SYSTEM;
					memcpy(packet->data + 1, data + sizeof(OFFLINE_MESSAGE_DATA_ID) + sizeof(MessageID) * 2 + RakNetGUID::size(), dataLength - 1);
				}
				else
				{
					packet->data[0] = ID_OUT_OF_BAND_INTERNAL;
					memcpy(packet->data + 1, data + sizeof(OFFLINE_MESSAGE_DATA_ID) + sizeof(MessageID) + RakNetGUID::size(), dataLength);
				}

				packet->systemAddress = systemAddress;
				packet->systemAddress.systemIndex = (SystemIndex)rakPeer->GetIndexFromSystemAddress(systemAddress, true);
				packet->guid.systemIndex = packet->systemAddress.systemIndex;
				rakPeer->AddPacketToProducer(packet);
			}
			else if ((uint8_t)(data)[0] == (MessageID)ID_OPEN_CONNECTION_REPLY_1)
			{
				for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
					rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length * 8, systemAddress);

				RakNet::BitStream bsIn((uint8_t *)data, length, false);
				bsIn.IgnoreBytes(sizeof(MessageID));
				bsIn.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
				RakNetGUID serverGuid;
				bsIn.Read<RakNetGUID>(serverGuid);
				uint8_t serverHasSecurity;
				uint32_t cookie;
				(void)cookie;
				bsIn.Read<uint8_t>(serverHasSecurity);
				// Even if the server has security, it may not be required of us if we are in the security exception list
				if (serverHasSecurity)
				{
					bsIn.Read<uint32_t>(cookie);
				}

				RakNet::BitStream bsOut;
				bsOut.Write<MessageID>(ID_OPEN_CONNECTION_REQUEST_2);
				bsOut.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				if (serverHasSecurity)
					bsOut.Write<uint32_t>(cookie);

				unsigned i;
				rakPeer->requestedConnectionQueueMutex.Lock();
				for (i = 0; i < rakPeer->requestedConnectionQueue.Size(); i++)
				{
					RakPeer::RequestedConnectionStruct *rcs;
					rcs = rakPeer->requestedConnectionQueue[i];
					if (rcs->systemAddress == systemAddress)
					{
						if (serverHasSecurity)
						{
#if LIBCAT_SECURITY == 1
							uint8_t public_key[cat::EasyHandshake::PUBLIC_KEY_BYTES];
							bsIn.ReadAlignedBytes(public_key, sizeof(public_key));

							if (rcs->publicKeyMode == PKM_ACCEPT_ANY_PUBLIC_KEY)
							{
								memcpy(rcs->remote_public_key, public_key, cat::EasyHandshake::PUBLIC_KEY_BYTES);
								if (!rcs->client_handshake->Initialize(public_key) ||
									!rcs->client_handshake->GenerateChallenge(rcs->handshakeChallenge))
								{
									CAT_AUDIT_PRINTF("AUDIT: Server passed a bad public key with PKM_ACCEPT_ANY_PUBLIC_KEY");
									return true;
								}
							}

							if (cat::SecureEqual(public_key,
												 rcs->remote_public_key,
												 cat::EasyHandshake::PUBLIC_KEY_BYTES) == false)
							{
								rakPeer->requestedConnectionQueueMutex.Unlock();
								CAT_AUDIT_PRINTF("AUDIT: Expected public key does not match what was sent by server -- Reporting back ID_PUBLIC_KEY_MISMATCH to user\n");

								packet = rakPeer->AllocPacket(sizeof(char), _FILE_AND_LINE_);
								packet->data[0] = ID_PUBLIC_KEY_MISMATCH; // Attempted a connection and couldn't
								packet->bitSize = (sizeof(char) * 8);
								packet->systemAddress = rcs->systemAddress;
								packet->guid = serverGuid;
								rakPeer->AddPacketToProducer(packet);
								return true;
							}

							bool hasChallenge = rcs->client_handshake != 0;
							bsOut.Write<uint8_t>(hasChallenge ? 1 : 0);
							if (!hasChallenge)
							{
								// challenge
								CAT_AUDIT_PRINTF("AUDIT: Sending challenge\n");
								bsOut.WriteAlignedBytes((const uint8_t *)rcs->handshakeChallenge, cat::EasyHandshake::CHALLENGE_BYTES);
							}
#else // LIBCAT_SECURITY
	  // Message does not contain a challenge
							bsOut.Write<uint8_t>(0);
#endif // LIBCAT_SECURITY
						}
						else
						{
							// Server does not need security
#if LIBCAT_SECURITY == 1
							if (rcs->client_handshake != 0)
							{
								rakPeer->requestedConnectionQueueMutex.Unlock();
								CAT_AUDIT_PRINTF("AUDIT: Security disabled by server but we expected security (indicated by client_handshake not null) so failing!\n");

								packet = rakPeer->AllocPacket(sizeof(char), _FILE_AND_LINE_);
								packet->data[0] = ID_OUR_SYSTEM_REQUIRES_SECURITY; // Attempted a connection and couldn't
								packet->bitSize = (sizeof(char) * 8);
								packet->systemAddress = rcs->systemAddress;
								packet->guid = serverGuid;
								rakPeer->AddPacketToProducer(packet);
								return true;
							}
#endif // LIBCAT_SECURITY
						}

						uint16_t mtu;
						bsIn.Read<uint16_t>(mtu);

						bsOut.Write<SystemAddress>(rcs->systemAddress);
						rakPeer->requestedConnectionQueueMutex.Unlock();
						bsOut.Write<uint16_t>(mtu);
						bsOut.Write<RakNetGUID>(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));

						for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
							rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), rcs->systemAddress);

						RNS2_SendParameters bsp;
						bsp.data = (char *)bsOut.GetData();
						bsp.length = bsOut.GetNumberOfBytesUsed();
						bsp.systemAddress = systemAddress;
						rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

						return true;
					}
				}
				rakPeer->requestedConnectionQueueMutex.Unlock();
			}
			else if ((uint8_t)(data)[0] == (MessageID)ID_OPEN_CONNECTION_REPLY_2)
			{
				for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
					rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length * 8, systemAddress);

				RakNet::BitStream bs((uint8_t *)data, length, false);
				bs.IgnoreBytes(sizeof(MessageID));
				bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
				RakNetGUID guid;
				bs.Read<RakNetGUID>(guid);
				SystemAddress bindingAddress;
				bool b = bs.Read<SystemAddress>(bindingAddress);
				RakAssert(b);
				uint16_t mtu;
				b = bs.Read<uint16_t>(mtu);
				RakAssert(b);
				bool doSecurity = false;
				b = bs.Read<bool>(doSecurity);
				RakAssert(b);

#if LIBCAT_SECURITY == 1
				char answer[cat::EasyHandshake::ANSWER_BYTES];
				CAT_AUDIT_PRINTF("AUDIT: Got ID_OPEN_CONNECTION_REPLY_2 and given doSecurity=%i\n", (int)doSecurity);
				if (doSecurity)
				{
					CAT_AUDIT_PRINTF("AUDIT: Reading cookie and public key\n");
					bs.ReadAlignedBytes((uint8_t *)answer, sizeof(answer));
				}
				cat::ClientEasyHandshake *client_handshake = 0;
#endif // LIBCAT_SECURITY

				RakPeer::RequestedConnectionStruct *rcs;
				bool unlock = true;
				unsigned i;
				rakPeer->requestedConnectionQueueMutex.Lock();
				for (i = 0; i < rakPeer->requestedConnectionQueue.Size(); i++)
				{
					rcs = rakPeer->requestedConnectionQueue[i];

					if (rcs->systemAddress == systemAddress)
					{
#if LIBCAT_SECURITY == 1
						CAT_AUDIT_PRINTF("AUDIT: System address matches an entry in the requestedConnectionQueue and doSecurity=%i\n", (int)doSecurity);
						if (doSecurity)
						{
							if (rcs->client_handshake == 0)
							{
								CAT_AUDIT_PRINTF("AUDIT: Server wants security but we didn't set a public key -- Reporting back ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY to user\n");
								rakPeer->requestedConnectionQueueMutex.Unlock();

								packet = rakPeer->AllocPacket(2, _FILE_AND_LINE_);
								packet->data[0] = ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY; // Attempted a connection and couldn't
								packet->data[1] = 0;									// Indicate server public key is missing
								packet->bitSize = (sizeof(char) * 8);
								packet->systemAddress = rcs->systemAddress;
								packet->guid = guid;
								rakPeer->AddPacketToProducer(packet);
								return true;
							}

							CAT_AUDIT_PRINTF("AUDIT: Looks good, preparing to send challenge to server! client_handshake = %x\n", client_handshake);
						}

#endif // LIBCAT_SECURITY

						rakPeer->requestedConnectionQueueMutex.Unlock();
						unlock = false;

						RakAssert(rcs->actionToTake == RakPeer::RequestedConnectionStruct::CONNECT);
						// You might get this when already connected because of cross-connections
						bool thisIPConnectedRecently = false;
						remoteSystem = rakPeer->GetRemoteSystemFromSystemAddress(systemAddress, true, true);
						if (remoteSystem == 0)
						{
							if (rcs->socket == 0)
							{
								remoteSystem = rakPeer->AssignSystemAddressToRemoteSystemList(systemAddress, RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER, rakNetSocket, &thisIPConnectedRecently, bindingAddress, mtu, guid, doSecurity);
							}
							else
							{
								remoteSystem = rakPeer->AssignSystemAddressToRemoteSystemList(systemAddress, RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER, rcs->socket, &thisIPConnectedRecently, bindingAddress, mtu, guid, doSecurity);
							}
						}

						// 4/13/09 Attackers can flood ID_OPEN_CONNECTION_REQUEST and use up all available connection slots
						// Ignore connection attempts if this IP address connected within the last 100 milliseconds
						if (thisIPConnectedRecently == false)
						{
							// Don't check GetRemoteSystemFromGUID, server will verify
							if (remoteSystem)
							{
#if LIBCAT_SECURITY == 1
								cat::u8 ident[cat::EasyHandshake::IDENTITY_BYTES];
								bool doIdentity = false;

								if (rcs->client_handshake)
								{
									CAT_AUDIT_PRINTF("AUDIT: Processing answer\n");
									if (rcs->publicKeyMode == PKM_USE_TWO_WAY_AUTHENTICATION)
									{
										if (!rcs->client_handshake->ProcessAnswerWithIdentity(answer, ident, remoteSystem->reliabilityLayer.GetAuthenticatedEncryption()))
										{
											CAT_AUDIT_PRINTF("AUDIT: Processing answer -- Invalid Answer\n");
											rakPeer->requestedConnectionQueueMutex.Unlock();

											return true;
										}

										doIdentity = true;
									}
									else
									{
										if (!rcs->client_handshake->ProcessAnswer(answer, remoteSystem->reliabilityLayer.GetAuthenticatedEncryption()))
										{
											CAT_AUDIT_PRINTF("AUDIT: Processing answer -- Invalid Answer\n");
											rakPeer->requestedConnectionQueueMutex.Unlock();

											return true;
										}
									}
									CAT_AUDIT_PRINTF("AUDIT: Success!\n");

									RakNet::OP_DELETE(rcs->client_handshake, _FILE_AND_LINE_);
									rcs->client_handshake = 0;
								}
#endif // LIBCAT_SECURITY

								remoteSystem->weInitiatedTheConnection = true;
								remoteSystem->connectMode = RakPeer::RemoteSystemStruct::REQUESTED_CONNECTION;
								if (rcs->timeoutTime != 0)
									remoteSystem->reliabilityLayer.SetTimeoutTime(rcs->timeoutTime);

								RakNet::BitStream temp;
								temp.Write<MessageID>(ID_CONNECTION_REQUEST);
								temp.Write<RakNetGUID>(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
								temp.Write<RakNet::Time>(RakNet::GetTime());

#if LIBCAT_SECURITY == 1
								temp.Write<uint8_t>(doSecurity ? 1 : 0);

								if (doSecurity)
								{
									uint8_t proof[32];
									remoteSystem->reliabilityLayer.GetAuthenticatedEncryption()->GenerateProof(proof, sizeof(proof));
									temp.WriteAlignedBytes(proof, sizeof(proof));

									temp.Write<uint8_t>(doIdentity ? 1 : 0);

									if (doIdentity)
									{
										temp.WriteAlignedBytes(ident, sizeof(ident));
									}
								}
#else
								temp.Write<uint8_t>(0);
#endif // LIBCAT_SECURITY

								if (rcs->outgoingPasswordLength > 0)
									temp.Write((char *)rcs->outgoingPassword, rcs->outgoingPasswordLength);

								rakPeer->SendImmediate((char *)temp.GetData(), temp.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE, 0, systemAddress, false, false, timeRead, 0);
							}
							else
							{
								// Failed, no connections available anymore
								packet = rakPeer->AllocPacket(sizeof(char), _FILE_AND_LINE_);
								packet->data[0] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
								packet->bitSize = (sizeof(char) * 8);
								packet->systemAddress = rcs->systemAddress;
								packet->guid = guid;
								rakPeer->AddPacketToProducer(packet);
							}
						}

						rakPeer->requestedConnectionQueueMutex.Lock();
						for (unsigned int k = 0; k < rakPeer->requestedConnectionQueue.Size(); k++)
						{
							if (rakPeer->requestedConnectionQueue[k]->systemAddress == systemAddress)
							{
								rakPeer->requestedConnectionQueue.RemoveAtIndex(k);
								break;
							}
						}
						rakPeer->requestedConnectionQueueMutex.Unlock();

#if LIBCAT_SECURITY == 1
						CAT_AUDIT_PRINTF("AUDIT: Deleting client_handshake object %x and rcs->client_handshake object %x\n", client_handshake, rcs->client_handshake);
						RakNet::OP_DELETE(client_handshake, _FILE_AND_LINE_);
						RakNet::OP_DELETE(rcs->client_handshake, _FILE_AND_LINE_);
#endif // LIBCAT_SECURITY
						RakNet::OP_DELETE(rcs, _FILE_AND_LINE_);

						break;
					}
				}

				if (unlock)
					rakPeer->requestedConnectionQueueMutex.Unlock();

				return true;
			}
			else if ((uint8_t)(data)[0] == (MessageID)ID_CONNECTION_ATTEMPT_FAILED ||
					 (uint8_t)(data)[0] == (MessageID)ID_NO_FREE_INCOMING_CONNECTIONS ||
					 (uint8_t)(data)[0] == (MessageID)ID_CONNECTION_BANNED ||
					 (uint8_t)(data)[0] == (MessageID)ID_ALREADY_CONNECTED ||
					 (uint8_t)(data)[0] == (MessageID)ID_INVALID_PASSWORD ||
					 (uint8_t)(data)[0] == (MessageID)ID_IP_RECENTLY_CONNECTED ||
					 (uint8_t)(data)[0] == (MessageID)ID_INCOMPATIBLE_PROTOCOL_VERSION)
			{

				RakNet::BitStream bs((uint8_t *)data, length, false);
				bs.IgnoreBytes(sizeof(MessageID));
				bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
				if ((uint8_t)(data)[0] == (MessageID)ID_INCOMPATIBLE_PROTOCOL_VERSION)
					bs.IgnoreBytes(sizeof(uint8_t));

				RakNetGUID guid;
				bs.Read<RakNetGUID>(guid);

				RakPeer::RequestedConnectionStruct *rcs;
				bool connectionAttemptCancelled = false;
				unsigned i;
				rakPeer->requestedConnectionQueueMutex.Lock();
				for (i = 0; i < rakPeer->requestedConnectionQueue.Size(); i++)
				{
					rcs = rakPeer->requestedConnectionQueue[i];
					if (rcs->actionToTake == RakPeer::RequestedConnectionStruct::CONNECT && rcs->systemAddress == systemAddress)
					{
						connectionAttemptCancelled = true;
						rakPeer->requestedConnectionQueue.RemoveAtIndex(i);

#if LIBCAT_SECURITY == 1
						CAT_AUDIT_PRINTF("AUDIT: Connection attempt canceled so deleting rcs->client_handshake object %x\n", rcs->client_handshake);
						RakNet::OP_DELETE(rcs->client_handshake, _FILE_AND_LINE_);
#endif // LIBCAT_SECURITY
						RakNet::OP_DELETE(rcs, _FILE_AND_LINE_);
						break;
					}
				}

				rakPeer->requestedConnectionQueueMutex.Unlock();

				if (connectionAttemptCancelled)
				{
					// Tell user of connection attempt failed
					packet = rakPeer->AllocPacket(sizeof(char), _FILE_AND_LINE_);
					packet->data[0] = data[0]; // Attempted a connection and couldn't
					packet->bitSize = (sizeof(char) * 8);
					packet->systemAddress = systemAddress;
					packet->guid = guid;
					rakPeer->AddPacketToProducer(packet);
				}
			}
			else if ((uint8_t)(data)[0] == ID_OPEN_CONNECTION_REQUEST_1 && length > (int)(1 + sizeof(OFFLINE_MESSAGE_DATA_ID)))
			{
				unsigned int i;
				char remoteProtocol = data[1 + sizeof(OFFLINE_MESSAGE_DATA_ID)];
				if (remoteProtocol != RAKNET_PROTOCOL_VERSION)
				{
					RakNet::BitStream bs;
					bs.Write<MessageID>(ID_INCOMPATIBLE_PROTOCOL_VERSION);
					bs.Write<uint8_t>(RAKNET_PROTOCOL_VERSION);
					bs.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
					bs.Write<RakNetGUID>(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));

					for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
						rakPeer->pluginListNTS[i]->OnDirectSocketSend((char *)bs.GetData(), bs.GetNumberOfBitsUsed(), systemAddress);

					RNS2_SendParameters bsp;
					bsp.data = (char *)bs.GetData();
					bsp.length = bs.GetNumberOfBytesUsed();
					bsp.systemAddress = systemAddress;

					rakNetSocket->Send(&bsp, _FILE_AND_LINE_);
					return true;
				}

				for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
					rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length * 8, systemAddress);

				RakNet::BitStream bsOut;
				bsOut.Write<MessageID>(ID_OPEN_CONNECTION_REPLY_1);
				bsOut.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				bsOut.Write<RakNetGUID>(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
#if LIBCAT_SECURITY == 1
				if (rakPeer->_using_security)
				{
					bsOut.Write<uint8_t>(1); // HasCookie Yes
					// Write cookie
					uint32_t cookie = rakPeer->_cookie_jar->Generate(&systemAddress.address, sizeof(systemAddress.address));
					CAT_AUDIT_PRINTF("AUDIT: Writing cookie %i to %i:%i\n", cookie, systemAddress);
					bsOut.Write<uint32_t>(cookie);
					// Write my public key
					bsOut.WriteAlignedBytes((const uint8_t *)rakPeer->my_public_key, sizeof(rakPeer->my_public_key));
				}
				else
#endif										 // LIBCAT_SECURITY
					bsOut.Write<uint8_t>(0); // HasCookie No

				// MTU. Lower MTU if it is exceeds our own limit
				if (length + UDP_HEADER_SIZE > MAXIMUM_MTU_SIZE)
					bsOut.WriteCasted<uint16_t>(MAXIMUM_MTU_SIZE);
				else
					bsOut.WriteCasted<uint16_t>(length + UDP_HEADER_SIZE);

				for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
					rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);

				RNS2_SendParameters bsp;
				bsp.data = (char *)bsOut.GetData();
				bsp.length = bsOut.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;
				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);
			}
			else if ((uint8_t)(data)[0] == ID_OPEN_CONNECTION_REQUEST_2)
			{
				SystemAddress bindingAddress;
				RakNetGUID guid;
				RakNet::BitStream bsOut;
				RakNet::BitStream bs((uint8_t *)data, length, false);
				bs.IgnoreBytes(sizeof(MessageID));
				bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));

				bool requiresSecurityOfThisClient = false;
#if LIBCAT_SECURITY == 1
				char remoteHandshakeChallenge[cat::EasyHandshake::CHALLENGE_BYTES];

				if (rakPeer->_using_security)
				{
					char str1[64];
					systemAddress.ToString(false, str1);
					requiresSecurityOfThisClient = rakPeer->IsInSecurityExceptionList(str1) == false;

					uint32_t cookie;
					bs.Read<uint32_t>(cookie);
					CAT_AUDIT_PRINTF("AUDIT: Got cookie %i from %i:%i\n", cookie, systemAddress);
					if (rakPeer->_cookie_jar->Verify(&systemAddress.address, sizeof(systemAddress.address), cookie) == false)
					{
						return true;
					}
					CAT_AUDIT_PRINTF("AUDIT: Cookie good!\n");

					uint8_t clientWroteChallenge;
					bs.Read<uint8_t>(clientWroteChallenge);

					if (requiresSecurityOfThisClient == true && clientWroteChallenge == 0)
					{
						// Fail, client doesn't support security, and it is required
						return true;
					}

					if (clientWroteChallenge)
					{
						bs.ReadAlignedBytes((uint8_t *)remoteHandshakeChallenge, cat::EasyHandshake::CHALLENGE_BYTES);
#ifdef CAT_AUDIT
						printf("AUDIT: RECV CHALLENGE ");
						for (int ii = 0; ii < sizeof(remoteHandshakeChallenge); ++ii)
						{
							printf("%02x", (cat::u8)remoteHandshakeChallenge[ii]);
						}
						printf("\n");
#endif
					}
				}
#endif // LIBCAT_SECURITY

				bs.Read<SystemAddress>(bindingAddress);
				uint16_t mtu;
				bs.Read<uint16_t>(mtu);
				bs.Read<RakNetGUID>(guid);

				RakPeer::RemoteSystemStruct *rssFromSA = rakPeer->GetRemoteSystemFromSystemAddress(systemAddress, true, true);
				bool IPAddrInUse = rssFromSA != 0 && rssFromSA->isActive;
				RakPeer::RemoteSystemStruct *rssFromGuid = rakPeer->GetRemoteSystemFromGUID(guid, true);
				bool GUIDInUse = rssFromGuid != 0 && rssFromGuid->isActive;

				// IPAddrInUse, GuidInUse, outcome
				// TRUE,	  , TRUE	 , ID_OPEN_CONNECTION_REPLY if they are the same, else ID_ALREADY_CONNECTED
				// FALSE,     , TRUE     , ID_ALREADY_CONNECTED (someone else took this guid)
				// TRUE,	  , FALSE	 , ID_ALREADY_CONNECTED (silently disconnected, restarted rakNet)
				// FALSE	  , FALSE	 , Allow connection
				int outcome;
				if (IPAddrInUse & GUIDInUse)
				{
					if (rssFromSA == rssFromGuid && rssFromSA->connectMode == RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER)
					{
						outcome = 1;
					}
					else
					{
						outcome = 2;
					}
				}
				else if (IPAddrInUse == false && GUIDInUse == true)
				{
					outcome = 3;
				}
				else if (IPAddrInUse == true && GUIDInUse == false)
				{
					outcome = 4;
				}
				else
				{
					outcome = 0;
				}

				RakNet::BitStream bsAnswer;
				bsAnswer.Write<MessageID>(ID_OPEN_CONNECTION_REPLY_2);
				bsAnswer.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				bsAnswer.Write<RakNetGUID>(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
				bsAnswer.Write<SystemAddress>(systemAddress);
				bsAnswer.Write<uint16_t>(mtu);
				bsAnswer.Write<bool>(requiresSecurityOfThisClient);

				if (outcome == 1)
				{
					// Duplicate connection request packet from packetloss
					// Send back the same answer
#if LIBCAT_SECURITY == 1
					if (requiresSecurityOfThisClient)
					{
						CAT_AUDIT_PRINTF("AUDIT: Resending public key and answer from packetloss.  Sending ID_OPEN_CONNECTION_REPLY_2\n");
						bsAnswer.WriteAlignedBytes((const uint8_t *)rssFromSA->answer, sizeof(rssFromSA->answer));
					}
#endif // LIBCAT_SECURITY

					unsigned int i;
					for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
						rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)bsAnswer.GetData(), bsAnswer.GetNumberOfBitsUsed(), systemAddress);

					RNS2_SendParameters bsp;
					bsp.data = (char *)bsAnswer.GetData();
					bsp.length = bsAnswer.GetNumberOfBytesUsed();
					bsp.systemAddress = systemAddress;
					rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

					return true;
				}
				else if (outcome != 0)
				{
					bsOut.Write<MessageID>(ID_ALREADY_CONNECTED);
					bsOut.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
					bsOut.Write<RakNetGUID>(rakPeer->myGuid);
					for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
						rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);
					RNS2_SendParameters bsp;
					bsp.data = (char *)bsOut.GetData();
					bsp.length = bsOut.GetNumberOfBytesUsed();
					bsp.systemAddress = systemAddress;
					rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

					return true;
				}

				if (rakPeer->AllowIncomingConnections() == false)
				{
					bsOut.Write<MessageID>(ID_NO_FREE_INCOMING_CONNECTIONS);
					bsOut.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
					bsOut.Write<RakNetGUID>(rakPeer->myGuid);
					for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
						rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);
					RNS2_SendParameters bsp;
					bsp.data = (char *)bsOut.GetData();
					bsp.length = bsOut.GetNumberOfBytesUsed();
					bsp.systemAddress = systemAddress;
					rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

					return true;
				}

				bool thisIPConnectedRecently = false;
				rssFromSA = rakPeer->AssignSystemAddressToRemoteSystemList(systemAddress, RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER, rakNetSocket, &thisIPConnectedRecently, bindingAddress, mtu, guid, requiresSecurityOfThisClient);

				if (thisIPConnectedRecently == true)
				{
					bsOut.Write<MessageID>(ID_IP_RECENTLY_CONNECTED);
					bsOut.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
					bsOut.Write<RakNetGUID>(rakPeer->myGuid);
					for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
						rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);

					RNS2_SendParameters bsp;
					bsp.data = (char *)bsOut.GetData();
					bsp.length = bsOut.GetNumberOfBytesUsed();
					bsp.systemAddress = systemAddress;
					rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

					return true;
				}

#if LIBCAT_SECURITY == 1
				if (requiresSecurityOfThisClient)
				{
					CAT_AUDIT_PRINTF("AUDIT: Writing public key.  Sending ID_OPEN_CONNECTION_REPLY_2\n");
					if (rakPeer->_server_handshake->ProcessChallenge(remoteHandshakeChallenge, rssFromSA->answer, rssFromSA->reliabilityLayer.GetAuthenticatedEncryption()))
					{
						CAT_AUDIT_PRINTF("AUDIT: Challenge good!\n");
					}
					else
					{
						CAT_AUDIT_PRINTF("AUDIT: Challenge BAD!\n");

						rakPeer->DereferenceRemoteSystem(systemAddress);
						return true;
					}

					bsAnswer.WriteAlignedBytes((const uint8_t *)rssFromSA->answer, sizeof(rssFromSA->answer));
				}
#endif // LIBCAT_SECURITY

				unsigned int i;
				for (i = 0; i < rakPeer->pluginListNTS.Size(); i++)
					rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char *)bsAnswer.GetData(), bsAnswer.GetNumberOfBitsUsed(), systemAddress);
				RNS2_SendParameters bsp;
				bsp.data = (char *)bsAnswer.GetData();
				bsp.length = bsAnswer.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;
				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);
			}
			return true;
		}

		return false;
	}

	void ProcessNetworkPacket(SystemAddress systemAddress, const char *data, const int length, RakPeer *rakPeer, RakNet::TimeUS timeRead, BitStream &updateBitStream)
	{
		ProcessNetworkPacket(systemAddress, data, length, rakPeer, rakPeer->socketList[0], timeRead, updateBitStream);
	}

	void ProcessNetworkPacket(SystemAddress systemAddress, const char *data, const int length, RakPeer *rakPeer, RakNetSocket2 *rakNetSocket, RakNet::TimeUS timeRead, BitStream &updateBitStream)
	{
#if LIBCAT_SECURITY == 1
#ifdef CAT_AUDIT
		printf("AUDIT: RECV ");
		for (int ii = 0; ii < length; ++ii)
		{
			printf("%02x", (cat::u8)data[ii]);
		}
		printf("\n");
#endif
#endif // LIBCAT_SECURITY

		RakAssert(systemAddress.GetPort());
		bool isOfflineMessage;
		if (ProcessOfflineNetworkPacket(systemAddress, data, length, rakPeer, rakNetSocket, &isOfflineMessage, timeRead))
		{
			return;
		}

		RakPeer::RemoteSystemStruct *remoteSystem;

		remoteSystem = rakPeer->GetRemoteSystemFromSystemAddress(systemAddress, true, true);
		if (remoteSystem)
		{
			if (isOfflineMessage == false)
			{
				remoteSystem->reliabilityLayer.HandleSocketReceiveFromConnectedPlayer(
					data, length, systemAddress, rakPeer->pluginListNTS, remoteSystem->MTUSize,
					rakNetSocket, &rnr, timeRead, updateBitStream);
			}
		}
	}
}

unsigned int RakPeer::GenerateSeedFromGuid(void)
{
	return (unsigned int)((myGuid.g >> 32) ^ myGuid.g);
}

void RakPeer::DerefAllSockets(void)
{
	unsigned int i;
	for (i = 0; i < socketList.Size(); i++)
	{
		delete socketList[i];
	}
	socketList.Clear(false, _FILE_AND_LINE_);
}

unsigned int RakPeer::GetRakNetSocketFromUserConnectionSocketIndex(unsigned int userIndex) const
{
	unsigned int i;
	for (i = 0; i < socketList.Size(); i++)
	{
		if (socketList[i]->GetUserConnectionSocketIndex() == userIndex)
			return i;
	}
	RakAssert("GetRakNetSocketFromUserConnectionSocketIndex failed" && 0);
	return (unsigned int)-1;
}

bool RakPeer::RunUpdateCycle(BitStream &updateBitStream)
{
	RakPeer::RemoteSystemStruct *remoteSystem;
	unsigned int activeSystemListIndex;
	Packet *packet;
	BitSize_t bitSize;
	unsigned int byteSize;
	uint8_t *data;
	SystemAddress systemAddress;
	BufferedCommandStruct *bcs;
	bool callerDataAllocationUsed;
	RakNetStatistics *rnss;
	RakNet::TimeUS timeNS = 0;
	RakNet::Time timeMS = 0;

#ifdef _WIN32
	if (socketList[0]->GetSocketType() == RNS2T_WINDOWS && ((RNS2_Windows *)socketList[0])->GetSocketLayerOverride())
	{
		int len;
		SystemAddress sender;
		char dataOut[MAXIMUM_MTU_SIZE];
		do
		{
			len = ((RNS2_Windows *)socketList[0])->GetSocketLayerOverride()->RakNetRecvFrom(dataOut, &sender, true);
			if (len > 0)
				ProcessNetworkPacket(sender, dataOut, len, this, socketList[0], RakNet::GetTimeUS(), updateBitStream);
		} while (len > 0);
	}
#endif

	RNS2RecvStruct *recvFromStruct;
	while ((recvFromStruct = PopBufferedPacket()) != 0)
	{
		ProcessNetworkPacket(recvFromStruct->systemAddress, recvFromStruct->data, recvFromStruct->bytesRead, this, recvFromStruct->socket, recvFromStruct->timeRead, updateBitStream);
		DeallocRNS2RecvStruct(recvFromStruct, _FILE_AND_LINE_);
	}

	while ((bcs = bufferedCommands.PopInaccurate()) != 0)
	{
		if (bcs->command == BufferedCommandStruct::BCS_SEND)
		{
			if (timeNS == 0)
			{
				timeNS = RakNet::GetTimeUS();
				timeMS = (RakNet::TimeMS)(timeNS / (RakNet::TimeUS)1000);
			}

			callerDataAllocationUsed = SendImmediate((char *)bcs->data, bcs->numberOfBitsToSend, bcs->priority, bcs->reliability, bcs->orderingChannel, bcs->systemIdentifier, bcs->broadcast, true, timeNS, bcs->receipt);
			if (callerDataAllocationUsed == false)
				rakFree_Ex(bcs->data, _FILE_AND_LINE_);

			if (bcs->connectionMode != RemoteSystemStruct::NO_ACTION)
			{
				remoteSystem = GetRemoteSystem(bcs->systemIdentifier, true, true);
				if (remoteSystem)
					remoteSystem->connectMode = bcs->connectionMode;
			}
		}
		else if (bcs->command == BufferedCommandStruct::BCS_CLOSE_CONNECTION)
		{
			CloseConnectionInternal(bcs->systemIdentifier, false, true, bcs->orderingChannel, bcs->priority);
		}
		else if (bcs->command == BufferedCommandStruct::BCS_CHANGE_SYSTEM_ADDRESS)
		{
			RakPeer::RemoteSystemStruct *rssFromGuid = GetRemoteSystem(bcs->systemIdentifier.rakNetGuid, true, true);
			if (rssFromGuid != 0)
			{
				unsigned int existingSystemIndex = GetRemoteSystemIndex(rssFromGuid->systemAddress);
				ReferenceRemoteSystem(bcs->systemIdentifier.systemAddress, existingSystemIndex);
			}
		}
		else if (bcs->command == BufferedCommandStruct::BCS_GET_SOCKET)
		{
			SocketQueryOutput *sqo;
			if (bcs->systemIdentifier.IsUndefined())
			{
				sqo = socketQueryOutput.Allocate(_FILE_AND_LINE_);
				sqo->sockets = socketList;
				socketQueryOutput.Push(sqo);
			}
			else
			{
				remoteSystem = GetRemoteSystem(bcs->systemIdentifier, true, true);
				sqo = socketQueryOutput.Allocate(_FILE_AND_LINE_);

				sqo->sockets.Clear(false, _FILE_AND_LINE_);
				if (remoteSystem)
				{
					sqo->sockets.Push(remoteSystem->rakNetSocket, _FILE_AND_LINE_);
				}
				socketQueryOutput.Push(sqo);
			}
		}

#ifdef _DEBUG
		bcs->data = 0;
#endif

		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
	}

	if (requestedConnectionQueue.IsEmpty() == false)
	{
		if (timeNS == 0)
		{
			timeNS = RakNet::GetTimeUS();
			timeMS = (RakNet::TimeMS)(timeNS / (RakNet::TimeUS)1000);
		}

		bool condition1, condition2;
		unsigned requestedConnectionQueueIndex = 0;
		requestedConnectionQueueMutex.Lock();
		while (requestedConnectionQueueIndex < requestedConnectionQueue.Size())
		{
			RequestedConnectionStruct *rcs;
			rcs = requestedConnectionQueue[requestedConnectionQueueIndex];
			requestedConnectionQueueMutex.Unlock();
			if (rcs->nextRequestTime < timeMS)
			{
				condition1 = rcs->requestsMade == rcs->sendConnectionAttemptCount + 1;
				condition2 = (bool)((rcs->systemAddress == UNASSIGNED_SYSTEM_ADDRESS) == 1);
				if (condition1 || condition2)
				{
					if (rcs->data)
					{
						rakFree_Ex(rcs->data, _FILE_AND_LINE_);
						rcs->data = 0;
					}

					if (condition1 && !condition2 && rcs->actionToTake == RequestedConnectionStruct::CONNECT)
					{
						packet = AllocPacket(sizeof(char), _FILE_AND_LINE_);
						packet->data[0] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
						packet->bitSize = (sizeof(char) * 8);
						packet->systemAddress = rcs->systemAddress;
						AddPacketToProducer(packet);
					}

#if LIBCAT_SECURITY == 1
					CAT_AUDIT_PRINTF("AUDIT: Connection attempt FAILED so deleting rcs->client_handshake object %x\n", rcs->client_handshake);
					RakNet::OP_DELETE(rcs->client_handshake, _FILE_AND_LINE_);
#endif
					RakNet::OP_DELETE(rcs, _FILE_AND_LINE_);

					requestedConnectionQueueMutex.Lock();
					for (unsigned int k = 0; k < requestedConnectionQueue.Size(); k++)
					{
						if (requestedConnectionQueue[k] == rcs)
						{
							requestedConnectionQueue.RemoveAtIndex(k);
							break;
						}
					}
					requestedConnectionQueueMutex.Unlock();
				}
				else
				{
					int MTUSizeIndex = rcs->requestsMade / (rcs->sendConnectionAttemptCount / NUM_MTU_SIZES);
					if (MTUSizeIndex >= NUM_MTU_SIZES)
						MTUSizeIndex = NUM_MTU_SIZES - 1;
					rcs->requestsMade++;
					rcs->nextRequestTime = timeMS + rcs->timeBetweenSendConnectionAttemptsMS;

					RakNet::BitStream bitStream;
					bitStream.Write<MessageID>(ID_OPEN_CONNECTION_REQUEST_1);
					bitStream.WriteAlignedBytes((const uint8_t *)OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
					bitStream.Write<MessageID>(RAKNET_PROTOCOL_VERSION);
					bitStream.PadWithZeroToByteLength(mtuSizes[MTUSizeIndex] - UDP_HEADER_SIZE);

					char str[256];
					rcs->systemAddress.ToString(true, str);

					unsigned i;
					for (i = 0; i < pluginListNTS.Size(); i++)
						pluginListNTS[i]->OnDirectSocketSend((const char *)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), rcs->systemAddress);

					RakNetSocket2 *socketToUse;
					if (rcs->socket == 0)
						socketToUse = socketList[rcs->socketIndex];
					else
						socketToUse = rcs->socket;

					rcs->systemAddress.FixForIPVersion(socketToUse->GetBoundAddress());
#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
					if (socketToUse->IsBerkleySocket())
						((RNS2_Berkley *)socketToUse)->SetDoNotFragment(1);
#endif

					RakNet::Time sendToStart = RakNet::GetTime();

					RNS2_SendParameters bsp;
					bsp.data = (char *)bitStream.GetData();
					bsp.length = bitStream.GetNumberOfBytesUsed();
					bsp.systemAddress = rcs->systemAddress;
					if (socketToUse->Send(&bsp, _FILE_AND_LINE_) == 10040)
					{
						// Don't use this MTU size again
						rcs->requestsMade = (uint8_t)((MTUSizeIndex + 1) * (rcs->sendConnectionAttemptCount / NUM_MTU_SIZES));
						rcs->nextRequestTime = timeMS;
					}
					else
					{
						RakNet::Time sendToEnd = RakNet::GetTime();
						if (sendToEnd - sendToStart > 100)
						{
							// Drop to lowest MTU
							int lowestMtuIndex = rcs->sendConnectionAttemptCount / NUM_MTU_SIZES * (NUM_MTU_SIZES - 1);
							if (lowestMtuIndex > rcs->requestsMade)
							{
								rcs->requestsMade = (uint8_t)lowestMtuIndex;
								rcs->nextRequestTime = timeMS;
							}
							else
								rcs->requestsMade = (uint8_t)(rcs->sendConnectionAttemptCount + 1);
						}
					}
#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
					if (socketToUse->IsBerkleySocket())
						((RNS2_Berkley *)socketToUse)->SetDoNotFragment(0);
#endif

					requestedConnectionQueueIndex++;
				}
			}
			else
				requestedConnectionQueueIndex++;

			requestedConnectionQueueMutex.Lock();
		}
		requestedConnectionQueueMutex.Unlock();
	}

	for (activeSystemListIndex = 0; activeSystemListIndex < activeSystemListSize; ++activeSystemListIndex)
	{
		remoteSystem = activeSystemList[activeSystemListIndex];
		systemAddress = remoteSystem->systemAddress;
		RakAssert(systemAddress != UNASSIGNED_SYSTEM_ADDRESS);

		if (timeNS == 0)
		{
			timeNS = RakNet::GetTimeUS();
			timeMS = (RakNet::TimeMS)(timeNS / (RakNet::TimeUS)1000);
		}

		if (timeMS > remoteSystem->lastReliableSend && timeMS - remoteSystem->lastReliableSend > remoteSystem->reliabilityLayer.GetTimeoutTime() / 2 && remoteSystem->connectMode == RemoteSystemStruct::CONNECTED)
		{
			// If no reliable packets are waiting for an ack, do a one byte reliable send so that disconnections are noticed
			RakNetStatistics rakNetStatistics;
			rnss = remoteSystem->reliabilityLayer.GetStatistics(&rakNetStatistics);
			if (rnss->messagesInResendBuffer == 0)
			{
				PingInternal(systemAddress, true, RELIABLE);

				remoteSystem->lastReliableSend = timeMS;
			}
		}

		remoteSystem->reliabilityLayer.Update(remoteSystem->rakNetSocket, systemAddress, remoteSystem->MTUSize, timeNS, maxOutgoingBPS, pluginListNTS, &rnr, updateBitStream); // systemAddress only used for the internet simulator test

		if (remoteSystem->reliabilityLayer.IsDeadConnection() ||
			((remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ASAP || remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY) && remoteSystem->reliabilityLayer.IsOutgoingDataWaiting() == false) ||
			(remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ON_NO_ACK && (remoteSystem->reliabilityLayer.AreAcksWaiting() == false || remoteSystem->reliabilityLayer.AckTimeout(timeMS) == true)) ||
			((
				(remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION ||
				 remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST ||
				 remoteSystem->connectMode == RemoteSystemStruct::UNVERIFIED_SENDER) &&
				timeMS > remoteSystem->connectionTime && timeMS - remoteSystem->connectionTime > 10000)))
		{
			if (remoteSystem->connectMode == RemoteSystemStruct::CONNECTED || remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION || remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ASAP || remoteSystem->connectMode == RemoteSystemStruct::DISCONNECT_ON_NO_ACK)
			{
				packet = AllocPacket(sizeof(char), _FILE_AND_LINE_);
				if (remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION)
					packet->data[0] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
				else if (remoteSystem->connectMode == RemoteSystemStruct::CONNECTED)
					packet->data[0] = ID_CONNECTION_LOST; // DeadConnection
				else
					packet->data[0] = ID_DISCONNECTION_NOTIFICATION; // DeadConnection

				packet->guid = remoteSystem->guid;
				packet->systemAddress = systemAddress;
				packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
				packet->guid.systemIndex = packet->systemAddress.systemIndex;

				AddPacketToProducer(packet);
			}

#ifdef _DO_PRINTF
			RAKNET_DEBUG_PRINTF("Connection dropped for player %i:%i\n", systemAddress);
#endif
			CloseConnectionInternal(systemAddress, false, true, 0, LOW_PRIORITY);
			continue;
		}

		if (remoteSystem->connectMode == RemoteSystemStruct::CONNECTED && timeMS > remoteSystem->nextPingTime && (occasionalPing || remoteSystem->lowestPing == (unsigned short)-1))
		{
			remoteSystem->nextPingTime = timeMS + 5000;
			PingInternal(systemAddress, true, UNRELIABLE);

			// Update again immediately after this tick so the ping goes out right away
			quitAndDataEvents.SetEvent();
		}

		bitSize = remoteSystem->reliabilityLayer.Receive(&data);

		while (bitSize > 0)
		{
			if (data[0] == ID_CONNECTION_ATTEMPT_FAILED)
			{
				RakAssert(0);
				bitSize = 0;
				continue;
			}

			byteSize = (unsigned int)BITS_TO_BYTES(bitSize);

			if (remoteSystem->connectMode == RemoteSystemStruct::UNVERIFIED_SENDER)
			{
				if ((uint8_t)(data)[0] == ID_CONNECTION_REQUEST)
				{
					ParseConnectionRequestPacket(remoteSystem, systemAddress, (const char *)data, byteSize);
					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else
				{
					CloseConnectionInternal(systemAddress, false, true, 0, LOW_PRIORITY);
#ifdef _DO_PRINTF
					RAKNET_DEBUG_PRINTF("Temporarily banning %i:%i for sending nonsense data\n", systemAddress);
#endif

					char str1[64];
					systemAddress.ToString(false, str1);
					AddToBanList(str1, remoteSystem->reliabilityLayer.GetTimeoutTime());

					rakFree_Ex(data, _FILE_AND_LINE_);
				}
			}
			else
			{
				if ((uint8_t)(data)[0] == ID_CONNECTION_REQUEST)
				{
					if (remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION)
					{
						ParseConnectionRequestPacket(remoteSystem, systemAddress, (const char *)data, byteSize);
					}
					else
					{

						RakNet::BitStream bs((uint8_t *)data, byteSize, false);
						bs.IgnoreBytes(sizeof(MessageID));
						bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
						bs.IgnoreBytes(RakNetGUID::size());
						RakNet::Time incomingTimestamp;
						bs.Read<RakNet::Time>(incomingTimestamp);

						OnConnectionRequest(remoteSystem, incomingTimestamp);
					}
					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((uint8_t)data[0] == ID_NEW_INCOMING_CONNECTION && byteSize > sizeof(uint8_t) + sizeof(unsigned int) + sizeof(unsigned short) + sizeof(RakNet::Time) * 2)
				{
					if (remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST)
					{
						remoteSystem->connectMode = RemoteSystemStruct::CONNECTED;
						PingInternal(systemAddress, true, UNRELIABLE);

						// Update again immediately after this tick so the ping goes out right away
						quitAndDataEvents.SetEvent();

						RakNet::BitStream inBitStream((uint8_t *)data, byteSize, false);
						SystemAddress bsSystemAddress;

						inBitStream.IgnoreBits(8);
						inBitStream.Read<SystemAddress>(bsSystemAddress);
						for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
							inBitStream.Read<SystemAddress>(remoteSystem->theirInternalSystemAddress[i]);

						RakNet::Time sendPingTime, sendPongTime;
						inBitStream.Read<RakNet::Time>(sendPingTime);
						inBitStream.Read<RakNet::Time>(sendPongTime);
						OnConnectedPong(sendPingTime, sendPongTime, remoteSystem);

						remoteSystem->myExternalSystemAddress = bsSystemAddress;

						// Bug: If A connects to B through R, A's firstExternalID is set to R. If A tries to send to R, sends to loopback because R==firstExternalID
						// Correct fix is to specify in Connect() if target is through a proxy.
						// However, in practice you have to connect to something else first anyway to know about the proxy. So setting once only is good enough
						if (firstExternalID == UNASSIGNED_SYSTEM_ADDRESS)
						{
							firstExternalID = bsSystemAddress;
							firstExternalID.debugPort = ntohs(firstExternalID.address.addr4.sin_port);
						}

						packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
						packet->bitSize = bitSize;
						packet->systemAddress = systemAddress;
						packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
						packet->guid = remoteSystem->guid;
						packet->guid.systemIndex = packet->systemAddress.systemIndex;
						AddPacketToProducer(packet);
					}
				}
				else if ((uint8_t)data[0] == ID_CONNECTED_PONG && byteSize == sizeof(uint8_t) + sizeof(RakNet::Time) * 2)
				{
					RakNet::Time sendPingTime, sendPongTime;

					RakNet::BitStream inBitStream((uint8_t *)data, byteSize, false);
					inBitStream.IgnoreBits(8);
					inBitStream.Read<RakNet::Time>(sendPingTime);
					inBitStream.Read<RakNet::Time>(sendPongTime);

					OnConnectedPong(sendPingTime, sendPongTime, remoteSystem);

					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((uint8_t)data[0] == ID_CONNECTED_PING && byteSize == sizeof(uint8_t) + sizeof(RakNet::Time))
				{
					RakNet::BitStream inBitStream((uint8_t *)data, byteSize, false);
					inBitStream.IgnoreBits(8);
					RakNet::Time sendPingTime;
					inBitStream.Read<RakNet::Time>(sendPingTime);

					RakNet::BitStream outBitStream;
					outBitStream.Write<MessageID>(ID_CONNECTED_PONG);
					outBitStream.Write<RakNet::Time>(sendPingTime);
					outBitStream.Write<RakNet::Time>(RakNet::GetTime());
					SendImmediate((char *)outBitStream.GetData(), outBitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, UNRELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);

					quitAndDataEvents.SetEvent();

					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((uint8_t)data[0] == ID_DISCONNECTION_NOTIFICATION)
				{
					remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ON_NO_ACK;
					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((uint8_t)(data)[0] == ID_DETECT_LOST_CONNECTIONS && byteSize == sizeof(uint8_t))
				{
					rakFree_Ex(data, _FILE_AND_LINE_);
				}
				else if ((uint8_t)(data)[0] == ID_INVALID_PASSWORD)
				{
					if (remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION)
					{
						packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
						packet->bitSize = bitSize;
						packet->systemAddress = systemAddress;
						packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
						packet->guid = remoteSystem->guid;
						packet->guid.systemIndex = packet->systemAddress.systemIndex;
						AddPacketToProducer(packet);

						remoteSystem->connectMode = RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
					}
					else
					{
						rakFree_Ex(data, _FILE_AND_LINE_);
					}
				}
				else if ((uint8_t)(data)[0] == ID_CONNECTION_REQUEST_ACCEPTED)
				{
					if (byteSize > sizeof(MessageID) + sizeof(unsigned int) + sizeof(unsigned short) + sizeof(SystemIndex) + sizeof(RakNet::Time) * 2)
					{
						bool allowConnection, alreadyConnected;

						if (remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST ||
							remoteSystem->connectMode == RemoteSystemStruct::REQUESTED_CONNECTION ||
							allowConnectionResponseIPMigration)
							allowConnection = true;
						else
							allowConnection = false;

						if (remoteSystem->connectMode == RemoteSystemStruct::HANDLING_CONNECTION_REQUEST)
							alreadyConnected = true;
						else
							alreadyConnected = false;

						if (allowConnection)
						{
							SystemAddress externalID;
							SystemIndex systemIndex;

							RakNet::BitStream inBitStream((uint8_t *)data, byteSize, false);
							inBitStream.IgnoreBits(8);
							inBitStream.Read<SystemAddress>(externalID);
							inBitStream.Read<SystemIndex>(systemIndex);
							for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
								inBitStream.Read<SystemAddress>(remoteSystem->theirInternalSystemAddress[i]);

							RakNet::Time sendPingTime, sendPongTime;
							inBitStream.Read<RakNet::Time>(sendPingTime);
							inBitStream.Read<RakNet::Time>(sendPongTime);
							OnConnectedPong(sendPingTime, sendPongTime, remoteSystem);

							remoteSystem->myExternalSystemAddress = externalID;
							remoteSystem->connectMode = RemoteSystemStruct::CONNECTED;

							// Bug: If A connects to B through R, A's firstExternalID is set to R. If A tries to send to R, sends to loopback because R==firstExternalID
							// Correct fix is to specify in Connect() if target is through a proxy.
							// However, in practice you have to connect to something else first anyway to know about the proxy. So setting once only is good enough
							if (firstExternalID == UNASSIGNED_SYSTEM_ADDRESS)
							{
								firstExternalID = externalID;
								firstExternalID.debugPort = ntohs(firstExternalID.address.addr4.sin_port);
							}

							packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
							packet->bitSize = byteSize * 8;
							packet->systemAddress = systemAddress;
							packet->systemAddress.systemIndex = (SystemIndex)GetIndexFromSystemAddress(systemAddress, true);
							packet->guid = remoteSystem->guid;
							packet->guid.systemIndex = packet->systemAddress.systemIndex;
							AddPacketToProducer(packet);

							RakNet::BitStream outBitStream;
							outBitStream.Write<MessageID>(ID_NEW_INCOMING_CONNECTION);
							outBitStream.Write<SystemAddress>(systemAddress);
							for (unsigned int i = 0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
								outBitStream.Write<SystemAddress>(ipList[i]);
							outBitStream.Write<RakNet::Time>(sendPongTime);
							outBitStream.Write<RakNet::Time>(RakNet::GetTime());

							SendImmediate((char *)outBitStream.GetData(), outBitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE_ORDERED, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);

							if (alreadyConnected == false)
							{
								PingInternal(systemAddress, true, UNRELIABLE);
							}
						}
						else
						{
							rakFree_Ex(data, _FILE_AND_LINE_);
						}
					}
					else
					{
						RakAssert(0);
						rakFree_Ex(data, _FILE_AND_LINE_);
					}
				}
				else
				{
					if ((data[0] >= (MessageID)ID_TIMESTAMP || data[0] == ID_SND_RECEIPT_ACKED || data[0] == ID_SND_RECEIPT_LOSS) &&
						remoteSystem->isActive)
					{
						packet = AllocPacket(byteSize, data, _FILE_AND_LINE_);
						packet->bitSize = bitSize;
						packet->systemAddress = systemAddress;
						packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
						packet->guid = remoteSystem->guid;
						packet->guid.systemIndex = packet->systemAddress.systemIndex;
						AddPacketToProducer(packet);
					}
					else
					{
						rakFree_Ex(data, _FILE_AND_LINE_);
					}
				}
			}

			bitSize = remoteSystem->reliabilityLayer.Receive(&data);
		}
	}

	return true;
}

void RakPeer::OnRNS2Recv(RNS2RecvStruct *recvStruct)
{
	if (incomingDatagramEventHandler)
	{
		if (incomingDatagramEventHandler(recvStruct) != true)
			return;
	}

	PushBufferedPacket(recvStruct);
	quitAndDataEvents.SetEvent();
}

RAK_THREAD_DECLARATION(RakNet::UpdateNetworkLoop)
{

	RakPeer *rakPeer = (RakPeer *)arguments;

	BitStream updateBitStream(MAXIMUM_MTU_SIZE
#if LIBCAT_SECURITY == 1
							  + cat::AuthenticatedEncryption::OVERHEAD_BYTES
#endif
	);
	rakPeer->isMainLoopThreadActive = true;

	while (rakPeer->endThreads == false)
	{
		if (rakPeer->userUpdateThreadPtr)
			rakPeer->userUpdateThreadPtr(rakPeer, rakPeer->userUpdateThreadData);

		rakPeer->RunUpdateCycle(updateBitStream);

		rakPeer->quitAndDataEvents.WaitOnEvent(10);
	}

	rakPeer->isMainLoopThreadActive = false;
	return 0;
}

void RakPeer::CallPluginCallbacks(DataStructures::List<PluginInterface2 *> &pluginList, Packet *packet)
{
	for (unsigned int i = 0; i < pluginList.Size(); i++)
	{
		switch (packet->data[0])
		{
		case ID_DISCONNECTION_NOTIFICATION:
			pluginList[i]->OnClosedConnection(packet->systemAddress, packet->guid, LCR_DISCONNECTION_NOTIFICATION);
			break;
		case ID_CONNECTION_LOST:
			pluginList[i]->OnClosedConnection(packet->systemAddress, packet->guid, LCR_CONNECTION_LOST);
			break;
		case ID_NEW_INCOMING_CONNECTION:
			pluginList[i]->OnNewConnection(packet->systemAddress, packet->guid, true);
			break;
		case ID_CONNECTION_REQUEST_ACCEPTED:
			pluginList[i]->OnNewConnection(packet->systemAddress, packet->guid, false);
			break;
		case ID_CONNECTION_ATTEMPT_FAILED:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_CONNECTION_ATTEMPT_FAILED);
			break;
		case ID_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_REMOTE_SYSTEM_REQUIRES_PUBLIC_KEY);
			break;
		case ID_OUR_SYSTEM_REQUIRES_SECURITY:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_OUR_SYSTEM_REQUIRES_SECURITY);
			break;
		case ID_PUBLIC_KEY_MISMATCH:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_PUBLIC_KEY_MISMATCH);
			break;
		case ID_ALREADY_CONNECTED:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_ALREADY_CONNECTED);
			break;
		case ID_NO_FREE_INCOMING_CONNECTIONS:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_NO_FREE_INCOMING_CONNECTIONS);
			break;
		case ID_CONNECTION_BANNED:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_CONNECTION_BANNED);
			break;
		case ID_INVALID_PASSWORD:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_INVALID_PASSWORD);
			break;
		case ID_INCOMPATIBLE_PROTOCOL_VERSION:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_INCOMPATIBLE_PROTOCOL);
			break;
		case ID_IP_RECENTLY_CONNECTED:
			pluginList[i]->OnFailedConnectionAttempt(packet, FCAR_IP_RECENTLY_CONNECTED);
			break;
		}
	}
}

void RakPeer::FillIPList(void)
{
	if (ipList[0] != UNASSIGNED_SYSTEM_ADDRESS)
		return;

#if !defined(WINDOWS_STORE_RT)
	RakNetSocket2::GetMyIP(ipList);
#endif

	std::sort(ipList, ipList + MAXIMUM_NUMBER_OF_INTERNAL_IDS - 1);
}
