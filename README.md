RakNet 5.00
============

Copyright (c) 2014, Oculus VR, Inc.

Package notes
------------------------------------------
The Help directory contains index.html, which is full help documentation in HTML format
The Source directory contain all files required for the core of Raknet and is used if you want to use the source in your program or create your own dll
The Samples directory contains code samples and one game using an older version of Raknet.  The code samples each demonstrate one feature of Raknet.  The game samples cover several features.
The lib directory contains libs for debug and release versions of RakNet and RakVoice
There is a make file for linux users in the root directory.  Windows users can use projects under Samples\Project Samples

C# support
------------------------------------------

See Help\swigtutorial.html

Windows users (Lower than VS10)
-----------------------------------------
You can get by if you directly include the source.
Or
Try this:
```shell
cd RakNet
cmake -G "NMake Makefiles" .
# Then you will have nmake file and you can use nmake in any visual studio version.
```

CYGWIN users
-----------------------------------------
Copy Include, Source, and whatever you want to run in the home directory.  Then type
`g++ ../../lib/w32api/libws2_32.a *.cpp`
You can run `a.exe`.
You might have to copy `*.dll` from `cygwin\bin` as well.

Linux users
-----------------------------------------
Use `cmake`, or `g++ -lpthread -g *.cpp` in the /Source directory.
With libcat, use `g++ -pthread -g -I./../libs *.cpp` in the /Source directory.

64 bit use -m64 command line
Sometimes you need -pthread instead of -lpthread

Command to build 64 bit chat example server from the /Source directory:

    g++ -m64 -g -lpthread -I./include/RakNet "../Samples/Chat Example/Chat Example Server.cpp" src/*.cpp

Command to build NATCompleteServer from the Samples/NATCompleteServer directory:

    g++ -g -lpthread -I./ -I./../../Source main.cpp -I./../CloudServer ./../../Source/*.cpp ./../CloudServer/CloudServerHelper.cpp

Command to build autopatcher server from /Source directory:

    g++ -lpthread -lpq -lssl -lbz2 -lssl -lcrypto -L/opt/PostgreSQL/9.0/lib -L../libs/bzip2 -I/opt/PostgreSQL/9.0/include -I../libs/bzip2 -I./ -I../libs/Autopatcher -I../libs/Autopatcher/AutopatcherPostgreRepository -I../libs/PostgreSQLInterface -g *.cpp ../libs/Autopatcher/AutopatcherServer.cpp ../libs/Autopatcher/CreatePatch.cpp ../libs/Autopatcher/MemoryCompressor.cpp ../libs/Autopatcher/AutopatcherPostgreRepository/AutopatcherPostgreRepository.cpp ../libs/PostgreSQLInterface/PostgreSQLInterface.cpp ../Samples/AutopatcherServer/AutopatcherServerTest.cpp

Command to build NATCompleteServer from /Source directory:

    g++ -lpthread -I./ -I../Samples/CloudServer ../Samples/CloudServer/CloudServerHelper.cpp ../Samples/NATCompleteServer/main.cpp *.cpp

Command to build BigPacketTest from /Source directory:

    g++ -lpthread -I./ ../Samples/BigPacketTest/BigPacketTest.cpp *.cpp

Or with debugging info on:

    g++ -g -lpthread -I./ ../Samples/BigPacketTest/BigPacketTest.cpp *.cpp

If you get /usr/local/lib/libraknet.so: undefined reference to \`__sync_fetch_and_add_4 then build with `-march=i686`

To debug:
http://www.unknownroad.com/rtfm/gdbtut/gdbstack.html
http://cs.baylor.edu/~donahoo/tools/gdb/tutorial.html
http://linux.bytesex.org/gdb.html
http://www.delorie.com/gnu/docs/gdb/gdb_29.html

    gdb ./a.out

Set breakpoint:

    b file:line

Disable a breakpoint:

    disable <breakpointNumber>

Delete a breakpoint:

    delete <breakpointNumber>

Get a list of breakpoints:

    info breakpoints

St breakpoint to be ignored that number of times

    ignore <breakpointNumber> <count>
    run

Other useful commands:

    info stack
    info locals
    delete (Clears all breakpoints)
    step (step into)
    next (step over)
    finish (step out)
    continue to keep going after step or next
    p <variableName>
    For example: p users.orderedList.listArray[0].guid

Command to install g++

    sudo apt-get install gcc-c++
    sudo apt-get install build-essential
Or:

    yum install gcc-c++
Or:

    sudo apt-get update
    sudo apt-get install g++

Command to install gdb

    sudo apt-get install gdb

Command to install wget, used to download files from webpages
sudo apt-get install wget

Series of commands for a new server:
    sudo apt-get install wget
    sudo apt-get update
    sudo apt-get install --fix-missing g++
    sudo apt-get install gdb
    cd RakNet_Install_Directory\Source
    g++ -m64 -g -pthread -I./ "../Samples/Chat Example/Chat Example Server.cpp" *.cpp
    ./a.out

Mac Users
-----------------------------------------
Open a Terminal window and type:

    cd ~/Desktop/RakNet/Source
    g++ -c -DNDEBUG -I -isysroot /Developer/SDKs/MacOSX10.5u.sdk/ -arch i386 *.cpp

Use whichever SDK you have. However, the 10.4 SDK is bugged and will not compile unless you use GCC 4.0 from inside XCODE

The sources should build cleanly. This gives you a bunch of PowerPC binaries, compiled against the 10.3.9 SDK which is a good thing.

Give the following command:

    libtool -static -o raknetppc.a *.o

This will stitch together a static library for the PowerPC architecture. There may be warnings that some .o files do not have any symbols. If you want to be prudent, remove the named files (the .o files, not the .cpp files!) and re-run the libtool command.

Now, we build the source files for Intel:

    gcc -c -I ../Include -isysroot /Developer/SDKs/MacOSX10.4u.sdk/ -arch i386 *.cpp

..and stitch it into a i386 library:

    libtool -static -o rakneti386.a *.o

Now, type:

    ls *.a

which should list the two .a files. Now, we make them into a universal binary:

    lipo -create *.a -o libraknet.a

You now have a file named libraknet.a. This is the RakNet library, built to run on both PowerPC and Intel Macs. Enjoy! ;-)

IPod
-----------------------------------------
Depending on what version you target, you may have to change two defines to not use 64 bit integers and floats or doubles.

Android
-----------------------------------------

You will need the latest CYWGIN and the android SDK to build native code on the android. Under CYWGIN, you will need to run ndk-build on a directory for RakNet.

1. Under cygwin, create the RakNet directory somewhere, such as under samples.
For example, if you create the path `\cygwin\home\Kevin\android-ndk-r4b\samples\RakNet`

2. I copied the Android.Manifest.xml and other files from another sample

3. Under jni, you will need the following Android.mk
```
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := RakNet
    MY_PREFIX := $(LOCAL_PATH)/RakNetSources/
    MY_SOURCES := $(wildcard $(MY_PREFIX)*.cpp)
    LOCAL_SRC_FILES += $(MY_SOURCES:$(MY_PREFIX)%=RakNetSources/%)
    include $(BUILD_SHARED_LIBRARY)
```

This version of Android.mk assumes there is a directory called RakNetSources, for example
`cygwin/home/Kevin/android-ndk-r4b/samples/RakNet/jni/RakNetSources`

Under RakNetSources should be the /Source directory to RakNet. Rather than copy the files I used junction.exe
http://technet.microsoft.com/en-us/sysinternals/bb896768.aspx

The command I used to create the junction was:

    D:/cygwin/home/Kevin/android-ndk-r4b/samples/RakNet/jni/junction.exe -s D:/cygwin/home/Kevin/android-ndk-r4b/samples/RakNet/jni/RakNetSources D:/RakNet4/Source

To unjunction I used:

    D:/cygwin/home/Kevin/android-ndk-r4b/samples/RakNet/jni/junction.exe -d D:/cygwin/home/Kevin/android-ndk-r4b/samples/RakNet/jni/RakNetSources

From within the CYWGIN enviroment, navigate to home/Kevin/android-ndk-r4b/samples/RakNet. Then type

    ../../ndk-build

Everything should build and you should end up with a .so file.

You should then be able to create a project in eclipse, and import cygwin/home/Kevin/android-ndk-r4b/samples/RakNet

Native client
-----------------------------------------
See Samples\nacl_sdk\RakNet_NativeClient_VS2010\HowToSetup.txt for detailed instructions on setup.

Windows Phone 8
-----------------------------------------
Add to your project libs\WinPhone8\ThreadEmulation.cpp
Add libs\WinPhone8\ to your include paths
Define _CRT_SECURE_NO_WARNINGS and WINDOWS_PHONE_8

Windows Store 8
-----------------------------------------
Add to your project libs\WinPhone8\ThreadEmulation.cpp
Add libs\WinPhone8\ and libs\WinRT to your include paths
TCP is not supported, only UDP (RakPeer).
IPV4 only (not hard to also add IPV6 upon request).
Define:
_CRT_SECURE_NO_WARNINGS
WINDOWS_STORE_RT
_RAKNET_SUPPORT_TCPInterface=0
_RAKNET_SUPPORT_PacketizedTCP=0
_RAKNET_SUPPORT_EmailSender=0
_RAKNET_SUPPORT_HTTPConnection=0
_RAKNET_SUPPORT_HTTPConnection2=0
_RAKNET_SUPPORT_TelnetTransport=0
_RAKNET_SUPPORT_NatTypeDetectionServer=0
_RAKNET_SUPPORT_UDPProxyServer=0
_RAKNET_SUPPORT_UDPProxyCoordinator=0
_RAKNET_SUPPORT_UDPForwarder=0
