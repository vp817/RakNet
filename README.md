## RakNet

Copyright © 2014 Oculus VR, Inc.

**General Information:**

* Version: 5.0.0
* Documentation: https://vp817.github.io/RakNetWebsite

**Package Contents:**

* src: All source files of RakNet
* include: All include directories that contains the header files of RakNet
* Samples: Code samples of using RakNet
* libs: The libraries that can be used to make RakNet easier to use

## Building RakNet

### Linux

1. Open a terminal window.
2. Navigate to the `RakNet` directory.
3. Run one of the following commands:
    * `g++ -lpthread -g -I./include/RakNet ./src/*.cpp`: Builds RakNet with debugging information.
    * `g++ -m64 -g -lpthread -I./include/RakNet "./Samples/Chat Example/Chat Example Server.cpp" ./src/*.cpp`: Builds a 64-bit Chat Example server.
4. The resulting executable will be named `a.out`.

### Windows

1. Create or open a Visual Studio project.
2. Right-click on the project and choose "Add Existing Item".
3. Select the `src` directory then the `include/RakNet` directory from the RakNet package.
4. Build the project.

### Mac

1. Open a terminal window.
2. Navigate to the `RakNet` directory.
3. Run the following commands:
    * `g++ -c -DNDEBUG -I -isysroot /Developer/SDKs/MacOSX10.5u.sdk/ -arch i386 -I./include/RakNet ./src/*.cpp`: Builds PowerPC binaries.
    * `libtool -static -o raknetppc.a *.o`: Creates a static library for PowerPC.
    * `gcc -c -I ../Include -isysroot /Developer/SDKs/MacOSX10.4u.sdk/ -arch i386 -I./include/RakNet ./src/*.cpp`: Builds Intel binaries.
    * `libtool -static -o rakneti386.a *.o`: Creates a static library for Intel.
    * `lipo -create *.a -o libraknet.a`: Creates a universal binary for both architectures.

### Android

1. Install the latest CYGWIN and Android SDK.
2. Create a directory for RakNet within the CYGWIN environment.
3. Copy the `Android.Manifest.xml` and other relevant files from another sample.
4. Create a directory named `RakNetIncludes` and copy the contents of the `include/RakNet` directory into it.
5. Copy the `include` directory from the RakNet package to the `RakNetIncludes` directory.
6. Create a file named `Android.mk` with the following content:

    ```
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE := RakNet
    MY_PREFIX := $(LOCAL_PATH)/RakNetSources/
    MY_SOURCES := $(wildcard $(MY_PREFIX)*.cpp)
    LOCAL_C_INCLUDES += $(LOCAL_PATH)/RakNetIncludes
    LOCAL_SRC_FILES += $(MY_SOURCES:$(MY_PREFIX)%=RakNetSources/%)
    include $(BUILD_SHARED_LIBRARY)
    ```

7. Create a directory named `RakNetSources` and copy the contents of the `src` directory into it.
8. Navigate to the RakNet directory within the CYGWIN environment.
9. Run the following command:

   ```
   ../../ndk-build
   ```

This will build a `.so` file that can be used in your Android project.

### Native Client
See `Samples\nacl_sdk\RakNet_NativeClient_VS2010\HowToSetup.txt` for detailed instructions on how to setup.

### Windows Phone 8
**To use RakNet in your Windows Phone 8 project:**

1. **Add libraries:**
    * Add `libs\WinPhone8\ThreadEmulation.cpp` to your project.
    * Add `libs\WinPhone8\` to your include paths.
 2. **Define preprocessor macros:**
    * Add the following preprocessor definitions to your project:
        * `_CRT_SECURE_NO_WARNINGS`
        * `WINDOWS_PHONE_8`

### Windows Store 8
RakNet currently does not support TCP or IPV6 in Windows Store 8 applications. Only UDP (RakPeer) and IPV4 are available.

**To use RakNet in your Windows Store 8 project:**

1. **Add libraries:**
    * Add `libs\WinPhone8\ThreadEmulation.cpp` to your project.
    * Add the following directories to your include paths:
        * `libs\WinPhone8\`
        * `libs\WinRT\`

2. **Define preprocessor macros:**
    * Add the following preprocessor definitions to your project:
        * `_CRT_SECURE_NO_WARNINGS`
        * `WINDOWS_STORE_RT`
        * `_RAKNET_SUPPORT_TCPInterface=0`
        * `_RAKNET_SUPPORT_PacketizedTCP=0`
        * `_RAKNET_SUPPORT_EmailSender=0`
        * `_RAKNET_SUPPORT_HTTPConnection=0`
        * `_RAKNET_SUPPORT_HTTPConnection2=0`
        * `_RAKNET_SUPPORT_TelnetTransport=0`
        * `_RAKNET_SUPPORT_NatTypeDetectionServer=0`
        * `_RAKNET_SUPPORT_UDPProxyServer=0`
        * `_RAKNET_SUPPORT_UDPProxyCoordinator=0`
        * `_RAKNET_SUPPORT_UDPForwarder=0`
