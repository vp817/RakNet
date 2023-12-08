cmake_minimum_required(VERSION 3.0)

option(RAKNET_ENABLE_EXTENSIONS "Enable extension projects that might need specific dependencies." ON)
option(RAKNET_EXTENSION_USEMYSQL "Enable extensions using MySQL" ON)
option(RAKNET_EXTENSION_USEPOSTGRESQL "Enable extensions using PostgreSQL" ON)
option(RAKNET_EXTENSION_USEBOOST "Enable extensions using Boost" ON)
option(RAKNET_EXTENSION_USESPEEX "Enable extensions using Speex" ON)

option(RAKNET_EXTENSION_AUTOPATCHER "Enable Autopatcher extension" ON)
option(RAKNET_EXTENSION_BZIP "Enable bzip extension" ON)
option(RAKNET_EXTENSION_XML "Enable xml extension" ON)

if(RAKNET_ENABLE_EXTENSIONS)
    if(RAKNET_EXTENSION_BZIP)
        add_subdirectory(bzip2)
    endif()

    if(RAKNET_EXTENSION_XML)
        add_subdirectory(XML)
    endif()

    if(RAKNET_EXTENSION_USEMYSQL)
        add_subdirectory(MySQLInterface)
    endif()

    if(RAKNET_EXTENSION_USEPOSTGRESQL)
        add_subdirectory(PostgreSQLInterface)
    endif()
endif()

if(RAKNET_EXTENSION_AUTOPATCHER)
    add_subdirectory(Autopatcher)
endif()

if(WIN32 AND NOT UNIX)
    if(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")
        add_subdirectory(portaudio)
    endif(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")

    add_subdirectory(speex)
endif()

if(RAKNET_ENABLE_EXTENSIONS)
    if(RAKNET_EXTENSION_USEBOOST)
        add_subdirectory(RPC3)
    endif()
endif()

if(NOT WIN32 AND UNIX)
    if(RAKNET_EXTENSION_USESPEEX AND RAKNET_ENABLE_EXTENSIONS)
        FINDSPEEX()
        include_directories(${RAKNETHEADERFILES} ${SPEEX_INCLUDE_DIRS})
        add_library(LibRakVoice STATIC RakVoice/RakVoice.cpp RakVoice/RakVoice.h)
        target_link_libraries(LibRakVoice ${RAKNET_COMMON_LIBS} ${SPEEX_LIBRARIES})
    endif()
endif()
