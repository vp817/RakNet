cmake_minimum_required(VERSION 3.5)

project(RakNet)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ${CMAKE_CXX_STANDARD})

if(NOT APPLE)
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		set(HAVE_64_BIT 0)
	else()
		set(HAVE_64_BIT 1)
	endif()
endif()

if(WIN32 AND NOT UNIX)
	set(PROGRAMFILESX86 $ENV{PROGRAMFILES})
	string(REPLACE "\\" "/" PROGRAMFILESX86 ${PROGRAMFILESX86})
endif()

if(WIN32 AND NOT UNIX)
	set(RAKNET_LIBRARY_LIBS ws2_32.lib)
else()
	set(RAKNET_LIBRARY_LIBS pthread)
endif()

set(RAKNET_INCLUDES_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(RAKNET_ACTUAL_INCLUDE_DIR_PATH ${RAKNET_INCLUDES_PATH}/RakNet)

file(GLOB_RECURSE RAKNET_ALL_CPP_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE RAKNET_ALL_HEADER_SRCS ${RAKNET_ACTUAL_INCLUDE_DIR_PATH}/*.h)

option(RAKNET_ENABLE_SAMPLES "Generate RakNet sample projects if true." OFF)
option(RAKNET_ENABLE_DLL "Generate the DLL project if true." OFF)
option(RAKNET_ENABLE_STATIC "Generate the static library project if true." ON)

include(./CMakeIncludes/CMakeMacros.cmake)
FIXLINKOPTIONS()
FIXCOMPILEOPTIONS()

if(RAKNET_ENABLE_DLL)
	if(WIN32 AND NOT UNIX)
		set(CMAKE_CXX_FLAGS "/D WIN32 /D _RAKNET_DLL /D _CRT_NONSTDC_NO_DEPRECATE /D _CRT_SECURE_NO_DEPRECATE /GS- /GR- ")
	endif()

	add_library(RakNetDLL SHARED ${RAKNET_ALL_CPP_SRCS} ${RAKNET_ALL_HEADER_SRCS})
	target_include_directories(RakNetDLL PRIVATE ${RAKNET_ACTUAL_INCLUDE_DIR_PATH})

	if(WIN32 AND NOT UNIX)
		target_link_libraries(RakNetDLL ${RAKNET_LIBRARY_LIBS})
	else()
		target_link_libraries(RakNetDLL ${RAKNET_LIBRARY_LIBS})
		install(TARGETS RakNetDLL DESTINATION ${CMAKE_CURRENT_SOURCE_DIR})
	endif()
elseif(RAKNET_ENABLE_STATIC)
	add_library(RakNetLibStatic STATIC ${RAKNET_ALL_CPP_SRCS} ${RAKNET_ALL_HEADER_SRCS})

	target_include_directories(RakNetLibStatic PRIVATE ${RAKNET_ACTUAL_INCLUDE_DIR_PATH})

	if(WIN32 AND NOT UNIX)
		set(CMAKE_CXX_FLAGS "/D WIN32 /D _RAKNET_LIB /D _CRT_NONSTDC_NO_DEPRECATE /D _CRT_SECURE_NO_DEPRECATE /GS- /GR- ")
	endif()

	target_link_libraries(RakNetLibStatic ${RAKNET_LIBRARY_LIBS})

	if(WIN32 AND NOT UNIX)
		if(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")
			if(MSVC_VERSION GREATER_EQUAL 1600)
				set_target_properties(RakNetLibStatic PROPERTIES STATIC_LIBRARY_FLAGS "/NODEFAULTLIB:\"LIBCD.lib LIBCMTD.lib MSVCRT.lib\"")
			else()
				set_target_properties(RakNetLibStatic PROPERTIES STATIC_LIBRARY_FLAGS "/NODEFAULTLIB:&quot;LIBCD.lib LIBCMTD.lib MSVCRT.lib&quot;")
			endif()
		endif()
	else()
		install(TARGETS RakNetLibStatic DESTINATION ${CMAKE_CURRENT_SOURCE_DIR})
		install(FILES ${RAKNET_ALL_HEADER_SRCS} DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/include/RakNet)
	endif()
elseif(RAKNET_GENERATE_SAMPLES)
	add_subdirectory(Samples)
endif()

if(UNIX AND NOT WIN32)
	set(RAKNET_COMMON_LIBS libRakNetLibStatic.a)
else()
	set(RAKNET_COMMON_LIBS RakNetLibStatic.lib)
endif()
