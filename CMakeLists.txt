cmake_minimum_required(VERSION 3.16)

project(doc2md LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MINGW)
    message(STATUS "Configuring static MinGW build")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    add_compile_definitions(_STATIC_CPPLIB)
endif()

option(DOC2MD_BUILD_TESTS "Build doc2md unit tests" OFF)

add_library(miniz STATIC
    thirdparty/miniz/miniz.c
    thirdparty/miniz/miniz_zip.c
    thirdparty/miniz/miniz_tinfl.c
    thirdparty/miniz/miniz_tdef.c)
target_include_directories(miniz PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty/miniz)

add_library(tinyxml2 STATIC thirdparty/tinyxml2/tinyxml2.cpp)
target_include_directories(tinyxml2 PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty/tinyxml2)

add_subdirectory(src)
add_subdirectory(examples)
