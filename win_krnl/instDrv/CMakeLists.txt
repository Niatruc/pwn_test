cmake_minimum_required(VERSION 3.0.0)
set(CMAKE_GENERATOR_PLATFORM x64)
set(CMAKE_GENERATOR_TOOLSET host=x64)
set(CMAKE_EXE_LINKER_FLAGS "/machine:x64")
project(instDrv VERSION 0.1.0)

# include(CTest)
# enable_testing()

# 静态编译: https://stackoverflow.com/questions/24648357/compiling-a-static-executable-with-cmake
set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

target_compile_options(VCRUNTIME140D PUBLIC /MT)
target_link_options(VCRUNTIME140D PUBLIC /INCREMENTAL:NO /NODEFAULTLIB:MSVCRT)

add_executable(instDrv main.cpp)
# if(CMAKE_CL_64)    #CMAKE的内建变量，如果是true，就说明编译器的64位的，自然可以编译64bit的程序
# set(ADDRESS_MODEL 64)
# set(NODE_TARGET x64)
# else()
# set(ADDRESS_MODEL 32)
# set(NODE_TARGET x86)
# endif()
# set(CPACK_PROJECT_NAME ${PROJECT_NAME})
# set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
# include(CPack)
