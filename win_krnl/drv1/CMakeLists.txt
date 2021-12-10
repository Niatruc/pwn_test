cmake_minimum_required(VERSION 3.10)
 
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../cmake")
 
project(drv)
 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX-")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /WX-")
 
# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
 
add_definitions(-DUNICODE -D_UNICODE)
 
find_package(WDK REQUIRED)
 
wdk_add_driver(drv1
    drv1.cpp
)