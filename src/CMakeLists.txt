cmake_minimum_required (VERSION 3.16)

# For DEBUG build, use : cmake -DCMAKE_BUILD_TYPE=Debug ../

project (NetworkPioneer)
set(CMAKE_CXX_STANDARD 20)

# Configuration types
SET(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "Configs" FORCE)
IF(DEFINED CMAKE_BUILD_TYPE AND CMAKE_VERSION VERSION_GREATER "2.8")
  SET_PROPERTY(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS  ${CMAKE_CONFIGURATION_TYPES})
ENDIF()

add_compile_options(${incubator} -Wall -Wextra -pedantic -Wno-unused-variable -Wno-unused-parameter -Wnon-virtual-dtor -pedantic)
# deps:
# * libboost-all-dev

# set(Boost_USE_STATIC_LIBS OFF) 
# set(Boost_USE_MULTITHREADED ON)  
# set(Boost_USE_STATIC_RUNTIME OFF) 

# include_directories (SYSTEM ${Boost_INCLUDE_DIR})

# apt install nlohmann-json3-dev
# find_package(nlohmann_json REQUIRED)

file(GLOB_RECURSE SOURCES "pioneertrace/*.cpp")

include_directories (${PROJECT_SOURCE_DIR}/include)

#add_subdirectory (include)
add_executable(pioneertrace ${SOURCES})
# target_link_libraries(pioneertrace PRIVATE nlohmann_json::nlohmann_json)
