# required to set:
# export PKG_CONFIG_PATH="/root/libyang/"

project(sysrepo-plugin-ietf-interfaces C CXX)
cmake_minimum_required(VERSION 3.0)
cmake_policy(SET CMP0053 OLD) 

set(ENV{PKG_CONFIG_PATH}  "/root/libyang")

include(GNUInstallDirs)

find_package(PkgConfig)
pkg_check_modules(SYSREPO REQUIRED libsysrepo)



set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CFLAGS "-Wall -pedantic -g -O0 ${CMAKE_CFLAGS}")
set(CMAKE_C_FLAGS "-Wall -pedantic -g -O0 ${CMAKE_CFLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -pedantic -g -O0 ${CMAKE_CFLAGS}")

add_definitions(${SYSREPO_CFLAGS})
include_directories(${SYSREPO_INCLUDE_DIRS})
link_directories(${SYSREPO_LIBRARY_DIRS})

set(YANG_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/iana-if-type@2017-01-19.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-inet-types@2015-09-30.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-interfaces@2017-12-16.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-ipv4-unicast-routing@2018-03-21.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-ipv6-unicast-routing@2018-03-21.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-ipv6-router-advertisements@2018-03-13.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-ip@2018-04-17.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-routing@2018-03-22.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-system@2017-09-15.yang
    ${CMAKE_CURRENT_SOURCE_DIR}/yang/ietf-yang-types@2015-09-30.yang
)
add_custom_target(YANG_files ${YANG_SRCS})

set(YANG_DIR ${CMAKE_INSTALL_PREFIX}/share/sysrepo/yang)

add_library(config STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/config.c)

add_executable(stest ${CMAKE_CURRENT_SOURCE_DIR}/src/subscription-test.cpp)
target_link_libraries(stest ${SYSREPO_LIBRARIES})
target_link_libraries(stest ${CMAKE_BINARY_DIR}/libconfig.a)

add_library(sysrepo-plugin-ietf-interfaces SHARED ${CMAKE_CURRENT_SOURCE_DIR}/src/interfaces-plugin.cpp)
target_link_libraries(sysrepo-plugin-ietf-interfaces ${SYSREPO_LIBRARIES})


# get sysrepo plugins directory
if (NOT SR_PLUGINS_DIR)
    if (PKG_CONFIG_FOUND)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=SR_PLUGINS_DIR" "libsysrepo" OUTPUT_VARIABLE SR_PLUGINS_DIR)
        string(STRIP ${SR_PLUGINS_DIR} SR_PLUGINS_DIR)
    endif()
endif()
if (NOT SR_PLUGINS_DIR)
    message(FATAL_ERROR "Cannot get sysrepo plugins directory due to missing pkg-config, set SR_PLUGINS_DIR manually.")
endif()

install(FILES ${YANG_SRCS} DESTINATION ${YANG_DIR})
install(TARGETS sysrepo-plugin-ietf-interfaces DESTINATION ${SR_PLUGINS_DIR})
#install(CODE "MESSAGE(STATUS
#\"To enable this plugin, run:
#
# - sysrepoctl --install -s ${YANG_DIR} --module ietf-interfaces
# - systemctl restart sysrepo-plugind
#\")")
