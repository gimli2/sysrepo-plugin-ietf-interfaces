# required to set:
# export PKG_CONFIG_PATH="/root/libyang/"

project(sysrepo-plugin-ietf-interfaces C CXX)
cmake_minimum_required(VERSION 3.0)
cmake_policy(SET CMP0053 OLD) 

include(CTest)
include(GNUInstallDirs)

find_package(PkgConfig)
pkg_check_modules(SYSREPO REQUIRED libsysrepo)

set(DSTPATH "/etc/systemd/network" CACHE STRING "Destination directory for systemd network related configuration - defaulting to '/etc/systemd/network'.")
add_definitions(-DDSTPATH="${DSTPATH}")

message(STATUS "Provided DSTPATH = ${DSTPATH}") 

set(CMAKE_CFLAGS "-Wall -Wno-unused-function -pedantic -g -O0 ${CMAKE_CFLAGS}")
set(CMAKE_C_FLAGS "-Wall -Wno-unused-function -pedantic -g -O0 ${CMAKE_CFLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -Wno-unused-function -pedantic -g -O0 ${CMAKE_CFLAGS}")

add_definitions(${SYSREPO_CFLAGS})
include_directories(${SYSREPO_INCLUDE_DIRS})
link_directories(${SYSREPO_LIBRARY_DIRS})

# models
set(YANG_SRCS
    yang/iana-if-type@2017-01-19.yang
    yang/ietf-inet-types@2013-07-15.yang
    yang/ietf-interfaces@2017-12-16.yang
    yang/ietf-ipv4-unicast-routing@2018-03-13.yang
    yang/ietf-ipv6-router-advertisements@2018-03-13.yang
    yang/ietf-ipv6-unicast-routing@2018-03-13.yang
    yang/ietf-ip@2018-02-22.yang
    yang/ietf-routing@2018-03-13.yang
    yang/ietf-system@2014-08-06.yang
    yang/ietf-yang-types@2013-07-15.yang
)
add_custom_target(YANG_files ${YANG_SRCS})
set(YANG_DIR ${CMAKE_INSTALL_PREFIX}/share/sysrepo/yang)

# testing binary
add_executable(stest src/subscription-test.cpp src/config.c)
target_link_libraries(stest ${SYSREPO_LIBRARIES})

# testing binary 2
add_executable(srgetxpath src/srgetxpath.cpp src/config.c)
target_link_libraries(srgetxpath ${SYSREPO_LIBRARIES})

# plugin *.so
add_library(sysrepo-plugin-ietf-interfaces SHARED src/interfaces-plugin.cpp src/config.c)
target_link_libraries(sysrepo-plugin-ietf-interfaces ${SYSREPO_LIBRARIES})


################################################################################
# testing stuff, CMake code inspired here:
# https://people.ece.cornell.edu/skand/post/intro-to-ctest/
################################################################################
#set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/tests)
set(CTEST_BINARY_DIRECTORY ${PROJECT_BINARY_DIR}/tests)
file(GLOB files "tests/test_*.cpp")
foreach(file ${files})   
    string(REGEX REPLACE "(^.*/|\\.[^.]*$)" "" file_without_ext ${file})
    add_executable(${file_without_ext} ${file})
    target_link_libraries(${file_without_ext} ${PROJECT_LIBS})
    add_test(${file_without_ext} ${file_without_ext})
    set_tests_properties(${file_without_ext}
        PROPERTIES
        PASS_REGULAR_EXPRESSION "Test passed")
    set_tests_properties(${file_without_ext}
        PROPERTIES
        FAIL_REGULAR_EXPRESSION "(Exception|Test failed)")
    set_tests_properties(${file_without_ext}
        PROPERTIES
        TIMEOUT 120)
endforeach()
# copy testing datafiles
file(GLOB datafiles "tests/*.json")
file(COPY ${datafiles} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# scripted/non-compiled tests
file(GLOB files "tests/test_*.sh")
foreach(file ${files})   
    add_test(${file} ${file})
    set_tests_properties(${file_without_ext}
        PROPERTIES
        PASS_REGULAR_EXPRESSION "Test passed")
    set_tests_properties(${file_without_ext}
        PROPERTIES
        FAIL_REGULAR_EXPRESSION "(Exception|Test failed)")
    set_tests_properties(${file_without_ext}
        PROPERTIES
        TIMEOUT 120)
endforeach()
################################################################################


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
