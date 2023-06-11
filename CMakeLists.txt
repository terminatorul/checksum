cmake_minimum_required(VERSION 3.24)

project(poco-md5 CXX)
include(GNUInstallDirs)

find_package(poco REQUIRED)
find_package(glib)

if(MSVC)
    set(BINMODE_OBJECT_FILE "binmode.obj")
else()
    set(BINMODE_OBJECT_FILE)
endif()

add_executable(checksum HANDLEStreamBuf.hpp HANDLEStreamBuf.cpp checksum.cpp)
target_link_libraries(checksum Poco::Poco glib::glib)
target_link_options(checksum PRIVATE ${BINMODE_OBJECT_FILE})

install(TARGETS checksum)
