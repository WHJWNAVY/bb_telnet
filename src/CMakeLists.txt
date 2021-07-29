cmake_minimum_required (VERSION 3.3.2)

project (telnet C)

set(EXECUTABLE_NAME telnet)
set(CMAKE_BUILD_TYPE Release)

find_package(PkgConfig REQUIRED)

file(GLOB HI_TELNET_SRCS source/*.c)
                                         
add_executable(${EXECUTABLE_NAME} ${HI_TELNET_SRCS})

target_include_directories(${EXECUTABLE_NAME} PUBLIC 
                                          ${PROJECT_SOURCE_DIR}/source
                                          ${PROJECT_SOURCE_DIR}/include)

install(TARGETS ${EXECUTABLE_NAME}
        RUNTIME DESTINATION bin)