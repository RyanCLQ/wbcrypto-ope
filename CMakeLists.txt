cmake_minimum_required(VERSION 3.9.0)

project(wbcrypto-ope)

# global import header file
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
include_directories(${INCLUDE_DIR})

# set the output location of compiled library file and header file
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/out)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
file(COPY ${CMAKE_SOURCE_DIR}/include DESTINATION ${CMAKE_BINARY_DIR}/out)

# files in library
aux_source_directory(src ope_src)
aux_source_directory(src/wbmatrix ope_src)

# static library
add_library(ope-static ${ope_src})
SET_TARGET_PROPERTIES(ope-static PROPERTIES OUTPUT_NAME "ope")

# dynamic library
add_library(ope SHARED ${ope_src})

# install the header and library files to the environment
install(DIRECTORY ${INCLUDE_DIR}/ DESTINATION include)
install(TARGETS ope ope-static
        LIBRARY DESTINATION lib  
        ARCHIVE DESTINATION lib  
        )

# test

ADD_SUBDIRECTORY(test)


SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O2 -g  -m64 -mavx2")

