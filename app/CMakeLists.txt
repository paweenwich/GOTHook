# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

include_directories(
    #src/main/cpp/include
)


add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/Utils.cpp
             src/main/cpp/ProcUtil.cpp
             src/main/cpp/ELFFile.cpp
             src/main/cpp/native-lib.cpp
             #src/main/cpp/elf_utils.c
             #src/main/cpp/injector.c
             #src/main/cpp/main.c
             #src/main/cpp/ptrace.c
             #src/main/cpp/utils.c
)

link_directories( libs )


# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )


# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       native-lib

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

add_executable(
    #name of exe
    helloworld
    #files
    src/main/cpp/main.cpp
    src/main/cpp/Utils.cpp
    src/main/cpp/ProcUtil.cpp
    src/main/cpp/ELFFile.cpp
    src/main/cpp/native-lib.cpp
)

target_link_libraries( # Specifies the target library.
                       helloworld

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

#add_custom_target(Qt5CopyBinaries
    #COMMAND ${CMAKE_COMMAND} -E copy D:/kwang/android/GOTHook/app/build/intermediates/cmake/debug/obj/x86/helloworld D:/kwang/helloworld
#    COMMAND adb push D:/kwang/android/GOTHook/app/build/intermediates/cmake/debug/obj/x86/helloworld /data/local/tmp/helloworld
#)

#add_dependencies(helloworld Qt5CopyBinaries)

add_custom_command(TARGET helloworld POST_BUILD
  #COMMAND ${CMAKE_COMMAND} -E "environment"
  COMMAND adb push ${PROJECT_BINARY_DIR}/helloworld /data/local/tmp/helloworld
  COMMAND adb shell chmod 777 /data/local/tmp/helloworld
)

#DUMP All Variable
get_cmake_property(_variableNames VARIABLES)
foreach (_variableName ${_variableNames})
#    message(STATUS "${_variableName}=${${_variableName}}")
endforeach()





