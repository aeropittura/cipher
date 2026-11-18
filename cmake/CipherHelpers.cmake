#
# Helper functions shared by the library, test, example and benchmark build scripts.
#

# cipher_add_module(<name> SOURCES <files...> [DEPENDS <modules...>])
#
# Builds one library module as an object library and wraps it into cipher_<name> (shared)
# and/or cipher_<name>_static, exported as Cipher::<name> and Cipher::<name>_static.
function(cipher_add_module name)
    cmake_parse_arguments(ARG "" "" "SOURCES;DEPENDS" ${ARGN})
    set(obj cipher_${name}_obj)
    add_library(${obj} OBJECT ${ARG_SOURCES})
    set_property(TARGET ${obj} PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_include_directories(${obj} PUBLIC ${CIPHER_BUILD_INCLUDE_DIRS})
    add_dependencies(${obj} cipher_data)

    set(_variants "")
    if(CIPHER_BUILD_SHARED)
        list(APPEND _variants shared)
    endif()
    if(CIPHER_BUILD_STATIC)
        list(APPEND _variants static)
    endif()

    foreach(variant IN LISTS _variants)
        if(variant STREQUAL "shared")
            set(lib cipher_${name})
            add_library(${lib} SHARED $<TARGET_OBJECTS:${obj}>)
            set_target_properties(${lib} PROPERTIES
                VERSION ${PROJECT_VERSION}
                SOVERSION ${PROJECT_VERSION_MAJOR}
                EXPORT_NAME ${name}
                INSTALL_RPATH "${Cipher_INSTALL_RPATH}")
            set(_thirdparty ${CIPHER_THIRDPARTY_LIBS})
            set(_suffix "")
        else()
            set(lib cipher_${name}_static)
            add_library(${lib} STATIC $<TARGET_OBJECTS:${obj}>)
            set_target_properties(${lib} PROPERTIES EXPORT_NAME ${name}_static)
            set(_thirdparty ${CIPHER_THIRDPARTY_STATIC_LIBS})
            set(_suffix "_static")
        endif()
        add_library(Cipher::${name}${_suffix} ALIAS ${lib})
        target_include_directories(${lib} PUBLIC
            "$<BUILD_INTERFACE:${CIPHER_BUILD_INCLUDE_DIRS}>"
            "$<INSTALL_INTERFACE:${Cipher_INSTALL_INCLUDEDIR}>"
            "$<INSTALL_INTERFACE:${Cipher_INSTALL_INCLUDEDIR}/cipher/extern>")
        target_compile_definitions(${lib} PUBLIC CIPHER_MATH_BACKEND=${CIPHER_MATH_BACKEND})
        if(CIPHER_WITH_OPENMP)
            target_compile_definitions(${lib} PUBLIC CIPHER_PARALLEL)
        endif()
        set(_deps "")
        foreach(dep IN LISTS ARG_DEPENDS)
            list(APPEND _deps cipher_${dep}${_suffix})
        endforeach()
        target_link_libraries(${lib} PUBLIC ${_deps} ${_thirdparty} ${OpenMP_CXX_FLAGS} ${CIPHER_EXTRA_LIBS})
        install(TARGETS ${lib}
            EXPORT CipherTargets
            RUNTIME DESTINATION ${Cipher_INSTALL_BINDIR}
            LIBRARY DESTINATION ${Cipher_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${Cipher_INSTALL_LIBDIR})
        set_property(GLOBAL APPEND PROPERTY CIPHER_LIBRARY_TARGETS ${lib})
    endforeach()

    foreach(dep IN LISTS ARG_DEPENDS)
        add_dependencies(${obj} cipher_${dep}_obj)
    endforeach()
endfunction()

# cipher_program_libs(<out-var> <module>)
#
# The libraries an in-tree program links to use <module>: the shared flavor when it is
# built, the static one otherwise, plus the optional out-of-library diagnostic sink.
function(cipher_program_libs out module)
    if(CIPHER_BUILD_SHARED)
        set(libs cipher_${module})
    else()
        set(libs cipher_${module}_static)
    endif()
    if(NOT CIPHER_WITH_DEFAULT_DIAGNOSTIC_SINK)
        list(APPEND libs cipher_diagnostic_sink)
    endif()
    if(NOT CIPHER_WITH_OPENMP AND NOT EMSCRIPTEN)
        list(APPEND libs Threads::Threads)
    endif()
    set(${out} ${libs} PARENT_SCOPE)
endfunction()

# cipher_add_programs(<group> MODULE <module> OUTPUT <dir> SOURCES <files...>
#                     [SKIP <names...>] [EXTRA_SOURCES <name> <files...>])
#
# Adds one executable per source file (named after the file) linked against <module>, placed
# in <build>/bin/<dir>, and an umbrella target <group> that builds all of them.
function(cipher_add_programs group)
    cmake_parse_arguments(ARG "" "MODULE;OUTPUT" "SOURCES;SKIP;INCLUDES;LIBS" ${ARGN})
    cipher_program_libs(libs ${ARG_MODULE})
    set(targets "")
    foreach(src IN LISTS ARG_SOURCES)
        get_filename_component(exe ${src} NAME_WE)
        if(exe IN_LIST ARG_SKIP)
            continue()
        endif()
        add_executable(${exe} ${src} ${CIPHER_PROGRAM_EXTRA_SOURCES_${exe}})
        set_target_properties(${exe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/${ARG_OUTPUT})
        target_include_directories(${exe} PRIVATE ${ARG_INCLUDES})
        target_link_libraries(${exe} PRIVATE ${libs} ${ARG_LIBS})
        list(APPEND targets ${exe})
    endforeach()
    if(NOT TARGET ${group})
        add_custom_target(${group})
    endif()
    if(targets)
        add_dependencies(${group} ${targets})
    endif()
endfunction()
