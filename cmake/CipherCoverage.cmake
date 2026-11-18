#
# Coverage report (g++ only): configure with -DCIPHER_WITH_COVERAGE=ON, then build "coverage".
# The HTML report is written to <build>/coverage/assets/index.html.
#
if(NOT CIPHER_WITH_COVERAGE)
    return()
endif()

find_program(LCOV lcov)
find_program(GENHTML genhtml)
if(NOT (LCOV AND GENHTML))
    message(STATUS "lcov and genhtml are needed for the coverage report")
    return()
endif()

# gcov must match the compiler's major version
string(REGEX MATCH "^[0-9]+" _gcc_major "${CMAKE_CXX_COMPILER_VERSION}")
find_program(GCOV NAMES gcov-${_gcc_major} gcov)
if(NOT GCOV)
    message(FATAL_ERROR "No gcov matching GCC ${_gcc_major} was found (e.g. 'apt-get install lcov gcc-${_gcc_major}').")
endif()

execute_process(COMMAND ${LCOV} --version OUTPUT_VARIABLE _lcov_out OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "[0-9]+\\.[0-9]+" _lcov_version "${_lcov_out}")
message(STATUS "lcov ${_lcov_version} found at ${LCOV}")

set(_lcov_ignore "")
if(_lcov_version VERSION_GREATER_EQUAL "2.0")
    # repeated on purpose: lcov 2.x counts repeats to also cover the "multiple" variants
    set(_lcov_ignore --ignore-errors mismatch --ignore-errors mismatch --ignore-errors unused
                     --ignore-errors unused --ignore-errors empty)
endif()
set(_lcov_opts ${_lcov_ignore} --rc geninfo_unexecuted_blocks=1 --gcov-tool ${GCOV}
               --exclude '*/usr/include/*' --exclude '*/extern/*')

set(_cov_dir ${PROJECT_BINARY_DIR}/coverage)
set(_capture "")
foreach(dir IN ITEMS tests/CMakeFiles/core_tests.dir tests/CMakeFiles/fhe_tests.dir
                     tests/CMakeFiles/boolean_tests.dir source/CMakeFiles/cipher_core_obj.dir
                     source/CMakeFiles/cipher_fhe_obj.dir source/CMakeFiles/cipher_boolean_obj.dir)
    string(MAKE_C_IDENTIFIER "${dir}" _name)
    list(APPEND _capture COMMAND ${LCOV} --capture --directory ${PROJECT_BINARY_DIR}/${dir}
                                 --output-file ${_cov_dir}/${_name}.info ${_lcov_opts})
endforeach()

add_custom_target(coverage
    DEPENDS core_tests fhe_tests boolean_tests
    COMMAND ${CMAKE_COMMAND} -E make_directory ${_cov_dir}/assets
    ${_capture}
    COMMAND ${GENHTML} -t "Coverage" -o ${_cov_dir}/assets ${_cov_dir}/*.info
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
