#Testing macro
macro (add_test_executable_with_lib _name libs)
	add_executable(test_${_name} "${_name}.cpp")
	target_link_libraries(test_${_name} ${EMP-OT_LIBRARIES})
endmacro()

macro (add_test_case _name)
	add_test_executable_with_lib(${_name} "")
  	add_test(NAME ${_name} COMMAND "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${_name}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")
endmacro()

macro (add_test_case_with_run _name)
	add_test_executable_with_lib(${_name} "")
	add_test(NAME ${_name} COMMAND "./run" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_${_name}" WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/")

endmacro()

# Test cases
# add_test_case_with_run(bit)
# add_test_case_with_run(int)
# IF(${ENABLE_FLOAT})
# add_test_case_with_run(float)
# ENDIF(${ENABLE_FLOAT})
# add_test_case_with_run(circuit_file)
# add_test_case_with_run(example)
# add_test_case_with_run(repeat)
add_test_case_with_run(2pc_hmac_expand)
add_test_case_with_run(2pc_hmac_key_iopad)
add_test_case_with_run(2pc_hmac_msg)
add_test_case_with_run(2pc_tls12_ems_s1s2sum)
add_test_case_with_run(2pc_tls12_ems_s1s2sum_secp256r1)
add_test_case_with_run(2pc_tls12_sha256)
add_test_case_with_run(2pc_tls12_expand)