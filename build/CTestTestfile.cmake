# CMake generated Testfile for 
# Source directory: /home/solanav/Projects/liu_env/client
# Build directory: /home/solanav/Projects/liu_env/client/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(network_active "/home/solanav/Projects/liu_env/client/build/tests/test_network_active")
add_test(system_utils "/home/solanav/Projects/liu_env/client/build/tests/test_system_utils")
add_test(network_utils "/home/solanav/Projects/liu_env/client/build/tests/test_network_utils")
add_test(pingpong "/home/solanav/Projects/liu_env/client/build/tests/test_pingpong")
add_test(peerexchange "/home/solanav/Projects/liu_env/client/build/tests/test_peerexchange")
subdirs("src")
subdirs("plugins")
subdirs("tests")
