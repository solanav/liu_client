# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/solanav/Projects/liu_env/client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/solanav/Projects/liu_env/client/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/test_pingpong.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_pingpong.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_pingpong.dir/flags.make

tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o: tests/CMakeFiles/test_pingpong.dir/flags.make
tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o: ../tests/test_pingpong.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/solanav/Projects/liu_env/client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o"
	cd /home/solanav/Projects/liu_env/client/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_pingpong.dir/test_pingpong.c.o   -c /home/solanav/Projects/liu_env/client/tests/test_pingpong.c

tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_pingpong.dir/test_pingpong.c.i"
	cd /home/solanav/Projects/liu_env/client/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/solanav/Projects/liu_env/client/tests/test_pingpong.c > CMakeFiles/test_pingpong.dir/test_pingpong.c.i

tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_pingpong.dir/test_pingpong.c.s"
	cd /home/solanav/Projects/liu_env/client/build/tests && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/solanav/Projects/liu_env/client/tests/test_pingpong.c -o CMakeFiles/test_pingpong.dir/test_pingpong.c.s

tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.requires:

.PHONY : tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.requires

tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.provides: tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.requires
	$(MAKE) -f tests/CMakeFiles/test_pingpong.dir/build.make tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.provides.build
.PHONY : tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.provides

tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.provides.build: tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o


# Object files for target test_pingpong
test_pingpong_OBJECTS = \
"CMakeFiles/test_pingpong.dir/test_pingpong.c.o"

# External object files for target test_pingpong
test_pingpong_EXTERNAL_OBJECTS = \
"/home/solanav/Projects/liu_env/client/build/CMakeFiles/net_lib.dir/src/network/active.c.o" \
"/home/solanav/Projects/liu_env/client/build/CMakeFiles/net_lib.dir/src/network/reactive.c.o" \
"/home/solanav/Projects/liu_env/client/build/CMakeFiles/net_lib.dir/src/network/peers.c.o" \
"/home/solanav/Projects/liu_env/client/build/CMakeFiles/net_lib.dir/src/network/netcore.c.o" \
"/home/solanav/Projects/liu_env/client/build/CMakeFiles/core_lib.dir/src/keylogger.c.o" \
"/home/solanav/Projects/liu_env/client/build/CMakeFiles/core_lib.dir/src/plugin_utils.c.o" \
"/home/solanav/Projects/liu_env/client/build/CMakeFiles/core_lib.dir/src/system_utils.c.o"

tests/test_pingpong: tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o
tests/test_pingpong: CMakeFiles/net_lib.dir/src/network/active.c.o
tests/test_pingpong: CMakeFiles/net_lib.dir/src/network/reactive.c.o
tests/test_pingpong: CMakeFiles/net_lib.dir/src/network/peers.c.o
tests/test_pingpong: CMakeFiles/net_lib.dir/src/network/netcore.c.o
tests/test_pingpong: CMakeFiles/core_lib.dir/src/keylogger.c.o
tests/test_pingpong: CMakeFiles/core_lib.dir/src/plugin_utils.c.o
tests/test_pingpong: CMakeFiles/core_lib.dir/src/system_utils.c.o
tests/test_pingpong: tests/CMakeFiles/test_pingpong.dir/build.make
tests/test_pingpong: ../lib/libhydrogen.a
tests/test_pingpong: tests/CMakeFiles/test_pingpong.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/solanav/Projects/liu_env/client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable test_pingpong"
	cd /home/solanav/Projects/liu_env/client/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_pingpong.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_pingpong.dir/build: tests/test_pingpong

.PHONY : tests/CMakeFiles/test_pingpong.dir/build

tests/CMakeFiles/test_pingpong.dir/requires: tests/CMakeFiles/test_pingpong.dir/test_pingpong.c.o.requires

.PHONY : tests/CMakeFiles/test_pingpong.dir/requires

tests/CMakeFiles/test_pingpong.dir/clean:
	cd /home/solanav/Projects/liu_env/client/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_pingpong.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_pingpong.dir/clean

tests/CMakeFiles/test_pingpong.dir/depend:
	cd /home/solanav/Projects/liu_env/client/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/solanav/Projects/liu_env/client /home/solanav/Projects/liu_env/client/tests /home/solanav/Projects/liu_env/client/build /home/solanav/Projects/liu_env/client/build/tests /home/solanav/Projects/liu_env/client/build/tests/CMakeFiles/test_pingpong.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_pingpong.dir/depend

