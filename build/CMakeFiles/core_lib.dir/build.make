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
include CMakeFiles/core_lib.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/core_lib.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/core_lib.dir/flags.make

CMakeFiles/core_lib.dir/src/keylogger.c.o: CMakeFiles/core_lib.dir/flags.make
CMakeFiles/core_lib.dir/src/keylogger.c.o: ../src/keylogger.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/solanav/Projects/liu_env/client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/core_lib.dir/src/keylogger.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/core_lib.dir/src/keylogger.c.o   -c /home/solanav/Projects/liu_env/client/src/keylogger.c

CMakeFiles/core_lib.dir/src/keylogger.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/core_lib.dir/src/keylogger.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/solanav/Projects/liu_env/client/src/keylogger.c > CMakeFiles/core_lib.dir/src/keylogger.c.i

CMakeFiles/core_lib.dir/src/keylogger.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/core_lib.dir/src/keylogger.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/solanav/Projects/liu_env/client/src/keylogger.c -o CMakeFiles/core_lib.dir/src/keylogger.c.s

CMakeFiles/core_lib.dir/src/keylogger.c.o.requires:

.PHONY : CMakeFiles/core_lib.dir/src/keylogger.c.o.requires

CMakeFiles/core_lib.dir/src/keylogger.c.o.provides: CMakeFiles/core_lib.dir/src/keylogger.c.o.requires
	$(MAKE) -f CMakeFiles/core_lib.dir/build.make CMakeFiles/core_lib.dir/src/keylogger.c.o.provides.build
.PHONY : CMakeFiles/core_lib.dir/src/keylogger.c.o.provides

CMakeFiles/core_lib.dir/src/keylogger.c.o.provides.build: CMakeFiles/core_lib.dir/src/keylogger.c.o


CMakeFiles/core_lib.dir/src/plugin_utils.c.o: CMakeFiles/core_lib.dir/flags.make
CMakeFiles/core_lib.dir/src/plugin_utils.c.o: ../src/plugin_utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/solanav/Projects/liu_env/client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/core_lib.dir/src/plugin_utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/core_lib.dir/src/plugin_utils.c.o   -c /home/solanav/Projects/liu_env/client/src/plugin_utils.c

CMakeFiles/core_lib.dir/src/plugin_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/core_lib.dir/src/plugin_utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/solanav/Projects/liu_env/client/src/plugin_utils.c > CMakeFiles/core_lib.dir/src/plugin_utils.c.i

CMakeFiles/core_lib.dir/src/plugin_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/core_lib.dir/src/plugin_utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/solanav/Projects/liu_env/client/src/plugin_utils.c -o CMakeFiles/core_lib.dir/src/plugin_utils.c.s

CMakeFiles/core_lib.dir/src/plugin_utils.c.o.requires:

.PHONY : CMakeFiles/core_lib.dir/src/plugin_utils.c.o.requires

CMakeFiles/core_lib.dir/src/plugin_utils.c.o.provides: CMakeFiles/core_lib.dir/src/plugin_utils.c.o.requires
	$(MAKE) -f CMakeFiles/core_lib.dir/build.make CMakeFiles/core_lib.dir/src/plugin_utils.c.o.provides.build
.PHONY : CMakeFiles/core_lib.dir/src/plugin_utils.c.o.provides

CMakeFiles/core_lib.dir/src/plugin_utils.c.o.provides.build: CMakeFiles/core_lib.dir/src/plugin_utils.c.o


CMakeFiles/core_lib.dir/src/system_utils.c.o: CMakeFiles/core_lib.dir/flags.make
CMakeFiles/core_lib.dir/src/system_utils.c.o: ../src/system_utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/solanav/Projects/liu_env/client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/core_lib.dir/src/system_utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/core_lib.dir/src/system_utils.c.o   -c /home/solanav/Projects/liu_env/client/src/system_utils.c

CMakeFiles/core_lib.dir/src/system_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/core_lib.dir/src/system_utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/solanav/Projects/liu_env/client/src/system_utils.c > CMakeFiles/core_lib.dir/src/system_utils.c.i

CMakeFiles/core_lib.dir/src/system_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/core_lib.dir/src/system_utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/solanav/Projects/liu_env/client/src/system_utils.c -o CMakeFiles/core_lib.dir/src/system_utils.c.s

CMakeFiles/core_lib.dir/src/system_utils.c.o.requires:

.PHONY : CMakeFiles/core_lib.dir/src/system_utils.c.o.requires

CMakeFiles/core_lib.dir/src/system_utils.c.o.provides: CMakeFiles/core_lib.dir/src/system_utils.c.o.requires
	$(MAKE) -f CMakeFiles/core_lib.dir/build.make CMakeFiles/core_lib.dir/src/system_utils.c.o.provides.build
.PHONY : CMakeFiles/core_lib.dir/src/system_utils.c.o.provides

CMakeFiles/core_lib.dir/src/system_utils.c.o.provides.build: CMakeFiles/core_lib.dir/src/system_utils.c.o


core_lib: CMakeFiles/core_lib.dir/src/keylogger.c.o
core_lib: CMakeFiles/core_lib.dir/src/plugin_utils.c.o
core_lib: CMakeFiles/core_lib.dir/src/system_utils.c.o
core_lib: CMakeFiles/core_lib.dir/build.make

.PHONY : core_lib

# Rule to build all files generated by this target.
CMakeFiles/core_lib.dir/build: core_lib

.PHONY : CMakeFiles/core_lib.dir/build

CMakeFiles/core_lib.dir/requires: CMakeFiles/core_lib.dir/src/keylogger.c.o.requires
CMakeFiles/core_lib.dir/requires: CMakeFiles/core_lib.dir/src/plugin_utils.c.o.requires
CMakeFiles/core_lib.dir/requires: CMakeFiles/core_lib.dir/src/system_utils.c.o.requires

.PHONY : CMakeFiles/core_lib.dir/requires

CMakeFiles/core_lib.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/core_lib.dir/cmake_clean.cmake
.PHONY : CMakeFiles/core_lib.dir/clean

CMakeFiles/core_lib.dir/depend:
	cd /home/solanav/Projects/liu_env/client/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/solanav/Projects/liu_env/client /home/solanav/Projects/liu_env/client /home/solanav/Projects/liu_env/client/build /home/solanav/Projects/liu_env/client/build /home/solanav/Projects/liu_env/client/build/CMakeFiles/core_lib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/core_lib.dir/depend

