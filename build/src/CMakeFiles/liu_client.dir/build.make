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
CMAKE_SOURCE_DIR = /home/artiimor/Liu/liu_client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/artiimor/Liu/liu_client/build

# Include any dependencies generated for this target.
include src/CMakeFiles/liu_client.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/liu_client.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/liu_client.dir/flags.make

src/CMakeFiles/liu_client.dir/core.c.o: src/CMakeFiles/liu_client.dir/flags.make
src/CMakeFiles/liu_client.dir/core.c.o: ../src/core.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/artiimor/Liu/liu_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/liu_client.dir/core.c.o"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/liu_client.dir/core.c.o   -c /home/artiimor/Liu/liu_client/src/core.c

src/CMakeFiles/liu_client.dir/core.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/liu_client.dir/core.c.i"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/artiimor/Liu/liu_client/src/core.c > CMakeFiles/liu_client.dir/core.c.i

src/CMakeFiles/liu_client.dir/core.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/liu_client.dir/core.c.s"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/artiimor/Liu/liu_client/src/core.c -o CMakeFiles/liu_client.dir/core.c.s

src/CMakeFiles/liu_client.dir/core.c.o.requires:

.PHONY : src/CMakeFiles/liu_client.dir/core.c.o.requires

src/CMakeFiles/liu_client.dir/core.c.o.provides: src/CMakeFiles/liu_client.dir/core.c.o.requires
	$(MAKE) -f src/CMakeFiles/liu_client.dir/build.make src/CMakeFiles/liu_client.dir/core.c.o.provides.build
.PHONY : src/CMakeFiles/liu_client.dir/core.c.o.provides

src/CMakeFiles/liu_client.dir/core.c.o.provides.build: src/CMakeFiles/liu_client.dir/core.c.o


src/CMakeFiles/liu_client.dir/keylogger.c.o: src/CMakeFiles/liu_client.dir/flags.make
src/CMakeFiles/liu_client.dir/keylogger.c.o: ../src/keylogger.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/artiimor/Liu/liu_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/CMakeFiles/liu_client.dir/keylogger.c.o"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/liu_client.dir/keylogger.c.o   -c /home/artiimor/Liu/liu_client/src/keylogger.c

src/CMakeFiles/liu_client.dir/keylogger.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/liu_client.dir/keylogger.c.i"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/artiimor/Liu/liu_client/src/keylogger.c > CMakeFiles/liu_client.dir/keylogger.c.i

src/CMakeFiles/liu_client.dir/keylogger.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/liu_client.dir/keylogger.c.s"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/artiimor/Liu/liu_client/src/keylogger.c -o CMakeFiles/liu_client.dir/keylogger.c.s

src/CMakeFiles/liu_client.dir/keylogger.c.o.requires:

.PHONY : src/CMakeFiles/liu_client.dir/keylogger.c.o.requires

src/CMakeFiles/liu_client.dir/keylogger.c.o.provides: src/CMakeFiles/liu_client.dir/keylogger.c.o.requires
	$(MAKE) -f src/CMakeFiles/liu_client.dir/build.make src/CMakeFiles/liu_client.dir/keylogger.c.o.provides.build
.PHONY : src/CMakeFiles/liu_client.dir/keylogger.c.o.provides

src/CMakeFiles/liu_client.dir/keylogger.c.o.provides.build: src/CMakeFiles/liu_client.dir/keylogger.c.o


src/CMakeFiles/liu_client.dir/network_utils.c.o: src/CMakeFiles/liu_client.dir/flags.make
src/CMakeFiles/liu_client.dir/network_utils.c.o: ../src/network_utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/artiimor/Liu/liu_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object src/CMakeFiles/liu_client.dir/network_utils.c.o"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/liu_client.dir/network_utils.c.o   -c /home/artiimor/Liu/liu_client/src/network_utils.c

src/CMakeFiles/liu_client.dir/network_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/liu_client.dir/network_utils.c.i"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/artiimor/Liu/liu_client/src/network_utils.c > CMakeFiles/liu_client.dir/network_utils.c.i

src/CMakeFiles/liu_client.dir/network_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/liu_client.dir/network_utils.c.s"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/artiimor/Liu/liu_client/src/network_utils.c -o CMakeFiles/liu_client.dir/network_utils.c.s

src/CMakeFiles/liu_client.dir/network_utils.c.o.requires:

.PHONY : src/CMakeFiles/liu_client.dir/network_utils.c.o.requires

src/CMakeFiles/liu_client.dir/network_utils.c.o.provides: src/CMakeFiles/liu_client.dir/network_utils.c.o.requires
	$(MAKE) -f src/CMakeFiles/liu_client.dir/build.make src/CMakeFiles/liu_client.dir/network_utils.c.o.provides.build
.PHONY : src/CMakeFiles/liu_client.dir/network_utils.c.o.provides

src/CMakeFiles/liu_client.dir/network_utils.c.o.provides.build: src/CMakeFiles/liu_client.dir/network_utils.c.o


src/CMakeFiles/liu_client.dir/plugin_utils.c.o: src/CMakeFiles/liu_client.dir/flags.make
src/CMakeFiles/liu_client.dir/plugin_utils.c.o: ../src/plugin_utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/artiimor/Liu/liu_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object src/CMakeFiles/liu_client.dir/plugin_utils.c.o"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/liu_client.dir/plugin_utils.c.o   -c /home/artiimor/Liu/liu_client/src/plugin_utils.c

src/CMakeFiles/liu_client.dir/plugin_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/liu_client.dir/plugin_utils.c.i"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/artiimor/Liu/liu_client/src/plugin_utils.c > CMakeFiles/liu_client.dir/plugin_utils.c.i

src/CMakeFiles/liu_client.dir/plugin_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/liu_client.dir/plugin_utils.c.s"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/artiimor/Liu/liu_client/src/plugin_utils.c -o CMakeFiles/liu_client.dir/plugin_utils.c.s

src/CMakeFiles/liu_client.dir/plugin_utils.c.o.requires:

.PHONY : src/CMakeFiles/liu_client.dir/plugin_utils.c.o.requires

src/CMakeFiles/liu_client.dir/plugin_utils.c.o.provides: src/CMakeFiles/liu_client.dir/plugin_utils.c.o.requires
	$(MAKE) -f src/CMakeFiles/liu_client.dir/build.make src/CMakeFiles/liu_client.dir/plugin_utils.c.o.provides.build
.PHONY : src/CMakeFiles/liu_client.dir/plugin_utils.c.o.provides

src/CMakeFiles/liu_client.dir/plugin_utils.c.o.provides.build: src/CMakeFiles/liu_client.dir/plugin_utils.c.o


src/CMakeFiles/liu_client.dir/system_utils.c.o: src/CMakeFiles/liu_client.dir/flags.make
src/CMakeFiles/liu_client.dir/system_utils.c.o: ../src/system_utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/artiimor/Liu/liu_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object src/CMakeFiles/liu_client.dir/system_utils.c.o"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/liu_client.dir/system_utils.c.o   -c /home/artiimor/Liu/liu_client/src/system_utils.c

src/CMakeFiles/liu_client.dir/system_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/liu_client.dir/system_utils.c.i"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/artiimor/Liu/liu_client/src/system_utils.c > CMakeFiles/liu_client.dir/system_utils.c.i

src/CMakeFiles/liu_client.dir/system_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/liu_client.dir/system_utils.c.s"
	cd /home/artiimor/Liu/liu_client/build/src && /usr/bin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/artiimor/Liu/liu_client/src/system_utils.c -o CMakeFiles/liu_client.dir/system_utils.c.s

src/CMakeFiles/liu_client.dir/system_utils.c.o.requires:

.PHONY : src/CMakeFiles/liu_client.dir/system_utils.c.o.requires

src/CMakeFiles/liu_client.dir/system_utils.c.o.provides: src/CMakeFiles/liu_client.dir/system_utils.c.o.requires
	$(MAKE) -f src/CMakeFiles/liu_client.dir/build.make src/CMakeFiles/liu_client.dir/system_utils.c.o.provides.build
.PHONY : src/CMakeFiles/liu_client.dir/system_utils.c.o.provides

src/CMakeFiles/liu_client.dir/system_utils.c.o.provides.build: src/CMakeFiles/liu_client.dir/system_utils.c.o


# Object files for target liu_client
liu_client_OBJECTS = \
"CMakeFiles/liu_client.dir/core.c.o" \
"CMakeFiles/liu_client.dir/keylogger.c.o" \
"CMakeFiles/liu_client.dir/network_utils.c.o" \
"CMakeFiles/liu_client.dir/plugin_utils.c.o" \
"CMakeFiles/liu_client.dir/system_utils.c.o"

# External object files for target liu_client
liu_client_EXTERNAL_OBJECTS =

src/liu_client: src/CMakeFiles/liu_client.dir/core.c.o
src/liu_client: src/CMakeFiles/liu_client.dir/keylogger.c.o
src/liu_client: src/CMakeFiles/liu_client.dir/network_utils.c.o
src/liu_client: src/CMakeFiles/liu_client.dir/plugin_utils.c.o
src/liu_client: src/CMakeFiles/liu_client.dir/system_utils.c.o
src/liu_client: src/CMakeFiles/liu_client.dir/build.make
src/liu_client: src/CMakeFiles/liu_client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/artiimor/Liu/liu_client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C executable liu_client"
	cd /home/artiimor/Liu/liu_client/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/liu_client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/liu_client.dir/build: src/liu_client

.PHONY : src/CMakeFiles/liu_client.dir/build

src/CMakeFiles/liu_client.dir/requires: src/CMakeFiles/liu_client.dir/core.c.o.requires
src/CMakeFiles/liu_client.dir/requires: src/CMakeFiles/liu_client.dir/keylogger.c.o.requires
src/CMakeFiles/liu_client.dir/requires: src/CMakeFiles/liu_client.dir/network_utils.c.o.requires
src/CMakeFiles/liu_client.dir/requires: src/CMakeFiles/liu_client.dir/plugin_utils.c.o.requires
src/CMakeFiles/liu_client.dir/requires: src/CMakeFiles/liu_client.dir/system_utils.c.o.requires

.PHONY : src/CMakeFiles/liu_client.dir/requires

src/CMakeFiles/liu_client.dir/clean:
	cd /home/artiimor/Liu/liu_client/build/src && $(CMAKE_COMMAND) -P CMakeFiles/liu_client.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/liu_client.dir/clean

src/CMakeFiles/liu_client.dir/depend:
	cd /home/artiimor/Liu/liu_client/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/artiimor/Liu/liu_client /home/artiimor/Liu/liu_client/src /home/artiimor/Liu/liu_client/build /home/artiimor/Liu/liu_client/build/src /home/artiimor/Liu/liu_client/build/src/CMakeFiles/liu_client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/liu_client.dir/depend

