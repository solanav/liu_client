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
CMAKE_SOURCE_DIR = /home/solanav/Projects/liu/client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/solanav/Projects/liu/client/build

# Include any dependencies generated for this target.
include plugins/CMakeFiles/encrypt.dir/depend.make

# Include the progress variables for this target.
include plugins/CMakeFiles/encrypt.dir/progress.make

# Include the compile flags for this target's objects.
include plugins/CMakeFiles/encrypt.dir/flags.make

plugins/CMakeFiles/encrypt.dir/encrypt.c.o: plugins/CMakeFiles/encrypt.dir/flags.make
plugins/CMakeFiles/encrypt.dir/encrypt.c.o: ../plugins/encrypt.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/solanav/Projects/liu/client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object plugins/CMakeFiles/encrypt.dir/encrypt.c.o"
	cd /home/solanav/Projects/liu/client/build/plugins && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/encrypt.dir/encrypt.c.o   -c /home/solanav/Projects/liu/client/plugins/encrypt.c

plugins/CMakeFiles/encrypt.dir/encrypt.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/encrypt.dir/encrypt.c.i"
	cd /home/solanav/Projects/liu/client/build/plugins && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/solanav/Projects/liu/client/plugins/encrypt.c > CMakeFiles/encrypt.dir/encrypt.c.i

plugins/CMakeFiles/encrypt.dir/encrypt.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/encrypt.dir/encrypt.c.s"
	cd /home/solanav/Projects/liu/client/build/plugins && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/solanav/Projects/liu/client/plugins/encrypt.c -o CMakeFiles/encrypt.dir/encrypt.c.s

plugins/CMakeFiles/encrypt.dir/encrypt.c.o.requires:

.PHONY : plugins/CMakeFiles/encrypt.dir/encrypt.c.o.requires

plugins/CMakeFiles/encrypt.dir/encrypt.c.o.provides: plugins/CMakeFiles/encrypt.dir/encrypt.c.o.requires
	$(MAKE) -f plugins/CMakeFiles/encrypt.dir/build.make plugins/CMakeFiles/encrypt.dir/encrypt.c.o.provides.build
.PHONY : plugins/CMakeFiles/encrypt.dir/encrypt.c.o.provides

plugins/CMakeFiles/encrypt.dir/encrypt.c.o.provides.build: plugins/CMakeFiles/encrypt.dir/encrypt.c.o


# Object files for target encrypt
encrypt_OBJECTS = \
"CMakeFiles/encrypt.dir/encrypt.c.o"

# External object files for target encrypt
encrypt_EXTERNAL_OBJECTS =

plugins/libencrypt.so: plugins/CMakeFiles/encrypt.dir/encrypt.c.o
plugins/libencrypt.so: plugins/CMakeFiles/encrypt.dir/build.make
plugins/libencrypt.so: plugins/CMakeFiles/encrypt.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/solanav/Projects/liu/client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library libencrypt.so"
	cd /home/solanav/Projects/liu/client/build/plugins && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/encrypt.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
plugins/CMakeFiles/encrypt.dir/build: plugins/libencrypt.so

.PHONY : plugins/CMakeFiles/encrypt.dir/build

plugins/CMakeFiles/encrypt.dir/requires: plugins/CMakeFiles/encrypt.dir/encrypt.c.o.requires

.PHONY : plugins/CMakeFiles/encrypt.dir/requires

plugins/CMakeFiles/encrypt.dir/clean:
	cd /home/solanav/Projects/liu/client/build/plugins && $(CMAKE_COMMAND) -P CMakeFiles/encrypt.dir/cmake_clean.cmake
.PHONY : plugins/CMakeFiles/encrypt.dir/clean

plugins/CMakeFiles/encrypt.dir/depend:
	cd /home/solanav/Projects/liu/client/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/solanav/Projects/liu/client /home/solanav/Projects/liu/client/plugins /home/solanav/Projects/liu/client/build /home/solanav/Projects/liu/client/build/plugins /home/solanav/Projects/liu/client/build/plugins/CMakeFiles/encrypt.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : plugins/CMakeFiles/encrypt.dir/depend

