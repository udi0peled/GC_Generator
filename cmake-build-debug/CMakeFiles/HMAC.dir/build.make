# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

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
CMAKE_COMMAND = /home/udi/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/192.7142.39/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/udi/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/192.7142.39/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/udi/MEGA/Fireblocks/Dev/HMAC

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/HMAC.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/HMAC.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/HMAC.dir/flags.make

CMakeFiles/HMAC.dir/main.c.o: CMakeFiles/HMAC.dir/flags.make
CMakeFiles/HMAC.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/HMAC.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/HMAC.dir/main.c.o   -c /home/udi/MEGA/Fireblocks/Dev/HMAC/main.c

CMakeFiles/HMAC.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/HMAC.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/udi/MEGA/Fireblocks/Dev/HMAC/main.c > CMakeFiles/HMAC.dir/main.c.i

CMakeFiles/HMAC.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/HMAC.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/udi/MEGA/Fireblocks/Dev/HMAC/main.c -o CMakeFiles/HMAC.dir/main.c.s

CMakeFiles/HMAC.dir/common.c.o: CMakeFiles/HMAC.dir/flags.make
CMakeFiles/HMAC.dir/common.c.o: common.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/HMAC.dir/common.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/HMAC.dir/common.c.o   -c /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug/common.c

CMakeFiles/HMAC.dir/common.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/HMAC.dir/common.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug/common.c > CMakeFiles/HMAC.dir/common.c.i

CMakeFiles/HMAC.dir/common.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/HMAC.dir/common.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug/common.c -o CMakeFiles/HMAC.dir/common.c.s

# Object files for target HMAC
HMAC_OBJECTS = \
"CMakeFiles/HMAC.dir/main.c.o" \
"CMakeFiles/HMAC.dir/common.c.o"

# External object files for target HMAC
HMAC_EXTERNAL_OBJECTS =

HMAC: CMakeFiles/HMAC.dir/main.c.o
HMAC: CMakeFiles/HMAC.dir/common.c.o
HMAC: CMakeFiles/HMAC.dir/build.make
HMAC: CMakeFiles/HMAC.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable HMAC"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/HMAC.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/HMAC.dir/build: HMAC

.PHONY : CMakeFiles/HMAC.dir/build

CMakeFiles/HMAC.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/HMAC.dir/cmake_clean.cmake
.PHONY : CMakeFiles/HMAC.dir/clean

CMakeFiles/HMAC.dir/depend:
	cd /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/udi/MEGA/Fireblocks/Dev/HMAC /home/udi/MEGA/Fireblocks/Dev/HMAC /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug /home/udi/MEGA/Fireblocks/Dev/HMAC/cmake-build-debug/CMakeFiles/HMAC.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/HMAC.dir/depend

