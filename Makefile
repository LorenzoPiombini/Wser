.DEFAULT_GOAL := wser 

.PHONY: debug clean install-server

PREFIX ?= /usr/local
bindir ?= $(PREFIX)/bin

DISTRO := $(shell . /etc/os-release && echo $$ID)

SRC = $(wildcard src/*.c)

debug: wser-debug db-debug ez-debug

WSER_OBJ = 	$(patsubst src/%.c, obj/wser/%.o, $(SRC))
DB_OBJ = 	$(patsubst src/%.c, obj/db/%.o, $(SRC))
EZ_OBJ = 	$(patsubst src/%.c, obj/ez/%.o, $(SRC))
DEBUG_OBJ = $(patsubst src/%.c, obj/debug/%.o, $(SRC))
DB_DEBUG_OBJ = $(patsubst src/%.c, obj/db-debug/%.o, $(SRC))
EZ_DEBUG_OBJ = $(patsubst src/%.c, obj/ez-debug/%.o, $(SRC))

# Flags for compilation

CFLAGS = -Iinclude -Wall -Wextra 
RELEASE_CFLAGS = -O3 -fhardened
DEBUG_FLAGS = -O0 -g3 -fsanitize=address,undefined
SECURITY_FLAGS = -Wl,-z,noexecstack

COMMON_LIBS := -lcrypto -lssl
DB_LIBS := -lcrud -ldblua -llua5.4 -lworker



ifeq ($(DISTRO),fedora)
	CFLAGS += -DFEDORA
	LIBDIR = /usr/lib64
else
	LIBDIR = /usr/local/lib
endif

OBJlibnet = obj/network.o obj/request.o obj/response.o obj/monitor.o
LIBNAMEnet = net
INCLUDEDIR = /usr/local/include
SHAREDLIBnet = lib$(LIBNAMEnet).so


library: $(SHAREDLIBnet)

$(SHAREDLIBnet): $(OBJlibnet)
	gcc -shared -o $@ $^

obj/%.o: src/%.c
	@mkdir -p $(@D)
	gcc $(CFLAGS) -fPIC -c $< -o $@


default: $(TARGET)
	
clean: 
	rm -rf obj/wser obj/db obj/ez
	rm -rf obj/debug obj/db-debug obj/ez-debug
	rm -f wser db ez wser-debug db-debug ez-debug
	rm -f *.so

# Normal web server
wser: $(WSER_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(RELEASE_CFLAGS) $(SECURITY_FLAGS) $(COMMON_LIBS)

install-server: wser
	install -D -m 0755 wser "$(DESTDIR)$(bindir)/wser"

# web server with database 
db: $(DB_OBJ)
	gcc -o $@ $^ $(RELEASE_CFLAGS) $(SECURITY_FLAGS) $(COMMON_LIBS) $(DB_LIBS) 

# web server being the GUI for Ezgen
ez: $(EZ_OBJ)
	gcc -o $@ $^ $(RELEASE_CFLAGS) $(SECURITY_FLAGS) $(COMMON_LIBS)

wser-debug: $(DEBUG_OBJ)
	gcc -o $@ $^ $(COMMON_LIBS) $(DEBUG_FLAGS) 

db-debug: $(DB_DEBUG_OBJ)
	gcc -o $@ $^ $(COMMON_LIBS) $(DEBUG_FLAGS) $(DB_LIBS)

ez-debug: $(EZ_DEBUG_OBJ)
	gcc -o $@ $^ $(COMMON_LIBS) $(DEBUG_FLAGS) 

obj/wser/%.o : src/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(RELEASE_CFLAGS) -c $< -o $@

obj/ez/%.o: src/%.c
	@mkdir -p $(@D)
	gcc  -DEZ_GUI $(CFLAGS) $(RELEASE_CFLAGS)  -c $< -o $@

obj/db/%.o: src/%.c
	@mkdir -p $(@D)
	gcc  -DOWN_DB $(CFLAGS) $(RELEASE_CFLAGS) -c $< -o $@

obj/db-debug/%.o : src/%.c
	@mkdir -p $(@D)
	gcc -DOWN_DB $(CFLAGS) $(DEBUG_FLAGS) -c $< -o $@

obj/debug/%.o : src/%.c
	@mkdir -p $(@D)
	gcc $(CFLAGS) $(DEBUG_FLAGS) -c $< -o $@

# DEBUG for web server being Ezgen GUI
obj/ez-debug/%.o : src/%.c
	@mkdir -p $(@D)
	gcc -DEZ_GUI $(CFLAGS) $(DEBUG_FLAGS) -c $< -o $@

install: wser library
	install -d $(INCLUDEDIR)
	install -m 644 include/main.h include/load.h include/network.h  include/request.h include/response.h $(INCLUDEDIR)/
	install -m 755 $(SHAREDLIBnet) $(LIBDIR)
	ldconfig
	
