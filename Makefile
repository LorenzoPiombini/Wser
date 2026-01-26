TARGET = wser
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))

OBJlibnet = obj/network.o obj/request.o obj/response.o obj/monitor.o

LIBNAMEnet = net
LIBDIR = /usr/local/lib
INCLUDEDIR = /usr/local/include
SHAREDLIBnet = lib$(LIBNAMEnet).so


library:
	gcc -Wall -fPIC -shared -o $(SHAREDLIBnet) $(OBJlibnet)

default: $(TARGET)
	
clean: 
	rm obj/*.*
	rm ./$(TARGET)
	rm *.so

$(TARGET):$(OBJ)
	gcc -o $@ $? -lcrypto -lssl -fpie -pie -z relro -z now -z noexecstack -fsanitize=address 

obj/%.o : src/%.c
	gcc  -Wall -Wextra -g3 -c $< -o $@ -Iinclude -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC -pie -fsanitize=address 

install: $(TARGET) library
	install -d $(INCLUDEDIR)
	install -m 644 include/load.h include/network.h  include/request.h include/response.h $(INCLUDEDIR)/
	install -m 755 $(SHAREDLIBnet) $(LIBDIR)
	ldconfig
	
