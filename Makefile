TARGET = wser
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))


default: $(TARGET)
	
clean: 
	rm obj/*.*
	rm ./$(TARGET)

$(TARGET):$(OBJ)
	gcc -o $@ $? -fpie -pie -z relro -z now -z noexecstack -fsanitize=address 

obj/%.o : src/%.c
	gcc  -Wall -Wextra -g3 -c $< -o $@ -Iinclude -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC -pie -fsanitize=address 
