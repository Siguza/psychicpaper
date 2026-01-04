TARGET := plparse
SRC_C  := src/*.c
SRC_H  := src/*.h
FLAGS  := -std=gnu17 -Wall -O3

ifndef HOST_OS
    ifeq ($(OS),Windows_NT)
        HOST_OS	:= Windows
    else
        HOST_OS	:= $(shell uname -s)
    endif
endif

ifeq ($(HOST_OS),Darwin)
    FLAGS += -framework CoreFoundation -framework IOKit -framework Security
else
    FLAGS += -Wno-unused-but-set-variable -isystem IOCFBootleg/include -isystem IOCFBootleg/src
    SRC_C += IOCFBootleg/src/CoreFoundation/*.c IOCFBootleg/src/IOKit/*.c aux/*.c
    SRC_H += IOCFBootleg/src/CoreFoundation/*.h IOCFBootleg/src/device/*.h IOCFBootleg/src/*.h IOCFBootleg/include/CoreFoundation/*.h IOCFBootleg/include/IOKit/*.h IOCFBootleg/include/System/libkern/*.h
endif


.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC_C) $(SRC_H)
	$(CC) -o $@ $(SRC_C) $(FLAGS) $(CFLAGS)

clean:
	rm -f $(TARGET)
