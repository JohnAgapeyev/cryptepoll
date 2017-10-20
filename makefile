CC=gcc
CFLAGS=-Wall -Wextra -std=c11 -pedantic -D_POSIX_C_SOURCE=200809L -O3 -march=native -flto
CLIBS=-pthread -lcrypto
EXEC=cryptepoll.elf
DEPS=$(EXEC).d
SRCWILD=$(wildcard *.c)
HEADWILD=$(wildcard *.h)

all: $(patsubst %.c, %.o, $(SRCWILD))
	$(CC) $(CFLAGS) $^ $(CLIBS) -o $(EXEC)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $(patsubst %.c, %.o, $<)

$(DEPS): $(SRCWILD) $(HEADWILD)
	@$(CC) $(CFLAGS) -MM $(SRCWILD) > $(DEPS)

ifneq ($(MAKECMDGOALS), clean)
-include $(DEPS)
endif

.PHONY: clean

clean:
	$(RM) $(EXEC) $(wildcard *.o) $(wildcard *.d)

