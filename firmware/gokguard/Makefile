# GOK-Guard firmware host build. Only `cc` + C99, no libraries.
#   make test    strict build (-Wall -Wextra -Werror -std=c99 -pedantic) + run all tests (UBSan)
#   make check   syntax-only check of the target entry point (main.c)
#   make size    object sizes of the core (-Os) as a rough flash indication
CC      ?= cc
STRICT  := -std=c99 -pedantic -Wall -Wextra -Werror
CORE    := policy.c guard.c se_host.c hal_host.c
BUILD   := build

.PHONY: test check size clean
test: check $(BUILD)/test_gokguard
	./$(BUILD)/test_gokguard

$(BUILD)/test_gokguard: $(CORE) tests/test_main.c $(wildcard *.h) tests/vectors_generated.h
	@mkdir -p $(BUILD)
	$(CC) $(STRICT) -O1 -g -fsanitize=undefined -fno-sanitize-recover=undefined -I. -o $@ $(CORE) tests/test_main.c

check:
	$(CC) $(STRICT) -fsyntax-only -I. main.c

size:
	@mkdir -p $(BUILD)/obj
	@for f in policy guard; do $(CC) $(STRICT) -Os -c -I. $$f.c -o $(BUILD)/obj/$$f.o; done
	@size $(BUILD)/obj/*.o

clean:
	rm -rf $(BUILD)
