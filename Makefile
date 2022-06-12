TARGET := adbg-test
CWARNS := -Wall
CFLAGS := -std=gnu99

all: $(TARGET)

$(TARGET): main.c adbg.c adbg.h
	@$(CC) $(CFLAGS) $(CWARNS) -o $@ main.c adbg.c
	@echo [$(CC)] $(CFLAGS) $@

clean:
	@echo [rm] $(TARGET)
	@rm -rf $(TARGET) 2> /dev/null || true

.PHONY: clean
