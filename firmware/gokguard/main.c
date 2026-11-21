/* main.c -- target firmware entry (STM32G0B1). Not built on the host; `make check` syntax-checks it. */
#include "board.h"
#include "guard.h"
#include "board_pins.h"

static guard_t g_guard;   /* static storage: no heap, no stack pressure */

int main(void) {
    guard_config_t cfg;
    board_init();
    guard_config_default(&cfg);
    guard_init(&g_guard, &cfg);
    for (;;) {
        guard_poll(&g_guard);          /* also kicks the watchdog */
        guard_flush_events(&g_guard);
    }
}
