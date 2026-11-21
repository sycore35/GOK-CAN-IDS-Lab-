/* board_pins.h -- GOK-GW1 pin assignments (STM32G0B1KBT6, LQFP-32).
 *
 * Source of truth: hardware/gok-gw1/pinout.md (KiCad project gok_gw1_can_gateway). Pin -> peripheral mapping was
 * checked against the KiCad symbol's alternate-function entries; the AFx numbers below must still be confirmed
 * against the STM32G0B1 datasheet ("alternate function mapping") before first bring-up.
 * Nothing in the host build depends on these values. */
#ifndef CG_BOARD_PINS_H
#define CG_BOARD_PINS_H

/* Port A: untrusted domain (OBD-II / infotainment) -- FDCAN1 + SN65HVD230 #1 */
#define PIN_CAN_A_RX        PB8      /* pin 32, FDCAN1_RX AF3 */
#define PIN_CAN_A_TX        PB9      /* pin 1,  FDCAN1_TX AF3 */
/* Port B: protected domain (powertrain / brake) -- FDCAN2 + SN65HVD230 #2 */
#define PIN_CAN_B_RX        PB0      /* pin 15, FDCAN2_RX AF3 */
#define PIN_CAN_B_TX        PB1      /* pin 16, FDCAN2_TX AF3 */
/* SN65HVD230 Rs pins: 10k pull-up on board -> transceivers in standby from reset (fail-closed).
 * Firmware drives LOW only after guard_init() = transmitter enabled. */
#define PIN_CAN_A_RS        PA4      /* pin 11 */
#define PIN_CAN_B_RS        PA5      /* pin 12 */
#define CAN_RS_ACTIVE_LEVEL     0
/* ATECC608A on I2C1 (4.7k pull-ups on board), 7-bit address 0x60 */
#define PIN_SE_SCL          PB6      /* pin 30, I2C1_SCL AF6 */
#define PIN_SE_SDA          PB7      /* pin 31, I2C1_SDA AF6 */
/* Stack header to GOK-TN1: I2C2 slave (TN1 is master, pull-ups on TN1) + USART2 event line */
#define PIN_STACK_SDA       PA6      /* pin 13, I2C2_SDA AF6, stack pin 5 */
#define PIN_STACK_SCL       PA7      /* pin 14, I2C2_SCL AF6, stack pin 6 */
#define PIN_EVT_TX          PA2      /* pin 9,  USART2_TX AF1 -> TN1 (stack pin 4, net "UART_RX" from TN1's view) */
#define PIN_EVT_RX          PA3      /* pin 10, USART2_RX AF1 <- TN1 (stack pin 3) */
#define PIN_GUARD_ALERT     PB2      /* pin 17, active high, 100k pull-down on TN1 */
/* Inputs */
#define PIN_WORKSHOP_KEY    PA0      /* pin 7, key closed to GND = diagnostics allowed */
#define PIN_TAMPER          PA1      /* pin 8, lid closed = switch pressed = LOW; HIGH = tamper */
#define WORKSHOP_ACTIVE_LEVEL   0
#define TAMPER_ACTIVE_LEVEL     1
/* LEDs (push-pull, active high, 1k series). PWR LED is hard-wired to 3V3. */
#define PIN_LED_PASS        PB3      /* pin 27, green */
#define PIN_LED_BLOCK       PB4      /* pin 28, red */
#define PIN_LED_DIAG        PB5      /* pin 29, yellow */
/* TPS3823 watchdog input (tWD ~1.6 s); RESET drives NRST */
#define PIN_WDI             PA8      /* pin 18 */

/* Bus parameters. No crystal on the board: FDCAN kernel clock from PLL (HSI16-based); verify error counters
 * on a real bus and add an HSE crystal if bit timing tolerance is exceeded. */
#define CG_CAN_BITRATE      500000u  /* classic CAN, 87.5 % sample point; must match both buses */
#define CG_CPU_HZ           64000000u

#endif
