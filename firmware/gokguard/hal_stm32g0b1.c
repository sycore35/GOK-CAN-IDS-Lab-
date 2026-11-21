/* hal_stm32g0b1.c -- GOK-GW1 HAL skeleton for STM32G0B1KBT6 (Cortex-M0+, 64 MHz, 144 KB RAM, 128 KB flash, 2x FDCAN).
 *
 * NOT compiled on the host (needs the CMSIS device header stm32g0b1xx.h, which is not vendored here). It documents,
 * register by register, what each board.h function has to do. All pin/AF choices come from board_pins.h and are TODO
 * until hardware/gok-gw1/pinout.md exists.
 *
 * Build on target (example): arm-none-eabi-gcc -mcpu=cortex-m0plus -mthumb -Os -std=c99 -Wall -Wextra -Werror
 *   -DSTM32G0B1xx main.c guard.c policy.c hal_stm32g0b1.c se_atecc608.c startup/linker...
 */
#include "board.h"
#include "board_pins.h"
#include "secure_element.h"
/* #include "stm32g0b1xx.h" */

/* ---- clocks -------------------------------------------------------------------------------------
 * RCC->CR: HSION, wait HSIRDY (16 MHz). RCC->PLLCFGR: PLLSRC=HSI16, PLLM=/1, PLLN=x8, PLLR=/2 => 64 MHz.
 * FDCAN kernel clock: RCC->CCIPR2.FDCANSEL = PLLQ or HSE (use a source whose tolerance meets the 0.5 % CAN limit;
 * HSI16 alone (~1 %) is NOT enough for 500 kbit/s over a long bus -> fit an 8 MHz crystal or use PLLQ from HSE).
 * RCC->IOPENR: GPIOAEN|GPIOBEN. RCC->APBENR1: FDCANEN | I2C1EN | I2C2EN | USART2EN.
 */

/* ---- time base ----------------------------------------------------------------------------------
 * millis(): SysTick (LOAD = 64000-1). micros(): TIM2 32-bit free-running, PSC = 63 => 1 MHz, ARR = 0xFFFFFFFF.
 */
static volatile uint32_t g_ms;
void SysTick_Handler(void) { g_ms++; }
uint32_t millis(void) { return g_ms; }
uint32_t micros(void) { return 0; /* TODO: return TIM2->CNT; */ }

/* ---- FDCAN1 (port A) and FDCAN2 (port B) --------------------------------------------------------
 * Both in classic mode (CCCR.FDOE = 0, BRSE = 0): a CAN FD frame is an error frame for the controller and is NEVER
 * forwarded (document in README). Message RAM (SRAMCAN, 212 words per instance on the G0B1): 11-bit filters, RX FIFO0
 * of 16 elements, TX FIFO of 8. Bit timing for 500 kbit/s @ 64 MHz kernel clock (example: NBRP=8, NTSEG1=13, NTSEG2=2,
 * NSJW=2 -> 87.5 %). Global filter: reject nothing in hardware (the policy decides), but ACCEPT-ALL into FIFO0.
 * RX is polled from the main loop (guard_poll), FIFO0 watermark interrupt optional.
 * can_read(): if (FDCAN->RXF0S.F0FL) { read element at GetIndex, copy id/dlc/data, RXF0A = GetIndex; return 1; }
 * can_write(): if (TXFQS.TFQF) return 0; put element at PutIndex, TXBAR = 1u << PutIndex; return 1.
 * Bus-off: on CCCR/PSR.BO set, hold the port silent, restart after 128 x 11 recessive bits (automatic) -- and log it.
 * Fail-closed boot: both transceiver Rs pins HIGH (standby, board pull-ups) from reset until board_init() finishes and guard_init()
 * has run the policy self-check; only then are they released.
 */
int can_read(cg_port_t port, cg_frame_t *f) { (void)port; (void)f; return 0; /* TODO */ }
int can_write(cg_port_t port, const cg_frame_t *f) { (void)port; (void)f; return 0; /* TODO */ }

/* ---- event line: USART2 TX (DMA or ring) to the GOK-TN1 stack header ------------------------------ */
void evt_write(const uint8_t *data, uint16_t len) { (void)data; (void)len; /* TODO: TX ring + TXEIE/DMA */ }

/* ---- GPIO --------------------------------------------------------------------------------------- */
int gpio_read_workshop_key(void) { return 0;   /* TODO: ((GPIOA->IDR >> n) & 1u) == WORKSHOP_ACTIVE_LEVEL */ }
int gpio_read_tamper(void) { return 0;         /* TODO: ((GPIOA->IDR >> n) & 1u) == TAMPER_ACTIVE_LEVEL; open loop = tamper */ }
void led_set(cg_led_t led, int on) { (void)led; (void)on;   /* TODO: GPIOx->BSRR = on ? (1u << pin) : (1u << (pin + 16)) */ }

/* ---- watchdog ----------------------------------------------------------------------------------- */
void wdt_kick(void) {
    /* TODO: toggle PIN_WDI (TPS3823: NRST if no edge within ~1.6 s) and also kick the IWDG (~1 s): two independent
     * supervisors. After a reset both CAN transceivers are silent until the guard re-arms: fail-closed. */
}

void board_init(void) {
    /* clocks -> SysTick -> TIM2 -> GPIO (Rs pins HIGH first) -> FDCAN1/2 -> I2C1/I2C2 -> USART2 -> NVIC. */
}

/* ---- secure element (ATECC608A, I2C1 @ 400 kHz, 7-bit address 0x60 default) ----------------------
 * se_init(): wake pulse, read config zone, verify it is locked (else refuse to arm in production builds).
 * se_hmac_sha256(): SHA command with HMAC_Start/Update/End using a non-readable key slot, CRC-16 on every packet,
 *   ~40 ms worst case: only called from guard_flush_events() in the main loop, never from the decision path.
 */
int se_init(void) { return -1; /* TODO */ }
int se_hmac_sha256(const uint8_t *data, uint16_t len, uint8_t out[32]) { (void)data; (void)len; (void)out; return -1; /* TODO */ }
