# GÖK-GW1 — STM32G0B1KBT6 (LQFP-32) pin tablosu

Kaynak: `gok-gw1/gok_gw1_can_gateway.json` (KiCad sembolü `MCU_ST_STM32G0:STM32G0B1KBTx`). Hangi pinin hangi
çevre birimini desteklediği KiCad sembolünün `alternate` kayıtlarından doğrulandı (FDCAN1: PB8 RX / PB9 TX;
FDCAN2: PB0 RX / PB1 TX; I2C1: PB6 SCL / PB7 SDA; I2C2: PA7 SCL / PA6 SDA; USART2: PA2 TX / PA3 RX).
**AF numaraları** (AFx sütunu) hafızaya dayanır; firmware yazılırken STM32G0B1 datasheet'indeki
"Port A/B alternate function mapping" tablosuyla bir kez daha teyit edin. Bu çalışmada kart üretilmedi,
pinler donanımda denenmedi.

Pin seçimi: LQFP-32 paketinde PB12/PB13 yoktur. FDCAN1 için SYSCFG yeniden eşlemesi gerektirmeyen PB8/PB9
(pin 32/1), FDCAN2 için PB0/PB1 (pin 15/16) kullanıldı (alternatif: PB5/PB6). Stack I2C'si PA9/PA10 yeniden
eşlemesi yerine PA6/PA7'deki I2C2'ye bağlandı.

| LQFP32 pin | MCU pini | Net | Fonksiyon / AF | Not |
|---|---|---|---|---|
| 1 | PB9 | CAN_A_TX | FDCAN1_TX (AF3) | Port A (güvenilmez) SN65HVD230 D |
| 2 | PC14 | — | kullanılmıyor | NC |
| 3 | PC15 | — | kullanılmıyor | NC |
| 4 | VDD/VDDA | 3V3 | güç | 100 nF + 4.7 µF; giriş 10 µF |
| 5 | VSS/VSSA | GND | güç | |
| 6 | PF2 / NRST | NRST | reset | 10k pull-up + 100 nF; TPS3823 RESET, SWD NRST |
| 7 | PA0 | MAINT_SW | GPIO giriş (EXTI0) | Atölye anahtarı: kapalı (GND) = atölye modu; 1k + 100 nF + 10k pull-up |
| 8 | PA1 | TAMPER_SW | GPIO giriş (EXTI1) | Tamper: kapak kapalı = basılı = LOW; HIGH = tamper; 10k pull-up + 100 nF |
| 9 | PA2 | UART_RX (net adı TN1 bakışıyla) | USART2_TX (AF1) | GW1 → TN1; stack pin 4 |
| 10 | PA3 | UART_TX | USART2_RX (AF1) | TN1 → GW1; stack pin 3 |
| 11 | PA4 | CAN_A_RS | GPIO çıkış | Port A SN65HVD230 Rs; 10k pull-up (reset'te sürücü kapalı); firmware LOW çeker = açık |
| 12 | PA5 | CAN_B_RS | GPIO çıkış | Port B Rs; aynı mantık |
| 13 | PA6 | I2C_SDA | I2C2_SDA (AF6) | Stack pin 5; TN1 master, GW1 slave; pull-up TN1'de |
| 14 | PA7 | I2C_SCL | I2C2_SCL (AF6) | Stack pin 6 |
| 15 | PB0 | CAN_B_RX | FDCAN2_RX (AF3) | Port B (korunan) R |
| 16 | PB1 | CAN_B_TX | FDCAN2_TX (AF3) | Port B D |
| 17 | PB2 | GUARD_ALERT | GPIO çıkış | Stack pin 7 → TN1 (aktif yüksek, TN1'de 100k pull-down) |
| 18 | PA8 | WDI | GPIO çıkış | TPS3823 watchdog besleme (≈1.6 s) |
| 19 | (PA9) | — | bu pakette bağlı değil | NC |
| 20 | PC6 | — | kullanılmıyor | NC |
| 21 | (PA10) | — | bu pakette bağlı değil | NC |
| 22 | PA9/PA11 | — | kullanılmıyor | NC (PA11 = FDCAN1_RX alternatifi) |
| 23 | PA10/PA12 | — | kullanılmıyor | NC (PA12 = FDCAN1_TX alternatifi) |
| 24 | PA13 | SWDIO | SYS_SWDIO | SWD başlığı |
| 25 | PA14/BOOT0 | SWCLK | SYS_SWCLK; BOOT0 | 10k pull-down; BOOT0 jumper'ı 3V3'e bağlar |
| 26 | PA15 | — | kullanılmıyor | NC |
| 27 | PB3 | LED_PASS | GPIO çıkış | Yeşil, 1k |
| 28 | PB4 | LED_BLOCK | GPIO çıkış | Kırmızı, 1k |
| 29 | PB5 | LED_DIAG | GPIO çıkış | Sarı, 1k (yedek: FDCAN2_RX alternatifi) |
| 30 | PB6 | SE_SCL | I2C1_SCL (AF6) | ATECC608A, 4.7k pull-up |
| 31 | PB7 | SE_SDA | I2C1_SDA (AF6) | ATECC608A, 4.7k pull-up |
| 32 | PB8 | CAN_A_RX | FDCAN1_RX (AF3) | Port A R |

PWR LED'i yazılımdan bağımsız, 3V3'e 1k ile bağlıdır.

## Notlar ve riskler

- **Saat:** kartta harici kristal yoktur (LQFP-32'de OSC_IN/OUT pinleri LSE ile paylaşılıyor, kullanılmadı).
  FDCAN çekirdek saati HSI48/PLL'den alınmalıdır; dahili RC'nin doğruluğu 500 kbit/s klasik CAN için sınırdadır
  (düğümler arası ≈ %1.5 tolerans). Gerçek bus'ta hata sayacı izlenmeli, gerekirse kristal eklenmelidir.
- SN65HVD230 klasik CAN (≤ 1 Mbit/s) içindir; CAN FD veri fazı hızlarını desteklemez. FDCAN'ın FD özelliği
  kullanılamaz.
- UART net adları (UART_TX/UART_RX) stack başlığında GÖK-TN1 bakış açısıyladır; GW1 tarafında yön tersidir (yukarıdaki tablo).
