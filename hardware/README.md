# GÖK donanımı: GÖK-TN1, GÖK-GW1, GÖK-PI1

Bu klasör GÖK CAN-IDS Lab'in üç kartını içerir. Kartlar KiCad 10 ile tasarlandı, FreeRouting ile yönlendirildi;
her kartın devre tanımı `hardware/<id>/*.json` dosyasındadır, buradaki çıktılar o build'in kopyasıdır. **Kartlar üretilmedi ve elektriksel
olarak prototiplenmedi**: tasarım KiCad ERC/DRC ve otomatik routing düzeyinde doğrulandı (bkz. sınırlamalar).

```
 OBD-II / Infotainment domain ──CAN A──► [GÖK-GW1 Secure CAN Gateway] ──CAN B──► Güç aktarma / fren domain
   (güvenilmez: dongle, telematik)            │ olay kaydı (I2C/UART, 2x5 stack başlığı)
                                              ▼
 OBD-II portu ──CAN (listen-only)──► [GÖK-TN1 OBD Tap Node · ESP32-S3] ──Wi-Fi/WebSocket──► GÖK CAN-IDS Lab
 Raspberry Pi ──SPI──► [GÖK-PI1 MCP2515 HAT] ──CAN──► araç / bench  (SocketCAN: can0)
```

| | GÖK-TN1 OBD Tap Node | GÖK-GW1 Secure CAN Gateway | GÖK-PI1 SocketCAN HAT |
|---|---|---|---|
| Boyut / katman | 84 x 56 mm, 2 katman | 64 x 54 mm, 2 katman | 45 x 43 mm, 2 katman |
| Bileşen / net | 38 / 26 | 48 / 36 | 13 / 15 |
| Routing | %100 (0 bağlantısız) | %100 (0 bağlantısız) | %100 (0 bağlantısız) |
| ERC | 0 hata, 0 uyarı | 0 hata, 0 uyarı | 0 hata, 0 uyarı |
| DRC | 0 hata, 32 uyarı | 0 hata, 24 uyarı | 0 hata, 7 uyarı |

Dosyalar: `hardware/<id>/` altında devre tanımı (JSON), BOM/CPL CSV, ERC/DRC JSON, `build_status.json`
(build özeti), 3D PNG'ler. Şematik PDF, Gerber ZIP ve `boards.json` UI için `src/ui/hw/` altındadır.
STEP dosyası bilerek kopyalanmadı. Pin tablosu: `gok-gw1/pinout.md`.

## 1. Mimari

**GÖK-TN1** (aracı dinle)
- 12 V OBD girişi (pin 16) → 1 A sigorta → SS34 ters polarite Schottky → SMAJ24A TVS + 10 µF/50 V →
  **R-78B3.3-2.0** DC/DC → 3V3 (22 µF + 100 nF).
- ESP32-S3-WROOM-1 (N8). Dahili TWAI denetleyicisi listen-only modunda çalışır (yazılımla; ACK ve iletim yok).
  SN65HVD230: TXD 10k pull-up (açılışta resesif), Rs pini GPIO'dan (10k pull-down; yüksek = sürücü kapalı).
  Anten kart kenarında, yasak bölgede parça yok. EN/IO0 pull-up + butonlar, programlama başlığı.
- NUP2105L CAN ESD, 120 Ω + jumper (araçta çıkarık).
- OBD kablo klemensi (4'lü, 3.5 mm): CANH, CANL, 12V, GND. J1962 konnektör footprint'i yok; kablo kullanıcı yapar.

**GÖK-GW1** (domainleri ayır, koru)
- STM32G0B1KBT6: FDCAN1 = Port A (güvenilmez), FDCAN2 = Port B (korunan). Her portta SN65HVD230 + NUP2105L + jumper'lı 120 Ω.
- ATECC608A I2C1'de (4.7k pull-up): kimlik, imzalı politika, olay HMAC'i.
- TPS3823-33: WDI'yi PA8 besler (≈1.6 s); RESET → NRST, MR ← GUARD_RST (TN1 GW1'i uzaktan resetleyebilir).
- Atölye anahtarı (harici 2'li klemens, GND'ye kapanır), tamper anahtarı (kart üstü), PWR/PASS/BLOCK/DIAG LED, SWD, BOOT0 jumper'ı.
- Güç: kendi 12 V girişi yoktur; 3V3 stack başlığının 1. ve 10. pininden TN1'den gelir (tezgâhta SWD başlığından).

**GÖK-PI1:** MCP2515 (8 MHz) + SN65HVD230 + jumper'lı 120 Ω; Pi'de `dtoverlay=mcp2515-can0,oscillator=8000000,interrupt=25`.

**Stack başlığı pin sırası (iki kartta aynı, TN1 bakış açısıyla):** 1 3V3, 2 GND, 3 UART_TX, 4 UART_RX, 5 I2C_SDA,
6 I2C_SCL, 7 GUARD_ALERT, 8 GUARD_RST, 9 GND, 10 3V3. İki kartta aynı 2x5 erkek başlık vardır; eşleştirme 1:1 IDC
flat kablo ile yapılır (pin 1 aynı köşede). Üst üste lehimsiz istif mekanik olarak tasarlanmadı. I2C'de TN1 master,
GW1 slave'dir (pull-up'lar TN1'de).

## 2. Güvenlik tasarımı

### Tehdit modeli
| Saldırgan | Yetenek | GÖK-GW1'in cevabı |
|---|---|---|
| OBD dongle / telematik (Port A) | ID enjeksiyonu, sahte hız/fren sinyali, DLC/aralık/sayaç ihlali, flood | GW-01..GW-05, GW-08, GW-10: çerçeve B'ye geçmeden denetlenir; ihlal = DROP + olay. B domaini saldırıyı görmez. |
| Tanı (UDS) kötüye kullanımı | SecurityAccess, flash, ECU reset, DID yazma | GW-06/07: yalnız fiziksel atölye anahtarı kapalıyken geçer; uzaktan açılamaz. |
| Aracı sökmeye çalışan | Kutu açma, flash okuma/değiştirme | Tamper → olay + kilit modu (GW-09: yalnız B→A geçer). Politika imzası ATECC608A'da doğrulanır. |
| Olay kaydını silmeye/sahtelemeye çalışan | Kaydı değiştirmek | Olaylar ATECC608A anahtarıyla HMAC'lenir; anahtar çipten çıkmaz. |
| Firmware'i kilitlemeye çalışan | Çökertme/DoS | TPS3823 NRST'yi çeker; TN1 GUARD_RST ile de resetler. |
| Pasif dinleme (TN1) | Bus'a yazarak iz bırakma | TWAI listen-only: ACK yok, iletim yok; TXD pull-up ile açılışta resesif. |

Kapsam dışı: fiziksel saldırganın flash'ı tamamen yeniden programlaması (RDP/secure boot ayarı yok), yan kanal
saldırıları, A tarafında B'ye elektriksel sızma, ECU'nun kendisinin ele geçirilmesi.

### Fail-safe kararı: **fail-closed**
GW1 hat içindedir. Güç gitmesi, firmware çökmesi veya watchdog reset'i sırasında iki SN65HVD230'un Rs pini
10k ile 3V3'e çekilidir (sürücü kapalı, standby) ve A↔B arasında donanımsal bir köprü/röle **yoktur**: kart ölürse
iki domain birbirinden kopar. Gerekçe: açık kalan bir güvenlik duvarı, saldırgana kartı çökertme yoluyla korumayı
atlatma imkânı verir. Araçta bunun bedeli ağır olabilir: korunan domain gateway üzerinden bilgi alıyorsa (ör.
göstergeler) fonksiyon kaybı yaşanır ve tamamen bağımsız çalışan güvenlik fonksiyonları (fren/direksiyon ECU'ları
kendi domainlerinde haberleşir) etkilenmemelidir. **Bu bir tasarım takasıdır**, sürüş güvenliği için kritik ECU
birbirine yalnız GW1 üzerinden bağlanıyorsa fail-closed kabul edilemez; bu durumda röleli bypass (açık-bırak
modu) eklenmelidir (v2 önerisi). Açık-bırak seçeneği bilinçli olarak yapılmadı.

### Atölye anahtarı
PA0'a bağlı fiziksel anahtar. Kapalı = atölye modu; firmware UDS oturum/flash isteklerine izin verir. Not:
anahtarı okuyan firmware'dir; yani fiziksel bir onaydır ama yazma yolunu fiziksel olarak kesen bir devre değildir.
Donanımla kesmek için transceiver Rs/TXD hattına anahtarlı kapı eklenmelidir.

### Secure element
ATECC608A: ECDSA P-256 ile imzalı politika doğrulaması, olay HMAC'i. I2C1 hattı kart içindedir ve şifrelenmemiştir
(fiziksel erişimli saldırgan dinleyebilir/yeniden oynatabilir; ATECC'in nonce/authorization mekanizmaları firmware'de kullanılmalıdır).

## 3. BOM ve maliyet tahmini

Adet-1 perakende (USD), **teklif değildir**; MPN atanmadı. `fab/*_bom.csv` Value/Footprint ile gruplanır.

| Kart | Ana kalemler | Tahmini parça | PCB + montaj (5 adet, JLCPCB sınıfı) |
|---|---|---|---|
| GÖK-TN1 | ESP32-S3-WROOM-1 (~4.5), R-78B3.3-2.0 (~6), SN65HVD230 (~1.5), NUP2105L (~0.5), SMAJ24A/SS34/sigorta (~1.5), 4'lü klemens + başlıklar (~3), pasifler/LED (~2) | ≈ 18-22 | ≈ 3-5 PCB + THT/SMT montaj |
| GÖK-GW1 | STM32G0B1KBT6 (~3), 2x SN65HVD230 (~3), ATECC608A (~0.8), TPS3823 (~1), 2x NUP2105L (~1), 3 klemens (~3.5), başlıklar/tamper (~2), pasifler/LED (~3) | ≈ 15-19 | ≈ 3-5 PCB + montaj |
| GÖK-PI1 | MCP2515 (~2), SN65HVD230 (~1.5), kristal/pasif/başlıklar (~2) | ≈ 6-8 | ≈ 2-3 PCB + montaj |

## 4. Bilinen sınırlamalar

1. **Prototip/üretim yok.** Yalnız ERC/DRC, routing ve KiCad render'ı. Fab öncesi MPN ataması, datasheet doğrulaması,
   termal/EMC incelemesi gerekir (MPN yok, test noktası yok, fiducial yok).
2. **DRC kuralları fab kapasitesine hizalandı** (KiCad kart ayarları): min delik 0.3 → **0.2 mm** (ESP32-S3-WROOM-1
   termal-pad via'ları 0.2 mm), bakır-kenar boşluğu 0.5 → **0.3 mm** (JLCPCB minimumu, FreeRouting kenardan yalnız
   0.2 mm bilir). Varsayılan KiCad kurallarıyla ESP32'li TN1'de DRC hata verir. GÖK-GW1 ve GÖK-PI1 ESP32 içermez.
   DRC uyarıları elektriksel değildir: silk çakışma/kenar (TN1 7, GW1 8), footprint-sembol adı farkı (2),
   `net_conflict` (NC bayraklı kullanılmayan pinler; TN1 23, GW1 14, PI1 7).
3. **12 V sınıfı güç:** SMAJ24A 24 V sıçrama için seçildi (standoff 24 V) fakat ~39 V'a kenetler; R-78B3.3-2.0'ın mutlak
   sınırı 32 V'tur. ISO 7637/16750 load dump (yüzlerce ms, 80-100 V yayılı) için tam koruma değildir; giriş LC filtresi ve
   güçlü TVS (SMDJ serisi) eklenmelidir. R-78E3.3-0.5 yerine R-78B seçildi (28 V sınırı yetersiz, ESP32 Wi-Fi tepe akımı 0.5 A'e yakın).
4. **CAN fiziksel katmanı:** ortak mod bobini (CMC) yok; kablo/EMC testi yapılmadı. SN65HVD230 CAN FD'yi desteklemez.
   NUP2105L ESD içindir, ISO 7637 darbe sınıfı yoktur. Transceiver standby'daki alıcı davranışı datasheet'ten teyit edilmedi.
5. **GW1 saati:** harici kristal yok; dahili HSI48/PLL ile 500 kbit/s sınırda (bkz. `gok-gw1/pinout.md`).
6. **AF numaraları** pinout.md'de hafızadan yazıldı; pin–çevre birimi eşlemesi KiCad kütüphanesinden doğrulandı, AF numaraları datasheet ile teyit edilmelidir.
7. **Güç bağımlılığı:** GW1 3V3'ü TN1'den alır; hat içi araç kurulumunda TN1 olmadan GW1 çalışmaz (bench: SWD'den). Ayrı bir GW1 beslemesi gerekebilir.
8. TN1'in listen-only hâli yazılımladır; donanımsal garanti için Rs'nin yüksek çekilmesi (sürücü kapalı) önerilir (GPIO6 ile).
9. Atölye anahtarı ve tamper firmware tarafından okunur; donanımla yazma yolunu kesmez (bkz. §2). Harici anahtar terminalinde ek TVS yoktur.
10. Analog değerler (pull-up, LED akımı, şönt) elle hesaplandı; SPICE ile simüle edilmedi.
11. Yalnız 2 montaj deliği (üst köşeler); alt kenarda terminal blokları delik yerini kullanır, muhafaza ek destek gerektirebilir.
12. OBD-II (J1962) konnektörü ve kablosu kartta yoktur; kablo klemense bağlanır.
