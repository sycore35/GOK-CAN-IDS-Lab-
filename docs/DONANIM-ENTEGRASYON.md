# GÖK Donanımı: Nerede, Ne Durumda, Nasıl Kullanılır

Bu belge üç kartın (GÖK-TN1, GÖK-GW1, GÖK-PI1) dosyalarının yerini, bugünkü olgunluk seviyesini, araca/tezgâha
nasıl bağlanacağını ve GÖK CAN-IDS Lab yazılımıyla nasıl birleştiğini anlatır. Aynı kılavuzun görsel hali panelde
**Donanım → "Nasıl kullanılır?"** bölümündedir.

Teknik ayrıntı: [hardware/README.md](../hardware/README.md) · pin tablosu: [hardware/gok-gw1/pinout.md](../hardware/gok-gw1/pinout.md) ·
firmware: [firmware/gokguard/README.md](../firmware/gokguard/README.md)

> **Güvenlik:** Bu kartlar yalnız kendi aracında ya da masadaki test tezgâhında denenmek içindir. Araç hareket
> halindeyken hiçbir deneme yapma. Fren, direksiyon ve motor hattına müdahale ciddi kazaya yol açabilir.

## 1. Kısaca: hangi kart ne işe yarar?

| Kart | Görev | Beyni | Benzetme |
|---|---|---|---|
| **GÖK-TN1 OBD Tap Node** | OBD-II portundaki CAN trafiğini **yalnız dinler** (listen-only), Wi-Fi ile panele yollar | ESP32-S3 (dahili TWAI) | "Kulak": duyar ama konuşmaz, aracı bozamaz |
| **GÖK-GW1 Secure CAN Gateway** | Güvenilmez A domaini (OBD, bilgi-eğlence) ile korunan B domaini (motor, fren, direksiyon) arasına girer; kural dışı kareyi **fiziksel hatta durdurur** | STM32G0B1 (2x FDCAN) + ATECC608A | "Sınır kapısı görevlisi" |
| **GÖK-PI1 SocketCAN HAT** | Raspberry Pi'ye gerçek CAN arayüzü (`can0`) kazandırır; bu repodaki SocketCAN köprüsü simülatör karelerini o hatta yazar, hattan gelenleri IDS'e verir | MCP2515 + SN65HVD230 | "Kulaklık adaptörü" |

### Araçta nereye takılır?

Kartlar aracın "beyni" (ECU) değildir; ECU'ların arasındaki hatta otururlar. Panelde **3B Araç** sekmesindeki
röntgen modu bu yerleri araç üzerinde işaretler.

| Kart | Yer | Neden orası |
|---|---|---|
| GÖK-TN1 | Sürücü tarafı, gösterge panelinin altındaki **OBD-II portu** (diz hizası), 4 telli kablonun ucunda küçük kutu | OBD-II portu standart gereği sürücü koltuğuna yakındır ve ortak CAN hattına açılır |
| GÖK-GW1 | **Ön konsol / torpido arkası**, aracın mevcut merkezi ağ geçidinin yanında; A (OBD, bilgi-eğlence) ve B (motor, fren, direksiyon) kablo demetlerinin ayrıldığı nokta | İki domain arasındaki tek geçide hat içi girmesi gerekir; başka bir yerde olursa kartın etrafından dolaşılır |
| GÖK-PI1 | **Araçta değil**: masadaki test tezgâhı, Raspberry Pi'nin 40 pinli başlığı | Simülatörü gerçek CAN hattına bağlamak için |

Yerler araç modeline göre değişir; merkezi ağ geçidinin yeri için aracın servis şemasına bak.

IDS (bu panel) bütün bus'ı görür ama durduramaz. GW1 durdurur ama yalnız iki domain arasındaki trafiği görür.
Örnek: gerçek ABS'i susturup yavaşça kayan sahte hız basan saldırgan B domaininin içindedir. Kareleri GW1'den hiç
geçmez, onu yalnız IDS'in fizik tabanlı davranış analizi (VBA-02) yakalar. Kapsam sekmesi bunu ölçerek gösterir:
IDS 12/12 saldırıyı yakalar, GW1 10/12'sini sahada durdururdu.

## 2. Dosyalar nerede?

| Ne | Yer |
|---|---|
| Devre tanımları (KiCad projesini üreten JSON) | `hardware/gok-*/*.json` |
| Gerber ZIP, şematik PDF | `src/ui/hw/gok-*_gerbers.zip`, `src/ui/hw/gok-*_schematic.pdf` |
| BOM + dizgi (CPL) | `hardware/gok-*/*_bom.csv`, `*_cpl.csv` |
| 3D görüntüler, ERC/DRC raporları | `hardware/gok-*/3d_*.png`, `erc.json`, `drc.json` |
| Firmware (GW1) | `firmware/gokguard/` |
| Panelde görmek | **Donanım** sekmesi (görseller, PDF/Gerber, BOM, konnektörler, kılavuz) |

KiCad projeleri (`.kicad_pro/.kicad_sch/.kicad_pcb`) bu depoda tutulmuyor; ayrı elektronik tasarım
çalışma alanımda bu JSON tanımlarından KiCad 10 + FreeRouting ile üretiliyor ve çıktılar buraya kopyalanıyor.

## 3. Bugün ne durumda?

| Parça | Durum |
|---|---|
| Şematik + PCB (3 kart) | ✅ %100 routing, 0 ERC / 0 DRC hata (DRC'de min. delik 0.2 mm ve bakır-kenar 0.3 mm'ye gevşetildi) |
| Prototip | ❌ Üretilmedi, hiç test edilmedi |
| GW1 firmware çekirdeği (politika, karar, olay kaydı, HMAC) | ✅ C99, bilgisayarda 24 test / 2240 kontrol; Python modeliyle 1494 çerçevede birebir aynı karar |
| GW1 donanım katmanı (FDCAN, ATECC608A sürücüsü) | ⚠️ İskelet; pinler `board_pins.h`'de gerçek pinout'a göre dolduruldu, sürücü kodu yazılmadı |
| TN1 firmware (ESP32-S3) | ❌ Yazılmadı |
| Panel ↔ kart bağlantısı | ⚠️ Panel tarafı hazır: `POST /api/guard/events` gerçek karttan gelen olay satırlarını kabul eder ve "donanım" etiketiyle gösterir. Kart tarafı (TN1'in Wi-Fi ile yollaması) yok. Paneldeki GW1 bugün Python modelidir |

## 4. Nasıl bağlanır? (iki kurulum)

### Kurulum A: Yalnız izleme (TN1)
```
OBD-II portu ──4 telli kablo (CANH, CANL, +12V, GND)──► GÖK-TN1 ──Wi-Fi──► GÖK CAN-IDS Lab paneli
```
Hiçbir şey engellenmez, hiçbir şey bozulmaz. Başlangıç için önerilen yol budur.

| OBD-II (J1962) | Sinyal | TN1 `J1` klemens |
|---|---|---|
| pin 6 | CAN H | 1 CANH |
| pin 14 | CAN L | 2 CANL |
| pin 16 | +12 V sürekli | 3 12V |
| pin 4 / 5 | şasi / sinyal GND | 4 GND |

- Kartta J1962 soketi yok; OBD-II'den çıkan 4 telli kablo `J1`'e girer. **Önce GND'yi bağla.**
- `J4` sonlandırma jumper'ını **takma**: araçta hattın iki ucunda 120 Ω zaten var.

### Kurulum B: Domainler arası koruma (TN1 + GW1)
```
A domaini (OBD / bilgi-eğlence) ──► GW1 J5 Port A ║ J7 Port B ──► B domaini (motor, fren, direksiyon)
                                         ▲ 2x5 flat kablo (3V3, UART, I2C, ALERT, RST) ▲
                                       GÖK-TN1 (12 V besleme, olayları Wi-Fi ile panele iletir)
```
- A ile B arasındaki mevcut bağlantı GW1'in iki portuna ayrılır. **A ile B arasında GW1'den başka bağlantı kalmamalı**,
  yoksa saldırgan kartın etrafından dolaşır.
- TN1 `J3` ↔ GW1 `J1`: 1:1 IDC flat kablo, pin 1 iki kartta da aynı köşede. GW1'in kendi güç girişi yoktur, 3V3'ü buradan alır.
- Önce **tezgâhta** dene (iki CAN düğümü + 12 V kaynak), araca ilk denemeyi yapma.

**2x5 istifleme başlığı** (iki kartta aynı, adlar TN1'in bakış açısıyla):
1 3V3 · 2 GND · 3 UART_TX · 4 UART_RX · 5 I2C_SDA · 6 I2C_SCL · 7 GUARD_ALERT · 8 GUARD_RST · 9 GND · 10 3V3

| GW1 konnektörü | Ne bağlanır |
|---|---|
| `J5` Port A (CAN_A_H, CAN_A_L, GND) | Güvenilmez taraf: OBD-II / bilgi-eğlence hattı |
| `J7` Port B (CAN_B_H, CAN_B_L, GND) | Korunan taraf: motor, fren, direksiyon ECU'ları |
| `J6` / `J8` | Port A / Port B 120 Ω sonlandırma: yalnız GW1 o hattın **fiziksel ucundaysa** tak |
| `J4` atölye anahtarı (MAINT_IN, GND) | Anahtarlı switch. Kapalı (GND) = atölye modu: UDS oturumu ve yazılım yükleme B'ye geçebilir (GW-06/07). Servis bitince aç |
| `S1` tamper | Kutu kapağı basılı tutmalı. Kapak açılırsa kilit modu (GW-09): yalnız B→A akar |
| `J2` SWD, `J3` BOOT0 | ST-LINK ile yazılım yükleme; BOOT0 normalde çıkarık |

**Sonlandırma kontrolü:** güçsüz hatta CANH-CANL arası ≈ 60 Ω ölçülmeli (iki uçta 120 Ω).

**Fail-closed uyarısı:** GW1'in güç gittiğinde ya da yazılımı kilitlendiğinde iki transceiver da kapanır (Rs pull-up).
Bu durumda B domaini A'dan kopar; bypass rölesi yok. Gerekçe ve takas: [hardware/README.md](../hardware/README.md) §2.

### Kurulum C: Masada gerçek CAN ile panel (GÖK-PI1 + Raspberry Pi)
1. HAT'i Pi'nin 40 pinli başlığına tak, `/boot/firmware/config.txt`'ye ekle:
   `dtoverlay=mcp2515-can0,oscillator=8000000,interrupt=25` ve `dtparam=spi=on`, yeniden başlat.
2. `sudo ip link set can0 up type can bitrate 500000`, kontrol: `candump can0`.
3. Paneli Pi üzerinde çalıştır: `pip install python-can`, `config/config.yaml` → `can.interface_name: "can0"`
   (ya da `CAN_LAB_SOCKETCAN=can0` ortam değişkeni), sunucuyu yeniden başlat, "SocketCAN · CAN FD · UDS" sekmesinden bağlan.
4. `JP1` jumper'ı: PI1 hattın ucundaysa tak.

Köprü iki yönlüdür: simülatörün ürettiği kareler gerçek hatta da akar (TX), hattan gelen kareler ise
`SOCKETCAN:can0` kaynağıyla sanal bus'a girer ve IDS, davranış analizi ve gateway modeli onları diğer kareler gibi
inceler (RX; "SocketCAN · CAN FD · UDS" sekmesinden kapatılabilir). Hattan gelen kare geri yansıtılmaz. Köprü gerçek
donanımda denenmedi; testlerde sahte bir python-can arayüzüyle doğrulandı.

## 5. İlk enerji (bring-up)

1. Gözle kontrol: lehim köprüsü, ters konnektör, gevşek klemens.
2. Akım sınırlı güç kaynağı: 12 V, sınır 100 mA → TN1 `J1`. 3V3 rayını ölç (3.25-3.35 V). Kısa devre yoksa sınırı 500 mA'e çıkar.
3. TN1: BOOT (`S2`) basılıyken EN (`S1`) → USB-UART (3.3 V) ile `J2`'den yazılım yükle. PWR LED yanmalı, CAN LED trafikle yanıp söner.
4. GW1: flat kabloyla TN1'e bağla, PWR yanmalı. ST-LINK → `J2`. LED'ler: **PASS** kare geçirildi, **BLOCK** kare engellendi, **DIAG** atölye modu.
5. Güvenlik testi: bir USB-CAN adaptörüyle Port A'dan simülatördeki saldırıların karelerini gönder (ör. 0x200 sahte fren, 0x7E0 UDS 0x34).
   BLOCK yanmalı, Port B'ye kare geçmemeli. Aynı vakalar `firmware/gokguard/tests/` içinde bilgisayarda zaten doğrulanıyor.

## 6. Yazılımla entegrasyon

1. **Politika: bugün çalışıyor.** `config/can_signals.json` (DBC: ID, DLC, periyot, sinyal aralıkları) ve `config/config.yaml`
   `gateway:` bölümü → `python tools/policy_compiler.py` → `firmware/gokguard/policy_generated.h`. Python modeli de aynı tablodan
   beslenir. `tools/gen_guard_vectors.py` iki tarafın aynı kararı verdiğini 1494 çerçevede doğrular.
2. **GW1 olayları → panel:** GW1 her engellemede tek satır JSON üretir:
   `{"t":12.345,"ev":"BLOCK","rule":"GW-04","dir":"A>B","id":"0x244","dlc":8,"data":"..."}`. TN1 bunu UART/I2C'den okuyup
   `POST /api/guard/events`'e yollar (tek nesne ya da liste). Panel: Donanım → "GÖK-GW1 canlı durum" ve Araç Ağı sekmesi.
   Yapılacak: TN1 firmware'i.
3. **TN1 frame'leri → IDS:** planlanan yol, TN1'in kareleri WebSocket ile yollaması ya da Linux'ta `slcan`/SocketCAN üzerinden
   `can0` olarak görünmesidir. Bugün çalışan yol: Linux'ta `can0`/`vcan0`'dan
   okunan kareler SocketCAN köprüsüyle IDS'e girer (Kurulum C). TN1'in Wi-Fi yolu yazılmadı.

## 7. Yol haritası

1. Sipariş öncesi: STM32G0B1 AF numaralarını datasheet'ten doğrula; CAN ortak mod bobini ve test noktaları ekle; MPN/LCSC numaralarını gir;
   GW1'e HSE kristali eklemeyi değerlendir (500 kbit/s için dahili RC sınırda); 12 V girişte tam load-dump koruması (SMAJ24A ≈ 39 V'ta kenetler,
   DC/DC sınırı 32 V).
2. 5'er adet prototip → GW1 HAL + ATECC608A sürücüsü → kartta `make test` vakalarını tekrarla.
3. TN1 firmware (ESP-IDF): TWAI listen-only, Wi-Fi, GW1 olay köprüsü → `POST /api/guard/events`.
4. İsteğe bağlı: bypass rölesi (açık-bırak modu), izoleli transceiver, kutu ve OBD-II soketli kablo.
