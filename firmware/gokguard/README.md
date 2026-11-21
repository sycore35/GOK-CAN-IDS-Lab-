# GÖK-Guard firmware (GÖK-GW1)

GÖK CAN-IDS Lab'deki Python kurallarının sahadaki **donanım karşılığı**: iki CAN domaini arasına seri bağlanan, ihlali yalnızca
tespit etmeyen **engelleyen** bir güvenlik duvarı (bump-in-the-wire). Hedef: STM32G0B1KBT6/KET6 (Cortex-M0+, 64 MHz,
144 KB RAM, 128 KB flash, 2x FDCAN). Burada yalnızca host'ta (`cc`, C99) derlenir ve test edilir; kart tarafı `board.h` HAL
arayüzünün arkasındadır. `malloc` yoktur, tüm tamponlar sabit boyutludur.

```
 OBD-II / infotainment ──CAN A──► FDCAN1 ─┐                              ┌─ FDCAN2 ──CAN B──► Motor / Fren / Direksiyon
   (güvenilmez domain)                    ▼                              │   (korunan domain)
                          can_read → guard_process → policy_evaluate ──► FORWARD ─► can_write(B)
                                          │                  └─► DROP (sessiz; CAN'de "ret cevabı" yoktur)
                                          └─► olay halkası ─► JSON satırı + HMAC ─► evt_write ─► GÖK-TN1 / GÖK CAN-IDS Lab
 B → A: her zaman iletilir (korunan domain konuşur), tamper kilidinde de.
```

Dosyalar: `can_frame.h` (klasik CAN çerçevesi), `policy.*` (saf fonksiyon: çerçeve+yön+zaman+bağlam → karar),
`guard.*` (A↔B durum makinesi, istatistik, olay halkası, JSON), `secure_element.h` (ATECC608A soyutlaması; host'ta `se_host.c`
yazılım HMAC-SHA256 **sahtesi**, sabit test anahtarlı), `board.h` / `board_pins.h` / `hal_host.c` / `hal_stm32g0b1.c` (HAL),
`policy_generated.h` (**üretilmiş**, `tools/policy_compiler.py`), `main.c` (hedef girişi), `tests/` (`test_main.c`,
`vectors.json`, `vectors_generated.h`). Python aynası: `src/gateway_model.py`.

## Karar akışı (sıra önemlidir; Python aynası aynı sıradadır)

B→A: **İLET** (kural yok). A→B için:

1. yön değeri bozuk → **GW-01** (fail-closed) · 2. kilit (tamper mandalı ya da açılış öz-denetimi başarısız) → **GW-09**
3. DLC > 8 → **GW-02** · 4. toplam A→B token bucket boş → **GW-08**
5. UDS istek kimliği (0x7DF, 0x7E0-0x7E7, 0x6F1): atölye anahtarı kapalıysa → tehlikeli servis ise **GW-07**, değilse **GW-06**;
   anahtar kapalıysa → **İLET** (ISO-TP ilk/tek çerçevede servis baytı okunur; ardışık çerçeve servis taşımaz → GW-06)
6. DBC'de olmayan / 29-bit kimlik → **GW-01** · 7. DLC DBC'den farklı → **GW-02**
8. 0x200: CRC-8 yanlış → **GW-05**; sayaç önceki+1 değil (ilk çerçeve hariç) → **GW-05** (sayaç durumu her CRC-geçerli çerçevede güncellenir)
9. sinyal ham aralığı dışında → **GW-04** · 10. güvenlik kritik kimlik (0x0C4, 0x200, 0x180) → **GW-10**
11. A→B için izinli olmayan kimlik (0x244, 0x2A0: yalnız B'de üretilir) → **GW-01**
12. kimlik başına token bucket boş → **GW-03** · aksi halde **İLET**

İçerik kuralları (GW-02/05/04) kritik-kimlik kuralından (GW-10) **önce** gelir: böylece olay kaydı çerçevenin *neden* kötü olduğunu
söyler (ör. bozuk CRC'li fren çerçevesi GW-05, kusursuz sahte fren çerçevesi GW-10). Sonuç aynıdır: A'dan kritik kimlik geçmez.

## Kural tablosu

| ID | Kural | Not |
|----|-------|-----|
| GW-01 | A→B: DBC'de olmayan kimlik, 29-bit, ya da bu yönde izinli olmayan kimlik | izinli A→B kimlikleri `config.yaml: gateway.a_to_b_ids` (varsayılan 0x320, 0x3C0) |
| GW-02 | DLC, DBC'deki DLC ile uyuşmuyor (ya da > 8) | |
| GW-03 | Kimlik başına hız sınırı | izinli hız = `per_id_rate_multiplier` x (1000 / cycle_time_ms) çerçeve/sn, derinlik `per_id_burst` |
| GW-04 | Sinyal fiziksel aralık dışı | DBC min/max, ölçek/ofsetle ham değere derlenir, **içe doğru yuvarlanır** |
| GW-05 | 0x200 sayaç + CRC-8 SAE J1850 hatası | poly 0x1D, init 0xFF, xorout 0xFF; `src/dbc_decoder.py` ile birebir |
| GW-06 | UDS istek kimliği, atölye anahtarı yok | |
| GW-07 | Tehlikeli UDS servisi (0x27, 0x2E, 0x31, 0x34/0x36/0x37, 0x11), atölye anahtarı yok | GW-06'dan önce raporlanır |
| GW-08 | Toplam A→B sel sınırı (kimlik 0x000 dahil) | `total_rate_fps` = 200, derinlik 40 |
| GW-09 | Tamper kilidi: yalnız B→A geçer | mandallı; açılışta bozuk tablo da aynı sonucu verir |
| GW-10 | Güvenlik kritik kimlikler A'dan asla geçmez | atölye anahtarı bunları **açmaz** |

Token bucket tamsayıdır (mikro-çerçeve, 1 s ile sınırlı geçen süre, uint32 mikrosaniye taşmasına dayanıklı): C ve Python **bit-bit
aynı** sonucu verir. Politika tabloları `tools/policy_compiler.py` ile `config/can_signals.json` + `config/config.yaml`'ın
`gateway:` bölümünden üretilir (`--check` bayat başlığı yakalar).

## Fail-closed gerekçesi

Bir güvenlik duvarının hata hali, açık kalmak değil **kapalı kalmaktır**; aksi halde saldırgan önce cihazı çökertir, sonra geçer:

- Güçsüz/yeniden başlayan kart: araya röle/bypass **yok**; MCU çalışmazken iki bus fiziksel olarak ayrıdır, korunan domain kendi
  içinde konuşmaya devam eder (kendi ECU'ları arasındaki trafik karttan geçmez). Transceiver Rs (standby) pinleri reset'ten itibaren
  yüksektir; ancak `guard_init` politika öz-denetimi geçince bırakılır.
- Bozuk politika tablosu (`policy_selfcheck`: sıralama, DLC içine sığma, sayaçlar) → kilit modu (GW-09), `guard_clear_lockdown` reddeder.
- Bozuk yön değeri, DLC > 8, bilinmeyen kimlik → DROP.
- TPS3823 donanım watchdog'u + IWDG: ana döngü takılırsa NRST; reset sonrası kart yeniden silahlanana kadar iki yön de kapalı.
- Atölye anahtarı 20 ms debounce edilir ve **açılışta açık-değil sayılır**; tamper debounce'suz anında mandallanır ve kapak kapanınca kalkmaz.
- Güvenli element yoksa/bozuksa olaylar `"mac":"none"` ile gider (kalite düşer ama engelleme sürer); üretimde kilitli config zorunlu olmalı.

Bedeli: kart arızasında araçtaki OBD/infotainment (A) tarafı B'den kopar, yani tanılama ve eğlence işlevleri kaybolur; güvenlik
fonksiyonları (fren, direksiyon) B içinde çalışmaya devam eder. Bu bilinçli bir öncelik tercihidir.

## Olay biçimi

```
{"t":12.345,"ev":"BLOCK","rule":"GW-04","dir":"A>B","id":"0x3C0","dlc":4,"data":"31750000","seq":7,"mac":"<16 hex>"}
```
`ev`: BLOCK | LOCKDOWN (tamper mandalı, `rule` GW-09, `id` 0x000). `t` saniye (ms basamaklı, kesme), `seq` kayıp tespiti için artar,
`mac` = HMAC-SHA256'nın ilk 8 baytı (`,"mac"`'tan önceki metin üzerinde). Aynı kural için **100 ms'de en fazla bir olay** (sel kaydı
boğmasın; sayaçlar tam, `events_suppressed` bastırılanı sayar). Halka 16 olay (15 kullanılabilir): doluysa **en eski** düşer.
HMAC (ATECC'de onlarca ms) yalnızca ana döngüde, çağrı başına tek olay için çalışır; karar yolunda değildir.

## Bellek ve zamanlama bütçesi (tahmin; kartta ölçülmedi)

**RAM**: `guard_t` = **684 B** (politika durumu 80 B, 16 x 28 B olay halkası, sayaçlar), testte basılır; HAL tarafında FDCAN mesaj
RAM'i (212 kelime/örnek, donanımda) ve ATECC I2C tamponu (~80 B). Yığın < 300 B. Toplam < **1,5 KB / 144 KB**. Heap yok.

**Flash**: host `-Os` nesneleri (arm64): policy ≈ 1,7 KB, guard ≈ 3,2 KB; politika tabloları (`cg_msgs`+`cg_sigs`) 324 B. Çekirdek
**≈ 5-6 KB**; HAL + startup ≈ 3 KB, ATECC608A sürücüsü ≈ 3 KB, FDCAN sürücüsü ≈ 2 KB → toplam **≈ 15 KB / 128 KB**.

**Zaman** (M0+ @ 64 MHz, döngü sayımı): karar yolu = doğrusal kimlik araması (7 giriş) + CRC-8 (7 bayt x 8 adım ≈ 600 döngü, yalnız 0x200)
+ ≤ 4 sinyal aralık denetimi + 2 token bucket (64-bit çarpma `__aeabi_lmul` ≈ 50 döngü) ≈ **1 000-2 000 döngü ≈ 15-30 µs**. 500 kbit/s'de
8 baytlık klasik çerçeve ≈ 260 µs (en kötü bit doldurmayla ≈ 270 µs). Store-and-forward gecikmesi ≈ alma süresi + karar + gönderme ≈
**0,55 ms**; çok yüklü hat (≈ 3 700 çerçeve/sn tek yönde) için işlemci yükü ≈ %3-11. Bunlar hesaptır; sıralama/zamanlama ölçümü kartta yapılmalıdır.

## Test

```
make -C firmware/gokguard test      # -std=c99 -pedantic -Wall -Wextra -Werror, UBSan; main.c sözdizimi kontrolü dahil
make -C firmware/gokguard size      # çekirdek nesne boyutları
.venv/bin/python tools/policy_compiler.py            # policy_generated.h'i yeniden üret   (--check: bayatsa çıkış 1)
.venv/bin/python tools/gen_guard_vectors.py          # tests/vectors.json + vectors_generated.h (--check: bayatsa çıkış 1)
.venv/bin/python -m pytest tests/test_firmware_parity.py -q
```
Kapsam: CRC bilinen vektörleri (0x4B "123456789", Python ile aynı), RFC 4231 HMAC vektörü, **her GW kuralı için pozitif + negatif**,
token bucket yenilenmesi ve 32-bit mikrosaniye taşması, atölye anahtarı debounce/fail-safe, tamper mandalı (tek olay, B→A açık,
temizleme reddi), sel (GW-08 + olay bastırma), bozuk yön/öz-denetim fail-closed, `guard_poll` uçtan uca (iletim, TX dolu, LED), olay JSON'u +
MAC doğrulaması, olay halkası taşması ve **Python parite**: simülatörün 12 saldırısından, normal trafikten ve her GW kuralı için
elle hazırlanmış problardan üretilen 26 senaryo / 1 494 çerçeve Python modeli ile C'de aynı karar ve kural kimliğini vermek zorundadır.

## Bilinen sınırlar

- **B domaininden gelen saldırı görünmez.** Gizli hız taklidi (`speed_spoof_stealth`) gerçek ABS düğümünü susturur: bunun için saldırganın
  korunan bus'ta olması gerekir; trafik karttan geçmez. GÖK-GW1 bunu **engelleyemez**; yalnız bus'ı izleyen IDS + fizik analizi (VBA-02) yakalar.
- **Politikaya uygun görünen A çerçeveleri geçer**: izinli kimlik (0x320 gövde), doğru DLC, aralıkta değer, hız sınırının altında →
  kapı kilidi açma enjeksiyonu (`headlight_can_injection_unlock`) iletilir. Ayırt etmek IDS'in iş birimi (zamanlama/çift kaynak).
  Yalnızca saldırı hızı 2x nominali aşarsa (`rate_hz` > 20) GW-03 devreye girer.
- Atölye anahtarı kapalıyken UDS **içeriği** (ISO-TP birleştirme, oturum durumu) yorumlanmaz; anahtar bir "hepsi ya da hiçbiri" kapısıdır.
  Anahtara fiziksel erişimi olan saldırgan tanılama yapabilir (kritik kimlikler yine geçmez).
- Klasik CAN: CAN FD çerçeveleri FDCAN'da hata çerçevesidir, **iletilmez**. Uzak (remote) çerçeve ve 29-bit kimlik (J1939) bu araç profilinde izinli değildir (GW-01).
- Sayaç kuralı yalnız A'dan gelen akışı görür; sayacı B tarafındaki gerçek ECU ile eşlemez (kritik kimlikler zaten geçmez; kural, içerik raporu için).
- ATECC608A sürücüsü ve gerçek HAL iskelettir; pinler `board_pins.h`'de **TODO** yer tutucudur (`hardware/gok-gw1/pinout.md` ile eşlenecek);
  sayılar tahmindir, kartta ölçülmelidir. Host HMAC anahtarı sabit test anahtarıdır, güvenli değildir.
