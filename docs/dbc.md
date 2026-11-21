# DBC desteği

`src/dbc_decoder.py` içindeki `DBCDecoder`, Vector DBC dosyalarının sadece `BO_` ve `SG_` kısmını okuyan küçük bir regex ayrıştırıcıdır. Ek bağımlılık gerektirmez. `cantools` veya CANoe'nun yerine geçmez, DBC formatının tamamını desteklediği de iddia edilmiyor.

Desteklenenler:

- 11 bit ve 29 bit (bit 31 işaretli) mesaj ID'leri
- Intel (`@1`) ve Motorola (`@0`) bayt sırası, işaretli / işaretsiz sinyaller
- Çarpan / offset, min-max kontrolü (aralık dışı sinyal `in_range: false` olarak işaretlenir)
- Multiplexer göstergeleri (`M`, `m0..m15`) ve `SG_MUL_VAL_`
- `VAL_` değer tabloları (decode çıktısında `enum_desc`)
- DLC sinyali karşılamıyorsa sinyal `valid: false` olur, hata fırlatılmaz
- `CM_` gibi tanınmayan satırlar atlanır
- `validate_dbc_integrity()`: bit taşması ve çakışma kontrolü

Desteklenmeyenler: `BA_DEF_` / `BA_` öznitelikleri (döngü süreleri JSON tarafında tutuluyor), `EV_`, `SIG_GROUP_`.

CRC-8 (SAE J1850, poly 0x1D, init 0xFF, xorout 0xFF) ve 4 bitlik rolling counter sadece `0x200 Brake_Safety_Control` mesajında vardır. Bu, laboratuvardaki sentetik profilin uygulama katmanı koruması; CAN'in kendi 15 bitlik donanım CRC'si değil. Diğer mesajlarda (`0x180`, `0x244`, `0x320`) CRC / counter yoktur ve IDS bu kontrolü sadece `0x200` için yapar.
