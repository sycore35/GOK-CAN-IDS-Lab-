// GÖK CAN-IDS Lab — Araç Ağı (canlı topoloji + "Saldırı oynat") ve Saldırı Atlası.
// app.js'ten sonra yüklenir; $, esc, nf, api, toast, act, ico, ruleTitle, LAYER_TR, CAT_TR, atkName genel değişkenlerini kullanır.
// Backend uçları (guard/*) henüz yoksa hata fırlatmaz; zarif yer tutucu gösterir.
(() => {
  "use strict";
  const SVGNS = "http://www.w3.org/2000/svg";
  const RM = window.matchMedia ? matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };

  /* ---------- sabit veri ---------- */
  const GWL = 428, GWR = 532, GWX = 480, BUS_Y = 250;
  const ECU = {
    cluster: { n: "Gösterge", dom: "A", x: 170, y: 130, ids: ["0x3C0"], role: "Sürücüye hızı ve uyarı lambalarını gösterir.", sim: "Aracın kadranı: başkalarının söylediğini okur, kendi karar vermez.", edge: 156 },
    body: { n: "Gövde", dom: "A", x: 330, y: 130, ids: ["0x320"], role: "Kapı kilidi, sinyal ve dörtlü flaşörü yönetir.", sim: "Kapıcı: kapıları açar-kapatır; yanlış emir gelirse yine uygular.", edge: 156 },
    engine: { n: "Motor", dom: "B", x: 610, y: 130, ids: ["0x180"], role: "Devir, soğutma suyu sıcaklığı ve gaz bilgisini yayınlar.", sim: "Kalp: aracın temposunu belirler.", edge: 156 },
    brake: { n: "Fren / ABS", dom: "B", x: 790, y: 130, ids: ["0x200", "0x244"], role: "Fren basıncı ve tekerlek hızından hesaplanan araç hızını yayınlar.", sim: "Refleks sistemi: tekerleklerin kilitlenmesini önler, hız bilgisinin kaynağıdır.", edge: 156 },
    steer: { n: "Direksiyon", dom: "B", x: 610, y: 370, ids: ["0x0C4"], role: "Direksiyon açısı ve dönüş hızını yayınlar.", sim: "Elin uzantısı: aracın nereye döneceğini söyler.", edge: 344 },
    trans: { n: "Şanzıman", dom: "B", x: 790, y: 370, ids: ["0x2A0"], role: "Seçili ve gerçek vites ile yağ sıcaklığını yayınlar.", sim: "Dişli kutusu: motorun gücünü tekerleğe uygun oranda iletir.", edge: 344 },
  };
  const ID2ECU = { 0x180: "engine", 0x244: "brake", 0x200: "brake", 0xc4: "steer", 0x2a0: "trans", 0x320: "body", 0x3c0: "cluster" };
  const SRC2ECU = { ECU_Engine: "engine", ECU_Brake: "brake", ECU_Steering: "steer", ECU_Transmission: "trans", ECU_Body: "body", ECU_Cluster: "cluster" };
  const ECU_TR = Object.fromEntries(Object.entries(ECU).map(([k, v]) => [k, v.n]));

  /* ---------- Saldırı Atlası verisi (yalnızca bu repodaki simülatör saldırıları) ---------- */
  // gw: GÖK-GW1 kural kimlikleri (firmware/gokguard/README.md); v: block | partial | none
  const ATLAS = {
    speed_spoof: { tgt: "brake", what: "Saldırgan, aracın gerçek hızından çok yüksek “sahte hız” kareleri (0x244) basar; gerçek ABS ile aynı ID’yi taklit eder.",
      effect: "Gösterge yanlış hız okur. Hıza bağlı sistemler (kapı kilidi, direksiyon yardımı) yanlış karar verebilir.",
      detect: "Kinematik sıçrama (K03): hız bir anda yüzlerce km/h zıplar. Zamanlama sapması (K02): kare aralığı bozulur.",
      gw: ["GW-01", "GW-04"], v: "block", gwText: "0x244 yalnızca B domaininde üretilir; A’dan gelen kopya yön kuralıyla (GW-01) düşer, 260 km/h üstü değerler ayrıca GW-04’e takılır.",
      manip: "Sahte hız kareleri (0x244) aracın gerçek hızının çok üstünde yayınlanıyor.", impact: "Gösterge yanlış hız gösteriyor; hıza bağlı sistemler yanıltılabilir." },
    speed_spoof_stealth: { tgt: "brake", what: "Saldırgan gerçek ABS’i susturur, yerine yavaş yavaş kayan sahte hız verir. Periyot doğru, ani sıçrama yok.",
      effect: "Hız göstergesi fark edilmeden, saniyede birkaç km/h kayarak gerçekten uzaklaşır.",
      detect: "Kare katmanları (K01–K07) hiçbir şey görmez; yalnızca fizik tabanlı araç davranışı analizi (VBA) tutarsızlığı yakalar.",
      gw: [], v: "none", gwText: "Gerçek ABS’i susturabilmek için saldırgan korunan B domaininin içinde olmalı. Kareleri GÖK-GW1’in üzerinden geçmez; burada yalnızca IDS’in fizik tabanlı davranış analizi (VBA-02) korur.",
      manip: "Gerçek ABS susturuldu; yavaşça kayan sahte hız kareleri yayınlanıyor.", impact: "Hız bilgisi fark edilmeden gerçeğinden uzaklaşıyor." },
    spoof_id: { tgt: "engine", what: "Seçilen bir CAN ID’sine (varsayılan 0x180, motor) saldırgan yükü yüksek hızda yollanır; gerçek ECU ile yarışılır.",
      effect: "Motor verisi (devir, sıcaklık) sahte değerlerle bozulur; göstergeler ve diğer ECU’lar yanlış bilgi alır.",
      detect: "Zamanlama sapması (K02): normalde 20 ms’de bir gelen kare çok sık gelir. Tekrar penceresi (K06): aynı yük defalarca görülür.",
      gw: ["GW-10", "GW-03"], v: "block", gwText: "0x180 güvenlik kritik kimliktir; A domaininden asla geçmez (GW-10). Geçse bile hız sınırı (GW-03) taşkını keser.",
      manip: "Motor verisinin ID’si taklit edilerek saniyede 50 sahte kare basılıyor.", impact: "Motor devir ve sıcaklık bilgisi bozuluyor." },
    replay: { tgt: "engine", what: "Gerçek motor, fren ve hız kareleri bir süre kaydedilir, sonra olduğu gibi tekrar yollanır. Kareler “gerçek” göründüğü için kolay inandırır.",
      effect: "Araç, geçmişteki bir sürüş anını şimdiki sanır; göstergeler ve karar mekanizmaları yanılır.",
      detect: "Sayaç / CRC (K04): eski rolling counter değeri geri gelir. Tekrar penceresi (K06): birebir aynı dizi tekrar eder.",
      gw: ["GW-10", "GW-01", "GW-05"], v: "block", gwText: "Kaydedilen kimlikler (0x180, 0x200, 0x244) A’dan geçemez; ayrıca fren sayacı/CRC (GW-05) tekrar edilen kareyi eler.",
      manip: "Kaydedilmiş gerçek kareler birebir tekrar yayınlanıyor.", impact: "ECU’lar geçmişteki sürüş anını şimdiki sanıyor." },
    flooding: { tgt: null, what: "En yüksek öncelikli ID olan 0x000 ile bus doyurulur. Arbitrasyonu hep o kazanır, meşru kareler sıra bulamaz.",
      effect: "ECU’lar birbirini duyamaz: göstergeler donar, kontrol mesajları gecikir. Hizmet engelleme (DoS).",
      detect: "Bus yükü taşkını (K05) en hızlı yakalayan katmandır. Ayrıca bilinmeyen ID (K01) ve zamanlama (K02) sinyal verir.",
      gw: ["GW-08", "GW-01"], v: "block", gwText: "GÖK-GW1 taşkını B domainine geçirmez (GW-08, GW-01): motor, fren ve direksiyon çalışmaya devam eder. A tarafındaki ECU’lar (Gösterge, Gövde) ise aynı hatta oldukları için yine etkilenir.",
      manip: "ID 0x000 ile saniyede binlerce kare basılıp bus dolduruluyor.", impact: "Meşru kareler sıra bulamıyor; göstergeler donuyor, kontrol mesajları gecikiyor." },
    fuzzing: { tgt: "engine", what: "Rastgele ID ve yüklerle ECU’lar zorlanır; beklenmeyen bir davranış (çökme, tuhaf mod) aranır.",
      effect: "Öngörülemez: bazı ECU’lar yeniden başlar, uyarı lambaları yanar, ya da hiçbir şey olmaz.",
      detect: "Bilinmeyen ID (K01): DBC’de olmayan ID’ler hemen göze çarpar.",
      gw: ["GW-01", "GW-02", "GW-08"], v: "block", gwText: "İzin listesinde olmayan her ID düşer (GW-01); olan ID’ler de DLC (GW-02) ve toplam hız sınırında (GW-08) elenir.",
      manip: "Rastgele ID ve yüklerle ECU’lara kare yağdırılıyor.", impact: "ECU’larda öngörülemeyen davranış deneniyor." },
    counter_crc_desync: { tgt: "brake", what: "Fren mesajının (0x200) canlı sayacı ve CRC alanları bozulur; fren ECU’su geçerli mesajları geçersiz sanmaya başlar.",
      effect: "Fren denetimi mesajları reddedilebilir; aracın güvenli duruma düşmesi (limp mode) tetiklenebilir.",
      detect: "Sayaç / CRC (K04): rolling counter atlıyor, CRC-8 tutmuyor.",
      gw: ["GW-10", "GW-05"], v: "block", gwText: "0x200 güvenlik kritik; A’dan asla geçmez (GW-10). Bozuk sayaç/CRC zaten GW-05 ile düşer.",
      manip: "Fren mesajının sayaç ve CRC alanları bozuluyor.", impact: "Fren ECU’su geçerli mesajları da reddetmeye başlıyor." },
    unauthorized_id: { tgt: "engine", what: "DBC’de bulunmayan 0x6F1 ID’si ile kare enjekte edilir; ağa yabancı bir cihazın izidir.",
      effect: "Doğrudan zarar vermeyebilir ama saldırganın ağa girdiğini gösterir; sonraki adımların habercisidir.",
      detect: "ID beyaz liste (K01): DBC’de olmayan ID anında alarm üretir.",
      gw: ["GW-01"], v: "block", gwText: "İzin listesinde olmayan ID, A’dan B’ye geçemez (GW-01).",
      manip: "DBC’de olmayan 0x6F1 ID’li kareler enjekte ediliyor.", impact: "Ağa yabancı bir cihazın girdiği ortaya çıkıyor." },
    uds_diagnostic_attack: { tgt: "engine", what: "Tanı oturumu açılır, SecurityAccess (0x27) anahtarı kaba kuvvetle sürekli denenir.",
      effect: "Anahtar bulunursa ECU’nun kilidi açılır; yazılım değiştirme, ayar bozma gibi kalıcı zarar kapısı açılır.",
      detect: "ISO-TP / UDS güvenlik duvarı (K07): riskli servis ve tekrarlayan başarısız deneme yakalanır.",
      gw: ["GW-06", "GW-07"], v: "block", gwText: "Atölye anahtarı kapalıyken UDS istek ID’leri (GW-06) ve tehlikeli servisler (GW-07) A’dan B’ye geçemez.",
      manip: "Tanı oturumu açılıp güvenlik anahtarı sürekli deneniyor.", impact: "Anahtar bulunursa ECU kilidi açılır." },
    uds_reflash: { tgt: "engine", what: "UDS 0x34 ile ISO-TP üzerinden ECU’ya yazılım yazma (reflash) girişimi yapılır.",
      effect: "Başarılırsa ECU’nun yazılımı değişir: en kalıcı ve en tehlikeli saldırı türü.",
      detect: "ISO-TP / UDS güvenlik duvarı (K07): çok çerçeveli aktarım ve 0x34 servisi işaretlenir.",
      gw: ["GW-06", "GW-07"], v: "block", gwText: "Atölye anahtarı yokken 0x34/0x36/0x37 servisleri düşürülür; araç sahibi anahtarı bilerek kapatmadıkça reflash geçemez.",
      manip: "ISO-TP üzerinden yazılım yazma (0x34) başlatılıyor.", impact: "Başarılırsa ECU yazılımı kalıcı olarak değişir." },
    headlight_can_injection_unlock: { tgt: "body", what: "Gövde verisi yoluna kapı kilidi açma kareleri (0x320) enjekte edilir; bilinen “far üzerinden araç hırsızlığı” yönteminin benzeri.",
      effect: "Kapılar sürücü bilmeden açılır.",
      detect: "Zamanlama sapması (K02): gerçek gövde ECU’sunun 100 ms periyodu bozulur, çift kaynak görünür.",
      gw: [], v: "none", gwText: "Gövde ECU’su A domaininde olduğu için kare GÖK-GW1’den hiç geçmez; yalnızca A içinde kalır. Korumak için gövdenin ayrı domaine alınması gerekir. IDS yine de uyarı verir.",
      manip: "Gövde yoluna kapı kilidi açma kareleri (0x320) basılıyor.", impact: "Kapılar sürücü bilmeden açılıyor." },
    brake_spoof: { tgt: "brake", what: "Gaz sıfırken sahte yüksek fren basıncı kareleri yollanır.",
      effect: "Fren sistemi ve diğer ECU’lar gerçekte olmayan bir fren komutu görür; araç beklenmedik biçimde yavaşlayabilir.",
      detect: "Sayaç / CRC (K04) ve zamanlama sapması (K02). Davranış analizi “fren var, yavaşlama yok” (VBA-03) der.",
      gw: ["GW-10", "GW-05"], v: "block", gwText: "0x200 A domaininden asla geçmez (GW-10); sayaç/CRC tutmayan kare ayrıca GW-05 ile düşer.",
      manip: "Gaz sıfırken sahte yüksek fren basıncı kareleri yayınlanıyor.", impact: "Fren sistemi olmayan bir fren komutu görüyor." },
  };
  const GW_RULE_TR = {
    "GW-01": "İzin listesi / yön", "GW-02": "DLC uyuşmazlığı", "GW-03": "ID başına hız sınırı", "GW-04": "Sinyal aralık dışı", "GW-05": "Sayaç / CRC hatası",
    "GW-06": "UDS istek kimlikleri", "GW-07": "Tehlikeli UDS servisi", "GW-08": "Bus seli", "GW-09": "Tamper kilit modu", "GW-10": "Güvenlik kritik kimlik",
  };
  const VERDICT = { block: ["ok", "GÖK-GW1 sahada engellerdi"], partial: ["warn", "GÖK-GW1 kısmen engellerdi"], none: ["bad", "GÖK-GW1 sahada engelleyemezdi"] };
  window.VEH_ATLAS = ATLAS; window.VEH_GW_RULE_TR = GW_RULE_TR; window.VEH_VERDICT = VERDICT;

  /* ---------- durum ---------- */
  const S = {
    inited: false, lastTs: -1, polled: 0, fpsHist: [], atkFrames: 0, blocked: 0, dots: [], raf: 0, gwOn: true,
    sel: "gw", alerts: [], guard: null, guardOk: null, ecuState: {}, playing: false, cancel: false, catalog: [],
    counts: {}, tap: 0, caption: "",
  };
  const active = () => document.body.dataset.tab === "veh" && !document.hidden;
  const el = (name, attrs = {}, parent) => { const e = document.createElementNS(SVGNS, name); for (const k in attrs) e.setAttribute(k, attrs[k]); if (parent) parent.appendChild(e); return e; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /* ---------- SVG topoloji ---------- */
  function ecuNode(k) {
    const e = ECU[k];
    return `<g class="ecu" id="e-${k}" data-k="${k}" tabindex="0" role="button" aria-label="${esc(e.n)} ECU bilgisi">
      <rect x="${e.x - 62}" y="${e.y - 26}" width="124" height="52" rx="6"/>
      <text class="nm" x="${e.x}" y="${e.y - 3}" text-anchor="middle">${esc(e.n)}</text>
      <text class="sb" x="${e.x}" y="${e.y + 14}" text-anchor="middle">${esc(e.ids.join(" · "))}</text></g>`;
  }
  function buildSvg() {
    const stub = (k) => { const e = ECU[k]; return `<line class="stub" x1="${e.x}" y1="${e.edge}" x2="${e.x}" y2="${BUS_Y}"/>`; };
    return `<svg id="vnet" class="vnet" viewBox="0 0 960 510" role="img" aria-labelledby="vnetT vnetD" preserveAspectRatio="xMidYMid meet">
      <title id="vnetT">Araç CAN ağı topolojisi</title>
      <desc id="vnetD">İki domain: A (güvenilmez: OBD-II, Gösterge, Gövde) ve B (korunan: Motor, Fren, Direksiyon, Şanzıman). Ortada GÖK-GW1 ağ geçidi, OBD-II portunda GÖK-TN1 dinleyici kart, dışarıda saldırgan dongle.</desc>
      <rect class="band a" x="20" y="22" width="400" height="474" rx="8"/><rect class="band b" x="540" y="22" width="400" height="474" rx="8"/>
      <text class="bt" x="36" y="46">A DOMAİNİ · GÜVENİLMEZ</text><text class="bs" x="36" y="63">OBD-II, gösterge, gövde</text>
      <text class="bt" x="556" y="46">B DOMAİNİ · KORUNAN</text><text class="bs" x="556" y="63">güç aktarma ve fren</text>
      ${["cluster", "body", "engine", "brake", "steer", "trans"].map(stub).join("")}
      <line class="stub" x1="170" y1="344" x2="170" y2="${BUS_Y}"/>
      <line class="stub tap" x1="330" y1="344" x2="330" y2="${BUS_Y}"/>
      <line class="bus a" id="busA" x1="90" y1="${BUS_Y}" x2="${GWL}" y2="${BUS_Y}"/>
      <line class="bus b" id="busB" x1="${GWR}" y1="${BUS_Y}" x2="910" y2="${BUS_Y}"/>
      <text class="bl" x="96" y="${BUS_Y - 8}">CAN A · 500 kbit/s</text><text class="bl" x="904" y="${BUS_Y - 8}" text-anchor="end">CAN B · 500 kbit/s</text>
      <line class="uplink" x1="170" y1="446" x2="170" y2="396"/>
      <path class="wifi" d="M330 396 V468 H395"/><text class="bl" x="338" y="440">Wi-Fi</text>
      <line class="wifi" x1="${GWX}" y1="446" x2="${GWX}" y2="312"/><text class="bl" x="${GWX + 8}" y="412">tüm trafiği görür</text>
      ${["cluster", "body", "engine", "brake", "steer", "trans"].map(ecuNode).join("")}
      <g class="node" id="n-obd" data-k="obd"><rect x="108" y="344" width="124" height="52" rx="6"/><text class="nm" x="170" y="366" text-anchor="middle">OBD-II portu</text><text class="sb" x="170" y="383" text-anchor="middle">pin 6 · 14 · 16</text></g>
      <g class="node tn" id="n-tn1" tabindex="0" role="button" data-k="tn1" aria-label="GÖK-TN1 OBD dinleyici kart bilgisi"><rect x="268" y="344" width="124" height="52" rx="6"/><text class="nm" x="330" y="366" text-anchor="middle">GÖK-TN1</text><text class="sb" x="330" y="383" text-anchor="middle">dinler · ESP32-S3</text></g>
      <g class="node atk" id="n-atk" tabindex="0" role="button" data-k="atk" aria-label="Saldırgan OBD dongle bilgisi"><rect x="98" y="446" width="144" height="44" rx="6"/><text class="nm" x="170" y="466" text-anchor="middle">Saldırgan</text><text class="sb" x="170" y="482" text-anchor="middle">OBD-II dongle</text></g>
      <g class="node ids" id="n-ids" tabindex="0" role="button" data-k="ids" aria-label="GÖK CAN-IDS Lab bilgisi"><rect x="395" y="446" width="170" height="44" rx="6"/><text class="nm" x="480" y="466" text-anchor="middle">GÖK CAN-IDS Lab</text><text class="sb" x="480" y="482" text-anchor="middle">tespit eder, durduramaz</text></g>
      <g class="gw" id="n-gw" tabindex="0" role="button" data-k="gw" aria-label="GÖK-GW1 güvenli ağ geçidi bilgisi"><rect x="${GWL}" y="190" width="${GWR - GWL}" height="120" rx="8"/>
        <text class="nm" x="${GWX}" y="224" text-anchor="middle">GÖK-GW1</text><text class="sb" x="${GWX}" y="241" text-anchor="middle">ağ geçidi</text>
        <text class="gst" id="gwSt" x="${GWX}" y="275" text-anchor="middle">NORMAL</text><text class="sb" id="gwBl" x="${GWX}" y="294" text-anchor="middle">engellenen: 0</text></g>
      <g id="vDots"></g><g id="vBal"></g>
    </svg>`;
  }

  /* ---------- noktalar (kare animasyonu) ---------- */
  const pathLen = (pts) => { const seg = []; let t = 0; for (let i = 1; i < pts.length; i++) { const l = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]); seg.push(l); t += l; } return { seg, total: t }; };
  function spawn(kind, pts, opt = {}) {
    if (RM.matches || !active() || S.dots.length > 70) return;
    const layer = $("vDots"); if (!layer) return;
    const { seg, total } = pathLen(pts); const c = el("circle", { r: kind === "atk" ? 5 : 4, class: "dot " + kind, cx: pts[0][0], cy: pts[0][1] }, layer);
    S.dots.push({ c, pts, seg, total, d: 0, v: opt.v || 300, stop: opt.stop, onEnd: opt.onEnd, kind });
    if (!S.raf) S.raf = requestAnimationFrame(step);
  }
  let lastT = 0;
  function step(t) {
    const dt = Math.min(0.05, (t - (lastT || t)) / 1000); lastT = t;
    S.dots = S.dots.filter((o) => {
      o.d += o.v * dt; const lim = o.stop != null ? Math.min(o.stop, o.total) : o.total;
      const d = Math.min(o.d, lim); let i = 0, acc = 0; while (i < o.seg.length - 1 && acc + o.seg[i] < d) { acc += o.seg[i]; i++; }
      const f = o.seg[i] ? (d - acc) / o.seg[i] : 1, a = o.pts[i], b = o.pts[i + 1] || a;
      o.c.setAttribute("cx", (a[0] + (b[0] - a[0]) * f).toFixed(1)); o.c.setAttribute("cy", (a[1] + (b[1] - a[1]) * f).toFixed(1));
      if (o.d >= lim) { o.c.remove(); if (o.onEnd) o.onEnd(); return false; }
      return true;
    });
    if (S.dots.length && active()) S.raf = requestAnimationFrame(step); else { S.raf = 0; lastT = 0; if (!active()) { S.dots.forEach((o) => o.c.remove()); S.dots = []; } }
  }
  const stubTo = (k) => { const e = ECU[k]; return [[e.x, e.edge], [e.x, BUS_Y]]; };
  function route(kind, src, tgtK) {
    if (src === "atk") {
      const tk = tgtK && ECU[tgtK] ? tgtK : "engine", tg = ECU[tk], inB = tg.dom === "B";
      const pts = [[170, 446], [170, BUS_Y]];
      if (inB) { pts.push([GWL, BUS_Y], [GWX, BUS_Y], [GWR, BUS_Y], [tg.x, BUS_Y], [tg.x, tg.edge]); return { pts, tk, cross: true, stopAt: pathLen(pts.slice(0, 3)).total - 2 }; }
      pts.push([tg.x, BUS_Y], [tg.x, tg.edge]); return { pts, tk, cross: false };
    }
    const e = ECU[src]; if (!e) return null;
    const first = stubTo(src);
    if (e.dom === "B") return { pts: [...first, [GWR, BUS_Y], [GWL, BUS_Y], [96, BUS_Y]], cross: false };
    return { pts: [...first, [GWL, BUS_Y], [GWR, BUS_Y], [760, BUS_Y]], cross: false };
  }
  function flash(id, cls, ms) { const n = $(id); if (!n) return; n.classList.add(cls); clearTimeout(n._t); n._t = setTimeout(() => n.classList.remove(cls), ms); }

  function frameVisual(r, delay) {
    const id = r.arbitration_id, isAtk = !!r.attack, src = isAtk ? "atk" : SRC2ECU[r.source] || null;
    if (!src) return;
    const diag = !isAtk && (id >= 0x700 || id === 0x6f1), kind = isAtk ? "atk" : diag ? "diag" : "ok";
    const tgtK = isAtk ? (ID2ECU[id] || (ATLAS[(r.source || "").split(":")[1]] || {}).tgt || "engine") : null;
    setTimeout(() => {
      const rt = route(kind, src, tgtK); if (!rt) return;
      if (isAtk) {
        S.atkFrames++;
        const blocked = S.gwOn && rt.cross;
        if (blocked) {
          S.blocked++;
          spawn(kind, rt.pts, { stop: rt.stopAt, v: 360, onEnd: () => { flash("n-gw", "stop", 350); popAt(GWL - 4, BUS_Y); } });
        } else spawn(kind, rt.pts, { v: 360, onEnd: () => hit(rt.tk) });
        if (RM.matches) { if (blocked) flash("n-gw", "stop", 600); else hit(rt.tk); }
      } else {
        spawn(kind, rt.pts, { v: 280 });
        if (ECU[src] && ECU[src].dom === "A" || diag) { if (S.tap++ % 3 === 0) spawn("tap", [[330, BUS_Y], [330, 344]], { v: 120 }); }
      }
    }, delay);
  }
  function popAt(x, y) { if (RM.matches || !$("vDots")) return; const c = el("circle", { cx: x, cy: y, r: 6, class: "pop" }, $("vDots")); setTimeout(() => c.remove(), 600); }
  function hit(k) { flash("e-" + k, "hit", 900); }

  /* ---------- canlı poll ---------- */
  async function poll() {
    if (!active()) return;
    try {
      const rows = await api("GET", "/api/bus/trace?limit=90"); if (!Array.isArray(rows) || !rows.length) return;
      const maxT = rows[rows.length - 1].timestamp; if (maxT < S.lastTs - 2) S.lastTs = -1;
      const fresh = rows.filter((r) => r.timestamp > S.lastTs); S.lastTs = maxT;
      const now = performance.now(); S.fpsHist.push([now, fresh.length]); while (S.fpsHist.length && S.fpsHist[0][0] < now - 4000) S.fpsHist.shift();
      const seen = new Set(), pick = [];
      for (let i = fresh.length - 1; i >= 0; i--) { const r = fresh[i], key = r.source + r.arbitration_id; if (r.attack) { if (pick.filter((p) => p.attack).length < 5) pick.push(r); } else if (!seen.has(key)) { seen.add(key); pick.push(r); } }
      pick.forEach((r, i) => frameVisual(r, i * 70));
      const cnt = {}; fresh.forEach((r) => { const k = r.attack ? "atk" : SRC2ECU[r.source]; if (k) cnt[k] = (cnt[k] || 0) + 1; });
      for (const k in cnt) S.counts[k] = (S.counts[k] || 0) + cnt[k];
      paintKpi(); paintChips();
    } catch (e) { /* sessiz: sunucu yeniden başlıyor olabilir */ }
  }
  let guardMiss = 0;
  async function pollGuard() {
    if (!active()) return;
    if (S.guardOk === false && guardMiss++ % 8) return; // uç nokta yokken konsolu doldurma: seyrek yeniden dene
    const was = S.guardOk;
    try { S.guard = await api("GET", "/api/guard/state"); S.guardOk = true; } catch (e) { S.guardOk = false; S.guard = null; }
    paintGw();
    if (was !== S.guardOk) paintInfo();
  }
  function paintGw() {
    const g = S.guard, mode = g ? g.mode : "normal";
    const st = $("gwSt"), bl = $("gwBl"), gw = $("n-gw"); if (!st) return;
    const label = !S.gwOn ? "DEVRE DIŞI" : mode === "locked" ? "KİLİT" : mode === "workshop" ? "ATÖLYE" : "NORMAL";
    st.textContent = label; gw.classList.toggle("off", !S.gwOn); gw.classList.toggle("lock", S.gwOn && mode === "locked"); gw.classList.toggle("shop", S.gwOn && mode === "workshop");
    bl.textContent = "engellenen: " + (g && g.stats ? g.stats.blocked : S.blocked);
    paintKpi();
  }
  function paintKpi() {
    const f = S.fpsHist.length > 1 ? S.fpsHist.reduce((a, x) => a + x[1], 0) / Math.max(0.5, (S.fpsHist[S.fpsHist.length - 1][0] - S.fpsHist[0][0]) / 1000 + 0.9) : 0;
    const g = S.guard && S.guard.stats;
    const set = (id, v) => { const n = $(id); if (n) n.textContent = v; };
    set("kFps", nf(f, 0)); set("kAtk", S.atkFrames.toLocaleString("tr-TR"));
    set("kBlock", (g ? g.blocked : S.blocked).toLocaleString("tr-TR")); set("kIds", S.alerts.length.toLocaleString("tr-TR"));
    set("kBlockSrc", g ? "GÖK-GW1 modeli" : "görsel sayım");
  }

  /* ---------- alarmlar ---------- */
  function onAlerts(list) {
    if (!list || !list.length) return;
    list.forEach((a) => S.alerts.unshift(a)); S.alerts = S.alerts.slice(0, 60);
    if (!S.inited) return;
    const a = list[list.length - 1], id = a.arbitration_id, k = ID2ECU[id] || null;
    const target = k || (/^0x(7|6F)/i.test(a.hex_id || "") ? "engine" : null);
    if (target) { const n = $("e-" + target); if (n) { n.classList.add("alarm"); clearTimeout(n._a); n._a = setTimeout(() => n.classList.remove("alarm"), 5000); } }
    const hx = a.hex_id ? ` (${a.hex_id})` : "";
    balloon(target, `${ruleTitle(a)}`, target ? `Hedef: ${ECU_TR[target]}${hx}` : `Bus geneli${hx}`);
    say(`Alarm: ${ruleTitle(a)}${a.hex_id ? " · " + a.hex_id : ""}${target ? " · hedef " + ECU_TR[target] : ""}.`);
    paintKpi(); if (S.sel) paintInfo();
  }
  function balloon(k, l1, l2) {
    const layer = $("vBal"); if (!layer) return; const e = k ? ECU[k] : null, x = Math.max(110, Math.min(850, e ? e.x : GWX)), y = e ? (e.y < 200 ? e.y + 72 : e.y - 72) : 170;
    layer.innerHTML = ""; const g = el("g", { class: "bal" }, layer); const w = Math.max(l1.length, l2.length) * 6.6 + 24;
    el("rect", { x: x - w / 2, y: y - 22, width: w, height: 42, rx: 6 }, g);
    const t1 = el("text", { x, y: y - 4, "text-anchor": "middle", class: "b1" }, g); t1.textContent = l1;
    const t2 = el("text", { x, y: y + 12, "text-anchor": "middle", class: "b2" }, g); t2.textContent = l2;
    clearTimeout(balloon._t); balloon._t = setTimeout(() => (layer.innerHTML = ""), 5000);
  }
  function say(t) { S.caption = t; const c = $("vCap"); if (c) c.textContent = t; }

  /* ---------- seçili düğüm paneli ---------- */
  const INFO = {
    gw: { t: "GÖK-GW1 · Güvenli CAN ağ geçidi", sim: "Sınır kapısındaki görevli: iki domain arasındaki her kareyi kural listesine göre geçirir ya da durdurur.", body: "Hat içine (A ve B arasına) girer. İzin listesi, DLC, hız sınırı, sinyal aralığı, sayaç/CRC, UDS ve atölye anahtarı kurallarını (GW-01…GW-10) uygular. IDS yalnızca bakar; GÖK-GW1 gerçekten durdurur.", ids: [] },
    tn1: { t: "GÖK-TN1 · OBD dinleyici kart", sim: "Kulak: araçta konuşulanları dinler, hiçbir şey söylemez (listen-only).", body: "OBD-II portuna bağlanır, CAN’i yalnızca okur ve Wi-Fi ile bu panele gönderir. Kablo ucundaki bu kart, aracın ağını bozamaz.", ids: [] },
    obd: { t: "OBD-II portu", sim: "Aracın herkese açık kapısı.", body: "Servis, sigorta dongle’ları ve saldırganlar da buradan girer. CANH pin 6, CANL pin 14, +12 V pin 16, şasi pin 4 ve 5’tir.", ids: [] },
    atk: { t: "Saldırgan · OBD-II dongle", sim: "Kapıya takılan yabancı cihaz.", body: "Takılı bir dongle ya da ele geçirilmiş bir bilgi-eğlence ünitesi A domainine sahte kare basar. Soldaki “Saldırı oynat” bu senaryoyu adım adım anlatır.", ids: [] },
    ids: { t: "GÖK CAN-IDS Lab (Python IDS)", sim: "Güvenlik kamerası: her şeyi görür, kayıt alır ve alarm verir; ama kapıyı kendi kapatamaz.", body: "İki domaini de gören 7 tespit katmanı ve davranış analizi çalıştırır. Alarm üretir, kareyi durduramaz; durdurma işi GÖK-GW1’indir.", ids: [] },
  };
  function paintInfo() {
    const box = $("vInfo"); if (!box) return; const k = S.sel; let h = "";
    if (ECU[k]) {
      const e = ECU[k], al = S.alerts.filter((a) => ID2ECU[a.arbitration_id] === k).slice(0, 4);
      h = `<h3 class="vh">${esc(e.n)} ECU <span class="tag ${e.dom === "A" ? "warn" : "info"}">${e.dom} domaini</span></h3>
        <p class="vsim">${esc(e.sim)}</p><p>${esc(e.role)}</p>
        <dl class="vkv"><dt>Yayınladığı ID’ler</dt><dd class="mono">${esc(e.ids.join(", "))}</dd><dt>Koruma</dt><dd>${e.dom === "B" ? "Korunan domain: GÖK-GW1 arkasında; A’dan gelen kareler kural süzgecinden geçer." : "Güvenilmez domain: GÖK-GW1 bu ECU’ya giden trafiği göremez; yalnızca IDS izler."}</dd></dl>
        <div class="vh2">Son alarmlar</div>${al.length ? al.map((a) => `<div class="vrow"><span class="tag bad">${esc(SEV_TR[a.severity] || a.severity)}</span> ${esc(ruleTitle(a))} <span class="mono dim">${esc(a.hex_id || "")}</span></div>`).join("") : `<div class="dim">Bu ECU için alarm yok.</div>`}`;
    } else if (INFO[k]) {
      const i = INFO[k]; h = `<h3 class="vh">${esc(i.t)}</h3><p class="vsim">${esc(i.sim)}</p><p>${esc(i.body)}</p>`;
      if (k === "gw") h += `<dl class="vkv"><dt>Durum</dt><dd>${S.guardOk ? "Canlı model: " + esc(S.guard.mode === "locked" ? "kilit" : S.guard.mode === "workshop" ? "atölye" : "normal") : "Canlı durum uç noktası henüz yok (görsel sayım)"}</dd></dl><a class="link" href="#hw" data-goto="hw">Kartı, kablolamayı ve kullanımı Donanım sekmesinde gör →</a>`;
      if (k === "tn1") h += `<a class="link" href="#hw" data-goto="hw">Nasıl bağlanır? Donanım sekmesinde →</a>`;
    }
    box.innerHTML = h;
    document.querySelectorAll("#vnet [data-k], .vchip").forEach((n) => n.classList.toggle("sel", n.dataset.k === k));
  }
  function paintChips() {
    const host = $("vChips"); if (!host) return;
    const items = [["gw", "GÖK-GW1"], ["tn1", "GÖK-TN1"], ...Object.keys(ECU).map((k) => [k, ECU[k].n]), ["ids", "IDS"]];
    if (!host.children.length) host.innerHTML = items.map(([k, n]) => `<button type="button" class="vchip" data-k="${k}"><span>${esc(n)}</span><b class="mono" data-c="${k}">—</b></button>`).join("");
    items.forEach(([k]) => { const b = host.querySelector(`[data-c="${k}"]`); if (b && ECU[k]) b.textContent = (S.counts[k] || 0).toLocaleString("tr-TR"); });
  }

  /* ---------- Saldırı oynat ---------- */
  const STEPS = [
    ["Keşif", "Saldırgan aracın OBD-II portuna bir dongle takar ve ağı dinler: hangi ID’ler, hangi sıklıkta konuşuyor?"],
    ["Erişim", "Dongle A domaininin hattına karışır. Bu domain güvenilmezdir: bilgi-eğlence, telematik ve dongle’lar burada yaşar."],
    ["Manipülasyon", ""], ["Etki", ""],
  ];
  function stepperHtml() { return STEPS.map((s, i) => `<li data-i="${i}"><span class="n">${i + 1}</span><span class="tx"><b>${s[0]}</b><span class="d"></span></span></li>`).join(""); }
  function setStep(i, text) {
    document.querySelectorAll("#vSteps li").forEach((li, j) => { li.classList.toggle("on", j === i); li.classList.toggle("done", j < i); if (j === i) li.querySelector(".d").textContent = text; });
    if (text) say(`${STEPS[i][0]}: ${text}`);
  }
  async function loadCatalog() { if (!S.catalog.length) { try { S.catalog = await api("GET", "/api/attacks"); } catch (e) { S.catalog = []; } } return S.catalog; }
  async function play(id) {
    if (S.playing) return; const a = ATLAS[id]; if (!a) return;
    const cat = (await loadCatalog()).find((x) => x.id === id); S.playing = true; S.cancel = false; S.alerts0 = S.alerts.length;
    const btn = $("vPlay"), sel = $("vAtkSel"); btn.disabled = true; sel.disabled = true; $("vStop").hidden = false; $("vResult").hidden = true; $("vResult").innerHTML = "";
    $("vSteps").classList.add("run"); document.querySelectorAll("#vSteps li").forEach((li) => { li.classList.remove("on", "done"); li.querySelector(".d").textContent = ""; });
    const startedAlerts = [], keep = (l) => startedAlerts.push(...(l || [])); window.__vehPlayAlerts = keep;
    try {
      setStep(0, STEPS[0][1]); flash("n-atk", "focus", 2600); S.sel = "atk"; paintInfo(); if (await wait(2600)) return;
      setStep(1, STEPS[1][1]); flash("n-obd", "focus", 2600); if (await wait(2600)) return;
      setStep(2, a.manip); await api("POST", "/api/attacks/run", { attack: id, duration: 7, params: (cat && cat.defaults) || {}, combine: false });
      if (await wait(4200)) return;
      setStep(3, (S.gwOn ? "GÖK-GW1 olmasaydı: " : "") + a.impact); if (a.tgt && !S.gwOn) { hit(a.tgt); const nn = $("e-" + a.tgt); nn.classList.add("alarm"); setTimeout(() => nn.classList.remove("alarm"), 4000); } if (await wait(3200)) return;
      await api("POST", "/api/attacks/stop").catch(() => {});
      await showResult(id, a, startedAlerts);
    } catch (e) { toast(e.message, true); } finally {
      window.__vehPlayAlerts = null; S.playing = false; btn.disabled = false; sel.disabled = false; $("vStop").hidden = true; $("vSteps").classList.remove("run");
    }
  }
  async function wait(ms) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (S.cancel) { await api("POST", "/api/attacks/stop").catch(() => {}); say("Oynatma durduruldu."); return true; } await sleep(120); } return false; }
  async function showResult(id, a, got) {
    const rules = [...new Set(got.map((x) => x.rule_id))], res = $("vResult");
    const ids = rules.length ? `IDS tespit etti: <b class="mono">${esc(rules.join(", "))}</b> ${rules.map((r) => LAYER_TR[r] ? esc(LAYER_TR[r][0]) : "").filter(Boolean).join(" · ")}` : `IDS bu saldırıda alarm üretmedi. ${a.detect ? esc(a.detect) : ""}`;
    let ev = null; try { ev = await api("POST", "/api/guard/evaluate", { attack: id, params: {} }); } catch (e) { ev = null; }
    let vk = a.v, line, src;
    if (ev && ev.total != null) { vk = ev.total && ev.blocked >= ev.total ? "block" : ev.blocked > 0 ? "partial" : "none"; line = ev.verdict_tr ? ev.verdict_tr.replace(/^GÖK-GW1 sahada [^:]*:\s*/, "") : `${ev.blocked} / ${ev.total} kare engellendi${ev.rules && ev.rules.length ? " · kurallar: " + ev.rules.join(", ") : ""}.`; src = "canlı model kararı"; }
    else { line = a.gwText; src = "ön bilgi: gateway modeli uç noktası henüz yok, atlas kaydından"; }
    const [cls, title] = VERDICT[vk];
    res.innerHTML = `<div class="vres ids"><span class="tag ${rules.length ? "info" : "warn"}">IDS</span><span>${ids}</span></div>
      <div class="vres gw ${cls}"><span class="tag ${cls}">GÖK-GW1</span><span><b>${title}.</b> ${esc(line)} <span class="dim">(${esc(src)})</span></span></div>`;
    res.hidden = false; say(`Sonuç: ${title}.`);
  }

  /* ---------- Araç Ağı sekmesi ---------- */
  function initVeh() {
    $("p-veh").innerHTML = `
      <div class="vkpis" aria-label="Canlı sayaçlar">
        <div class="vk"><span>Kare / sn</span><b class="mono" id="kFps">—</b><small>örnekleme penceresi</small></div>
        <div class="vk"><span>Saldırı karesi</span><b class="mono bad-t" id="kAtk">0</b><small>kırmızı noktalar</small></div>
        <div class="vk"><span>GW1 engellenen</span><b class="mono" id="kBlock">0</b><small id="kBlockSrc">görsel sayım</small></div>
        <div class="vk"><span>IDS alarmı</span><b class="mono" id="kIds">0</b><small>bu oturumda</small></div>
      </div>
      <div class="vgrid">
        <div class="panel vmain">
          <div class="panel-h"><h2>Canlı araç ağı</h2>
            <div class="vleg" aria-label="Renk açıklaması"><span><i class="dot ok"></i>normal</span><span><i class="dot diag"></i>tanı</span><span><i class="dot atk"></i>saldırı</span></div></div>
          <div class="vscroll" tabindex="0" role="group" aria-label="Topoloji diyagramı, dar ekranda yatay kaydırılabilir">${buildSvg()}</div>
          <p class="vcap" id="vCap" role="status" aria-live="polite">Noktalar CAN karelerini gösterir. Bir ECU’ya, GÖK-GW1’e ya da karta tıklayıp ne yaptığını öğren.</p>
          <div class="vctl">
            <label class="chk"><span class="switch"><input type="checkbox" id="vGwOn" checked><i></i></span><span>GÖK-GW1 devrede</span></label>
            <span class="dim vhint">Kapatınca saldırı kareleri korunan domaine ulaşır ve hedef ECU kırmızı yanar.</span>
          </div>
          <div class="vchips" id="vChips" aria-label="Düğümler ve kare sayıları"></div>
        </div>
        <div class="vside">
          <div class="panel">
            <div class="panel-h"><h2>Saldırı oynat</h2><span class="hint-r">anlatımlı demo</span></div>
            <label class="fld"><span>Saldırı</span><select id="vAtkSel"></select></label>
            <div class="row"><button class="btn primary" id="vPlay" type="button">${ico("play")}<span>Oynat</span></button><button class="btn" id="vStop" type="button" hidden>${ico("square")}<span>Durdur</span></button></div>
            <ol class="vsteps" id="vSteps">${stepperHtml()}</ol>
            <div id="vResult" hidden></div>
          </div>
          <div class="panel"><div class="panel-h"><h2>Seçili düğüm</h2></div><div id="vInfo"></div></div>
        </div>
      </div>`;
    const sel = $("vAtkSel"); sel.innerHTML = Object.keys(ATLAS).map((k) => `<option value="${k}">${esc(atkName(k))}</option>`).join("");
    $("vPlay").addEventListener("click", () => play(sel.value));
    $("vStop").addEventListener("click", () => { S.cancel = true; });
    $("vGwOn").addEventListener("change", (e) => { S.gwOn = e.target.checked; paintGw(); say(S.gwOn ? "GÖK-GW1 devrede: saldırı kareleri geçitte durur." : "GÖK-GW1 devre dışı: saldırı kareleri korunan domaine ulaşır."); });
    const pick = (e) => { const n = e.target.closest("[data-k]"); if (!n) return; S.sel = n.dataset.k; paintInfo(); };
    $("p-veh").addEventListener("click", pick);
    $("p-veh").addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target.matches("[data-k]")) { e.preventDefault(); pick(e); } });
    S.inited = true; paintChips(); paintInfo(); paintGw(); S.alerts.slice(0, 0);
  }
  function show() { if (!S.inited) initVeh(); paintInfo(); poll(); pollGuard(); const h = location.hash.split("/")[1]; if (h && ATLAS[h]) $("vAtkSel").value = h; }
  setInterval(poll, 700); setInterval(pollGuard, 2500);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) S.lastTs = -1; });
  // Alarm akışı: kendi ekranım dışında da oynatma sonucu için toplanır (app.js pushAlerts kancası)
  function hookAlerts(list) { if (window.__vehPlayAlerts) window.__vehPlayAlerts(list); onAlerts(list); }

  /* ---------- Saldırı Atlası ---------- */
  let atlasCat = "all";
  function atlasCard(id, a) {
    const cat = (window.__atkCat || {})[id] || "", [n, d] = ATK_TR[id] || [id, ""];
    const [vc, vt] = VERDICT[a.v];
    return `<article class="acard" data-id="${id}" aria-labelledby="ah-${id}">
      <header><span class="cat">${esc(CAT_TR[cat] || cat)}</span><h3 id="ah-${id}">${esc(n)}</h3><p class="dim">${esc(d)}</p></header>
      <dl class="adl">
        <dt>Nedir?</dt><dd>${esc(a.what)}</dd>
        <dt>Araçta ne olur?</dt><dd>${esc(a.effect)}</dd>
        <dt>Nasıl yakalıyoruz?</dt><dd>${esc(a.detect)}</dd>
        <dt>GÖK-GW1 ne yapar?</dt><dd><span class="tag ${vc}">${vt}</span> ${a.gw.map((r) => `<span class="rtag mono" title="${esc(GW_RULE_TR[r])}">${r}</span>`).join("")}<br>${esc(a.gwText)}<span class="ev" data-ev></span></dd>
      </dl>
      <footer><button class="btn primary sm" type="button" data-try="${id}">${ico("play")}<span>Canlı dene</span></button><button class="btn sm" type="button" data-eval="${id}">${ico("shield")}<span>GÖK-GW1 ile ölç</span></button></footer></article>`;
  }
  async function loadAtlas() {
    const host = $("p-atlas"); const cat = await loadCatalog(); window.__atkCat = Object.fromEntries(cat.map((c) => [c.id, c.category]));
    const cats = [...new Set(Object.keys(ATLAS).map((k) => window.__atkCat[k]).filter(Boolean))];
    host.innerHTML = `<div class="panel"><div class="panel-h"><h2>Saldırı atlası</h2><span class="hint-r">${Object.keys(ATLAS).length} saldırı · her biri Saldırı Lab’da çalıştırılabilir</span></div>
      <p class="intro">Her kart aynı soruları yanıtlar: saldırı nedir, araçta ne olur, IDS nasıl yakalar, GÖK-GW1 sahada ne yapardı. “Canlı dene” Araç Ağı sekmesinde anlatımlı oynatır.</p>
      <div class="vfilter" role="group" aria-label="Kategori süzgeci"><button class="btn sm" type="button" data-f="all" aria-pressed="true">Tümü</button>${cats.map((c) => `<button class="btn sm" type="button" data-f="${c}" aria-pressed="false">${esc(CAT_TR[c] || c)}</button>`).join("")}</div></div>
      <div class="agrid" id="aGrid">${Object.entries(ATLAS).map(([k, a]) => atlasCard(k, a)).join("")}</div>`;
    filterAtlas();
  }
  function filterAtlas() {
    document.querySelectorAll("#p-atlas .vfilter [data-f]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.f === atlasCat));
    document.querySelectorAll("#aGrid .acard").forEach((c) => { c.hidden = atlasCat !== "all" && (window.__atkCat || {})[c.dataset.id] !== atlasCat; });
  }
  document.addEventListener("click", async (e) => {
    const f = e.target.closest("#p-atlas [data-f]"); if (f) { atlasCat = f.dataset.f; return filterAtlas(); }
    const t = e.target.closest("[data-try]"); if (t) { location.hash = "veh/" + t.dataset.try; if (document.body.dataset.tab !== "veh") showTab("veh", t.dataset.try); $("vAtkSel").value = t.dataset.try; setTimeout(() => play(t.dataset.try), 300); return; }
    const v = e.target.closest("[data-eval]"); if (v) {
      const out = v.closest(".acard").querySelector("[data-ev]"); out.textContent = " Ölçülüyor…";
      try { const r = await api("POST", "/api/guard/evaluate", { attack: v.dataset.eval, params: {} }); out.innerHTML = ` <b>Ölçüm:</b> ${r.blocked} / ${r.total} kare engellendi${r.rules && r.rules.length ? " (" + esc(r.rules.join(", ")) + ")" : ""}. ${esc(r.verdict_tr || "")}`; }
      catch (er) { out.textContent = " Ölçüm uç noktası (POST /api/guard/evaluate) henüz hazır değil; yukarıdaki metin atlas kaydıdır."; }
    }
  });

  window.Veh = { show, onAlerts: hookAlerts, atlas: loadAtlas, play };
  // app.js showTab'ı bu dosya yüklenmeden çalıştıysa ilk açılışı tamamla
  const cur = document.body.dataset.tab; if (cur === "veh") show(); if (cur === "atlas") loadAtlas();
})();
