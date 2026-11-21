// GÖK CAN-IDS Lab — Kapsam ve Donanım sekmeleri. app.js ve vehicle.js'ten sonra yüklenir.
// Backend uçları (coverage, guard) ya da hw/boards.json henüz yoksa hata fırlatmaz; yer tutucu gösterir.
(() => {
  "use strict";
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const tagCls = { detected: "ok", partial: "warn", missed: "bad" };
  const stTr = { detected: "Yakalandı", partial: "Kısmen", missed: "Kaçtı" };
  const stSym = { detected: "✓", partial: "◐", missed: "✕" };
  const placeholder = (ic, t, d) => `<div class="empty-cta">${ico(ic)}<b>${esc(t)}</b><span>${d}</span></div>`;

  /* ================= KAPSAM ================= */
  let covBusy = false;
  function paintCoverage(c) {
    const host = $("covBody");
    if (!c || c.status === "idle" || !c.summary) { host.innerHTML = placeholder("shield", "Henüz kapsam testi çalıştırılmadı", "“Kapsam testini çalıştır” 12 saldırının her birini ayrı ayrı oynatır; hangi IDS katmanının ve hangi GÖK-GW1 kuralının yakaladığını gösterir. Birkaç saniye sürer."); return; }
    const s = c.summary, res = c.results || [];
    const kp = (l, v, sub) => `<div class="vk"><span>${l}</span><b class="mono">${v}</b><small>${sub}</small></div>`;
    let h = `<div class="vkpis">${kp("Senaryo", s.scenarios, "denenen saldırı")}${kp("IDS yakaladı", `${s.detected} / ${s.scenarios}`, "kare + davranış katmanları")}${kp("GW1 engelledi", `${s.gateway_blocked} / ${s.scenarios}`, "sahada durdururdu")}${kp("Süre", nf((c.duration_ms || 0) / 1000, 1) + " sn", "toplam çalışma")}</div>`;
    const tac = c.matrix && c.matrix.tactics || [];
    if (tac.length) h += `<div class="panel"><div class="panel-h"><h2>Taktik ısı haritası</h2><span class="hint-r">yaklaşık eşleme, resmi MITRE eşlemesi değildir</span></div>
      <div class="heat">${tac.map((t) => `<div class="hcol"><div class="hh">${esc(t.name_tr)}</div>${(t.cells || []).map((x) => `<div class="hcell ${esc(x.status)}" title="${esc(x.name)}: ${stTr[x.status] || x.status}"><span class="sym" aria-hidden="true">${stSym[x.status] || "?"}</span><span>${esc(x.name)}</span><span class="sr">${stTr[x.status] || ""}</span></div>`).join("") || `<div class="dim hc0">Senaryo yok</div>`}</div>`).join("")}</div>
      <div class="vleg inline"><span><i class="sw ok"></i>✓ yakalandı</span><span><i class="sw warn"></i>◐ kısmen</span><span><i class="sw bad"></i>✕ kaçtı</span></div></div>`;
    h += `<div class="panel"><div class="panel-h"><h2>Senaryo sonuçları</h2></div><div class="tw"><table class="dense"><thead><tr><th>Saldırı</th><th>Taktik</th><th>Beklenen katman</th><th>Tetiklenen</th><th>Kaçan</th><th class="r">İlk tespit</th><th>GÖK-GW1</th><th>Sonuç</th></tr></thead><tbody>`;
    const tacTr = Object.fromEntries(tac.map((t) => [t.id, t.name_tr]));
    h += res.map((r) => {
      const lay = (a) => (a && a.length ? a.map((l) => `<span class="rtag mono">${esc(String(l).startsWith("CAN-IDS") ? "IDS-" + l.slice(8) : l)}</span>`).join("") : `<span class="dim">—</span>`);
      const g = r.gateway || {}; const gv = !g.total ? "none" : g.blocked >= g.total ? "block" : g.blocked > 0 ? "partial" : "none";
      return `<tr><td><b>${esc(atkName(r.id, r.name))}</b><div class="dim sm">${esc(r.note_tr || "")}</div></td><td>${esc(tacTr[r.tactic] || r.tactic || "")}</td><td>${lay(r.expected)}</td><td>${lay(r.triggered)}</td><td>${lay(r.missed)}</td>
        <td class="r mono">${r.first_detect_ms == null ? "—" : (r.first_detect_ms >= 1000 ? nf(r.first_detect_ms / 1000, 1) + " sn" : nf(r.first_detect_ms, 0) + " ms")}</td><td><span class="tag ${gv === "block" ? "ok" : gv === "partial" ? "warn" : "bad"}">${g.total ? `${g.blocked} / ${g.total}` : "yok"}</span> ${(g.rules || []).map((x) => `<span class="rtag mono">${esc(x)}</span>`).join("")}</td>
        <td><span class="tag ${r.detected ? "ok" : "bad"}">${r.detected ? "Yakalandı" : "Kaçtı"}</span></td></tr>`;
    }).join("");
    host.innerHTML = h + `</tbody></table></div></div>`;
  }
  async function loadCoverage() {
    $("covRun").disabled = covBusy;
    try { paintCoverage(await api("GET", "/api/coverage")); }
    catch (e) { $("covBody").innerHTML = placeholder("alert", "Kapsam servisi henüz hazır değil", "GET /api/coverage uç noktası yanıt vermiyor; arka uç güncellendiğinde burası kendiliğinden dolar."); }
  }
  async function runCoverage() {
    if (covBusy) return; covBusy = true; const b = $("covRun"); b.disabled = true; b.querySelector("span").textContent = "Çalışıyor…";
    $("covBody").insertAdjacentHTML("afterbegin", `<div class="notice" id="covWait">${ico("info")}<span>12 saldırı sırayla oynatılıyor, lütfen bekleyin…</span></div>`);
    try { paintCoverage(await api("POST", "/api/coverage/run")); toast("Kapsam testi tamamlandı"); }
    catch (e) { const w = $("covWait"); if (w) w.remove(); toast("Kapsam testi çalıştırılamadı: " + e.message, true); }
    finally { covBusy = false; b.disabled = false; b.querySelector("span").textContent = "Kapsam testini çalıştır"; }
  }

  /* ================= DONANIM ================= */
  const FALLBACK = [
    { id: "gok-tn1", name: "GÖK-TN1 OBD Tap Node", tagline: "Aracı dinle", role: "OBD-II portundan CAN’i yalnızca okur (listen-only), Wi-Fi ile bu panele gönderir.",
      features: ["ESP32-S3 + SN65HVD230, listen-only TWAI", "12 V giriş: sigorta, ters polarite koruması, TVS (yük atma), 3,3 V DC/DC", "Jumper’lı 120 Ω sonlandırma, CAN hattında ESD koruması", "2x5 istifleme başlığı → GÖK-GW1", "Programlama başlığı, EN/BOOT düğmeleri, PWR/CAN LED’leri"] },
    { id: "gok-gw1", name: "GÖK-GW1 Secure CAN Gateway", tagline: "Domainleri ayır, koru", role: "İki CAN domaini arasına girer; kural listesine uymayan kareyi düşürür. Hat içi güvenlik duvarı.",
      features: ["STM32G0B1 (2 × FDCAN), GÖK-Guard yazılımı", "ATECC608A güven kökü (cihaz kimliği, imzalı olay)", "TPS3823 watchdog: fail-closed", "Atölye anahtarı ve tamper anahtarı", "PWR / PASS / BLOCK / DIAG LED’leri, SWD başlığı"] },
    { id: "gok-pi1", name: "GÖK-PI1 SocketCAN HAT", tagline: "Raspberry Pi’ye CAN ver", role: "Raspberry Pi için MCP2515 + SN65HVD230 HAT’i. Linux’ta can0 olarak görünür.",
      features: ["MCP2515 (SPI) + SN65HVD230", "Linux SocketCAN: can0", "Bu repodaki SocketCAN köprüsüyle doğrudan çalışır"] },
  ];
  const BENZETME = { "gok-tn1": ["Kulak", "Dinler ama konuşmaz; aracı bozamaz."], "gok-gw1": ["Sınır kapısı görevlisi", "Her kareye kimlik sorar; kural dışını geri çevirir."], "gok-pi1": ["Kulaklık adaptörü", "Raspberry Pi’nin CAN’i duymasını sağlar."] };
  let boards = null, boardsOk = null;
  async function loadBoards() {
    if (boards) return;
    try { const r = await fetch("hw/boards.json", { cache: "no-cache" }); if (!r.ok) throw 0; const j = await r.json(); boards = (j.boards || []).length ? j.boards : FALLBACK; boardsOk = (j.boards || []).length > 0; }
    catch (e) { boards = FALLBACK; boardsOk = false; }
  }
  // Kartın araçta takıldığı yer (başlıkta parantezle + kart içinde açıklama). 3B Araç sekmesi aynı yerleri işaretler.
  const PLACE = {
    "gok-tn1": ["OBD-II portu · direksiyon altı", "Sürücü tarafında, gösterge panelinin altındaki OBD-II portuna (diz hizası) 4 telli kabloyla takılır. Küçük kutu kablonun ucunda durur; araca hiçbir şey yazmaz."],
    "gok-gw1": ["ön konsol arkası · merkezi ağ geçidinin yanı", "Torpido / ön konsol arkasında, aracın mevcut merkezi ağ geçidinin yanında; OBD-bilgi-eğlence (A) kablo demetinin motor-fren-direksiyon (B) demetinden ayrıldığı noktaya hat içi girer. Aracın beyni (ECU) değildir: ECU’lar arasındaki kapıdaki görevlidir."],
    "gok-pi1": ["araçta değil · test tezgâhı", "Araca takılmaz. Masadaki test tezgâhında Raspberry Pi’nin 40 pinli başlığına oturur; tezgâhtaki CAN hattına bağlanır."],
  };
  function boardCard(b) {
    const im = b.images || {}, views = [["top", "Üst"], ["bottom", "Alt"], ["iso", "3B"]].filter(([k]) => im[k]), bz = BENZETME[b.id];
    const st = b.stats || {}, kv = [["Bileşen", st.components], ["Ağ", st.nets], ["Boyut", st.width_mm ? `${st.width_mm} × ${st.height_mm} mm` : null], ["Katman", st.layers], ["Yönlendirme", st.routed_pct != null ? `% ${st.routed_pct}` : null], ["DRC hatası", st.drc_errors]].filter((x) => x[1] != null);
    return `<article class="bcard" data-b="${esc(b.id)}"><header><h3>${esc(b.name)}${PLACE[b.id] ? ` <span class="bplace">(${esc(PLACE[b.id][0])})</span>` : ""}</h3><span class="tag info">${esc(b.tagline || "")}</span></header>
      ${PLACE[b.id] ? `<p class="bwhere"><b>Araçta nerede?</b> ${esc(PLACE[b.id][1])} <a href="#car3d">3B araçta göster →</a></p>` : ""}
      ${views.length ? `<div class="bimg"><img src="${esc(im[views[views.length - 1][0]])}" alt="${esc(b.name)} kart görünümü" loading="lazy" data-img onerror="this.parentNode.classList.add('bad')"><div class="bimg-ph">Görsel yüklenemedi</div></div>
        <div class="seg-ctl bviews" role="group" aria-label="Görünüm">${views.map(([k, l], i) => `<button type="button" aria-pressed="${i === views.length - 1}" data-view="${esc(im[k])}">${l}</button>`).join("")}</div>`
        : `<div class="bimg ph"><div class="bimg-ph">Kart görseli henüz üretilmedi</div></div>`}
      ${bz ? `<p class="vsim"><b>${bz[0]}:</b> ${bz[1]}</p>` : ""}<p>${esc(b.role || "")}</p>
      <ul class="bfeat">${(b.features || []).map((f) => `<li>${esc(f)}</li>`).join("")}</ul>
      ${kv.length ? `<dl class="bstat">${kv.map(([k, v]) => `<div><dt>${k}</dt><dd class="mono">${esc(v)}</dd></div>`).join("")}</dl>` : ""}
      <div class="blinks">${b.schematic_pdf ? `<a class="btn sm" href="${esc(b.schematic_pdf)}" target="_blank" rel="noopener">${ico("download")}<span>Şema (PDF)</span></a>` : ""}${b.gerbers_zip ? `<a class="btn sm" href="${esc(b.gerbers_zip)}" download>${ico("download")}<span>Gerber (ZIP)</span></a>` : ""}</div>
      ${(b.bom || []).length ? `<details class="adv"><summary>Malzeme listesi (${b.bom.length} kalem)</summary><div class="tw short"><table class="dense mono"><thead><tr><th>Ref</th><th>Değer</th><th class="r">Adet</th></tr></thead><tbody>${b.bom.map((x) => `<tr><td>${esc(x.ref)}</td><td>${esc(x.value)}</td><td class="r">${esc(x.qty)}</td></tr>`).join("")}</tbody></table></div></details>` : ""}</article>`;
  }
  const BLOCK_SVG = `<svg class="vnet hwblk" viewBox="0 0 960 300" role="img" aria-labelledby="blkT blkD"><title id="blkT">Donanım blok diyagramı</title><desc id="blkD">OBD-II portu CAN A hattından GÖK-GW1’e, oradan CAN B hattıyla güç aktarma domainine gider. GÖK-TN1 OBD-II portundan dinler, 2x5 kabloyla GÖK-GW1’e bağlanır ve Wi-Fi ile GÖK CAN-IDS Lab paneline olay yollar. Raspberry Pi ve GÖK-PI1 SocketCAN ile aynı panele CAN karesi verir.</desc>
    <g class="node"><rect x="20" y="110" width="150" height="60" rx="6"/><text class="nm" x="95" y="136" text-anchor="middle">OBD-II portu</text><text class="sb" x="95" y="154" text-anchor="middle">A domaini</text></g>
    <line class="bus a" x1="170" y1="140" x2="330" y2="140"/><text class="bl" x="250" y="130" text-anchor="middle">CAN A</text>
    <g class="gw"><rect x="330" y="95" width="150" height="90" rx="8"/><text class="nm" x="405" y="132" text-anchor="middle">GÖK-GW1</text><text class="sb" x="405" y="150" text-anchor="middle">kural süzgeci</text><text class="sb" x="405" y="166" text-anchor="middle">fail-closed</text></g>
    <line class="bus b" x1="480" y1="140" x2="640" y2="140"/><text class="bl" x="560" y="130" text-anchor="middle">CAN B</text>
    <g class="node"><rect x="640" y="110" width="170" height="60" rx="6"/><text class="nm" x="725" y="136" text-anchor="middle">Güç aktarma / fren</text><text class="sb" x="725" y="154" text-anchor="middle">Motor · Fren · Direksiyon</text></g>
    <g class="node tn"><rect x="20" y="215" width="150" height="60" rx="6"/><text class="nm" x="95" y="241" text-anchor="middle">GÖK-TN1</text><text class="sb" x="95" y="259" text-anchor="middle">dinler · ESP32-S3</text></g>
    <line class="stub tap" x1="95" y1="170" x2="95" y2="215"/>
    <path class="wifi" d="M170 245 H405 V185"/><text class="bl" x="290" y="237" text-anchor="middle">2x5 kablo (UART · I2C · uyarı)</text>
    <g class="node ids"><rect x="560" y="215" width="250" height="60" rx="6"/><text class="nm" x="685" y="241" text-anchor="middle">GÖK CAN-IDS Lab paneli</text><text class="sb" x="685" y="259" text-anchor="middle">POST /api/guard/events</text></g>
    <path class="wifi" d="M170 262 H560"/><text class="bl" x="470" y="283" text-anchor="middle">Wi-Fi: olay ve kare</text>
    <g class="node"><rect x="830" y="30" width="110" height="92" rx="6"/><text class="nm" x="885" y="62" text-anchor="middle">Raspberry Pi</text><text class="sb" x="885" y="80" text-anchor="middle">+ GÖK-PI1</text><text class="sb" x="885" y="98" text-anchor="middle">can0</text></g>
    <path class="wifi" d="M885 122 V215 H810"/><text class="bl" x="893" y="190">SocketCAN</text></svg>`;

  const wt = (rows, head) => `<div class="tw"><table class="dense"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c, i) => `<td${i === 0 ? ' class="mono nw"' : ""}>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  const code = (t) => `<pre class="code mono" tabindex="0"><code>${esc(t)}</code></pre>`;
  function guideHtml() {
    const pinTn1 = [["6", "CAN H", "CANH", "Veri hattı (yüksek)"], ["14", "CAN L", "CANL", "Veri hattı (düşük)"], ["16", "+12 V (sürekli)", "+12V", "Sigortalı giriş; kart içinde ayrıca sigorta ve TVS var"], ["4", "Şasi GND", "GND", "Güç dönüşü"], ["5", "Sinyal GND", "GND", "Referans; 4 ile aynı klemense bağlanabilir"]];
    return `
    <div class="gsteps">
    <section class="gstep"><h3><span class="n">1</span>Hangi kart ne işe yarar?</h3>
      <div class="gcards"><div><b>GÖK-TN1 · Kulak</b><p>OBD-II portuna takılır, araçtaki CAN trafiğini yalnızca dinler ve Wi-Fi ile bu panele yollar. Hat üzerinde hiçbir kare göndermez (listen-only), bu yüzden aracı bozamaz. Tek başına “izleme” içindir.</p></div>
        <div><b>GÖK-GW1 · Sınır kapısı görevlisi</b><p>İki CAN domaininin arasına girer. A tarafından (güvenilmez: OBD-II, bilgi-eğlence) B tarafına (korunan: motor, fren, direksiyon) geçmek isteyen her kareye kimlik sorar. İzin listesinde yoksa, hızı fazlaysa, sinyali imkânsızsa, tanı komutuysa ve atölye anahtarı yoksa geri çevirir.</p></div>
        <div><b>GÖK-PI1 · Kulaklık adaptörü</b><p>Raspberry Pi’ye takılan CAN HAT’idir. Pi’de <span class="mono">can0</span> arayüzü açar; bu proje simülatör karelerini o arayüzden gerçek bir CAN hattına yazar (SocketCAN köprüsü). Araca değil, masadaki CAN’e bağlanır.</p></div></div>
      <p class="note">Ayrım: <b>IDS (bu panel)</b> bütün bus’ı görür ama durduramaz. <b>GÖK-GW1</b> sahada durdurur ama yalnızca iki domain arasındaki trafiği görür. İkisi birbirini tamamlar.</p></section>

    <section class="gstep"><h3><span class="n">2</span>İki kurulum biçimi</h3>
      <div class="seg-ctl gtopo" role="radiogroup" aria-label="Kurulum biçimi"><button type="button" role="radio" aria-checked="true" data-topo="tn">A · OBD-II’den yalnız izleme (TN1)</button><button type="button" role="radio" aria-checked="false" data-topo="gw">B · Domainler arası koruma (TN1 + GW1)</button></div>
      <div id="gtn"><p><b>Ne yapar:</b> TN1, OBD-II portuna takılır; panel aracı canlı izler. Hiçbir şey engellenmez, hiçbir şey bozulmaz.</p><ol class="gl"><li>Önce kartı güç vermeden OBD-II kablosuna bağla (Adım 3’teki tablo).</li><li>Sonlandırma jumper’ı <b>takılı değil</b> olsun.</li><li>Kartı Wi-Fi ağına tanıt (yazılımda ağ adı ve parola; bu yazılım henüz taslak).</li><li>Panel Araç Ağı sekmesinde TN1’in gönderdiği olayları göster.</li></ol></div>
      <div id="ggw" hidden><p><b>Ne yapar:</b> GW1, A ve B domaini arasına girer (bump-in-the-wire). Araçtaki A–B bağlantısı GW1’in iki portuna ayrılır; kural dışı kare B’ye ulaşmaz. TN1 yine OBD-II’den dinler ve GW1’le 2x5 kablo ile konuşur.</p><ol class="gl"><li>Önce <b>tezgâhta</b> dene: iki CAN düğümü + 12 V; araca ilk denemeyi yapma.</li><li>Araç tarafını GW1 <b>Port A</b>’ya, korunan tarafı <b>Port B</b>’ye bağla (A güvenilmez, B korunan).</li><li>TN1 ile GW1’i 2x5 flat kabloyla bağla: pin 1 işaretli damar iki kartta da aynı tarafta olsun. GW1 3,3 V’u bu kabloyla TN1’den alır.</li><li>Atölye anahtarı <b>etkin değil</b>; tamper anahtarı <b>serbest</b> konumda olsun.</li><li>Port başına 120 Ω jumper’ı yalnızca o port hattın <b>fiziksel ucundaysa</b> tak.</li></ol>
        <p class="note warn">Araçta kablo demetini kesip GW1’i araya sokmak ehliyetli bir elektrik/otomotiv bilgisi gerektirir. Bu proje yalnızca tezgâh ve kendi aracın içindir.</p></div></section>

    <section class="gstep"><h3><span class="n">3</span>Kablolama tablosu</h3>
      <h4>GÖK-TN1 ← OBD-II konnektörü (J1962)</h4>
      ${wt(pinTn1.map((r) => [`pin ${r[0]}`, r[1], r[2], r[3]]), ["OBD-II", "Sinyal", "TN1 klemens", "Not"])}
      <p class="note">Kartta J1962 konnektörü yoktur; OBD-II’den dört telli bir kablo çıkıp TN1’in 4’lü klemensine gider. Kablonun eşleşmesini kartın klemens baskısıyla ve aşağıdaki “Karttaki konnektörler” tablosuyla doğrula.</p>
      <h4>İki kart arası (2x5 istifleme başlığı)</h4>
      ${wt([["1, 10", "3V3", "GW1 beslemesi (TN1’den gelir)"], ["2, 9", "GND", "Ortak şase"], ["3", "UART_TX", "TN1 → GW1 (komut / yapılandırma)"], ["4", "UART_RX", "GW1 → TN1: olay satırları, TN1 bunları Wi-Fi ile panele yollar"], ["5, 6", "I2C_SDA / SCL", "Olay kanalı (TN1 yönetici, GW1 bağımlı)"], ["7", "GUARD_ALERT", "GW1’den “engelledim” uyarısı"], ["8", "GUARD_RST", "TN1’den GW1’i yeniden başlatma"]], ["Pin", "Sinyal", "Görev"])}
      <p class="note">TN1’de <span class="mono">J3</span>, GW1’de <span class="mono">J1</span>; iki kartta sıra aynıdır, 1:1 flat kablo kullan. Sinyal adları TN1’in bakış açısıyladır. MCU pinleri: <span class="mono">hardware/gok-gw1/pinout.md</span>.</p>
      <h4>GÖK-GW1 CAN portları</h4>
      ${wt([["J5 · Port A", "CAN_A_H, CAN_A_L, GND", "Güvenilmez taraf: OBD-II / bilgi-eğlence hattı"], ["J7 · Port B", "CAN_B_H, CAN_B_L, GND", "Korunan taraf: motor, fren, direksiyon ECU’ları"], ["J6 / J8", "120 Ω jumper", "Port A / Port B sonlandırması (yalnız hattın ucundaysa)"], ["J4", "MAINT_IN, GND", "Atölye anahtarı (kapalı = atölye modu)"], ["J2", "SWD", "ST-LINK ile yazılım yükleme; tezgâhta 3V3 buradan da verilebilir"]], ["Konnektör", "Pinler", "Ne bağlanır"])}
      <p class="note">GW1 araca hat içi girer: A ile B arasında GW1’den başka bir bağlantı kalmamalı, yoksa saldırgan kartın etrafından dolaşır.</p>
      <h4>Sonlandırma jumper’ı (120 Ω) ne zaman takılır?</h4>
      <ul class="gl"><li>CAN hattı yalnızca <b>iki uçta</b> 120 Ω ile sonlanır. Araçta bu zaten vardır: <b>TN1’de jumper’ı takma.</b></li><li>Tezgâhta TN1 ve bir test düğümü varsa, hattın iki ucundaki kart jumper’ı takar; ortadakiler takmaz.</li><li>GW1’de her port ayrı hat sayılır: o portun hattında GW1 uçtaysa tak, ortadaysa takma.</li><li>Kontrol: güçsüz hatta CANH–CANL arası direnç ≈ 60 Ω olmalı (iki uçta da 120 Ω).</li></ul>
      <h4>Atölye anahtarı ve tamper</h4>
      <ul class="gl"><li><b>Atölye anahtarı etkinken</b> tanı (UDS) oturumları ve yazılım yazma B’ye geçebilir. Etkin değilken GW-06 ve GW-07 bunları düşürür. Servise gittiğinde etkinleştir, dönünce kapat.</li><li><b>Tamper anahtarı</b>: kutu açılır ya da anahtar basılırsa GW1 “kilit modu”na (GW-09) geçer: yalnız B→A akar, A→B tümü düşer.</li></ul></section>

    <section class="gstep"><h3><span class="n">4</span>İlk enerji verme</h3>
      <ol class="gl"><li><b>Gözle bak:</b> lehim köprüsü, ters takılı konnektör, gevşek klemens var mı?</li><li><b>Akım sınırlı güç kaynağı kullan.</b> 12 V’a ayarla, akım sınırını düşük başlat (öneri: 100 mA). Kart sınıra dayanıp voltaj düşüyorsa hemen kes, kısa devre ara.</li><li><b>Önce yalnız TN1.</b> Güç ver: PWR LED’i yanmalı. CAN bağlıysa CAN LED’i trafik geldikçe yanıp söner.</li><li><b>Sonra GW1.</b> PWR yanar. LED anlamları: <span class="mono">PASS</span> kare geçirildi, <span class="mono">BLOCK</span> kare engellendi, <span class="mono">DIAG</span> atölye (tanı) modu etkin.</li><li>Panelde Araç Ağı sekmesini aç. Birkaç saniye içinde TN1 kareleri görünmeli.</li></ol>
      <p class="note">Hiçbir LED yanmıyorsa güç kaynağı polaritesini, sigortayı ve GND bağlantısını kontrol et. LED davranışı kart yazılımına bağlıdır; bu yazılım taslaktır.</p></section>

    <section class="gstep"><h3><span class="n">5</span>Bu panelde ne görürsün?</h3>
      <p><b>TN1 ile:</b> TN1 olayları Wi-Fi üzerinden panele gönderir (<span class="mono">POST /api/guard/events</span>); “Donanım” kartı ve Araç Ağı’nda <span class="mono">source: hardware</span> etiketiyle görünür. Elle denemek için:</p>
      ${code(`curl -X POST http://127.0.0.1:8003/api/guard/events \\\n  -H 'Content-Type: application/json' \\\n  -d '{"t":12.345,"ev":"BLOCK","rule":"GW-04","dir":"A>B","id":"0x244","dlc":8,"data":"00FF00FF00000000"}'`)}
      <p><b>GÖK-PI1 + Raspberry Pi ile:</b> Pi’de CAN HAT’ı etkinleştir (SPI açık; kristal değerini kartındakiyle eşle), sonra:</p>
      ${code(`sudo ip link set can0 up type can bitrate 500000\ncandump can0        # kareler akıyorsa donanım hazır`)}
      <p>Paneli Pi üzerinde çalıştır: <span class="mono">pip install python-can</span>, <span class="mono">config/config.yaml</span> içinde <span class="mono">can.interface_name: "can0"</span> yap (ya da <span class="mono">CAN_LAB_SOCKETCAN=can0</span>), sunucuyu yeniden başlat. “SocketCAN · CAN FD · UDS” sekmesinden bağlan: simülatörün ürettiği kareler artık gerçek hatta da akar; tezgâhtaki bir ECU ya da ikinci bir CAN adaptörü <span class="mono">candump</span> ile görür.</p>
      <p class="note">Köprü iki yönlü: hattan gelen kareler <span class="mono">SOCKETCAN:can0</span> kaynağıyla IDS’e de girer (aynı sekmeden kapatılabilir). SocketCAN köprüsü gerçek donanımda denenmedi.</p></section>

    <section class="gstep warn"><h3><span class="n">!</span>Güvenlik uyarıları</h3>
      <ul class="gl"><li>Yalnızca <b>kendi aracında</b> ya da <b>tezgâhta</b> dene. Başkasının aracına bağlanma.</li><li><b>Sürüş halinde deneme yapma.</b> Frenle, direksiyonla ilgili CAN’e müdahale tehlikelidir.</li><li><b>Fail-closed:</b> GW1 kapanır, güç keser ya da watchdog yeniden başlatırsa B domaini A’dan <b>kopar</b>. Bu bilinçli bir güvenlik kararıdır; ama araç bazı A tarafı verilerini (örn. gösterge) kaybedebilir.</li><li><b>Kartlar henüz üretilmedi ve prototiplenmedi.</b> Şema, yerleşim ve yazılım tasarım aşamasındadır; yukarıdaki LED ve kablolama bilgileri tasarıma göredir, gerçek kartla doğrulanmadı.</li><li>Araç garantisi, sigorta ve yerel mevzuat sorumluluğu sende.</li></ul></section>
    </div>`;
  }

  /* ---- canlı gateway durumu ---- */
  let gst = null;
  async function loadGuard() {
    const host = $("gwLive"); if (!host) return;
    try { gst = await api("GET", "/api/guard/state"); } catch (e) { gst = null; host.innerHTML = placeholder("alert", "Gateway durumu henüz yok", "GET /api/guard/state uç noktası yanıt vermiyor. Arka uç hazır olunca mod, istatistik ve olaylar burada akar. Anahtarlar şimdilik devre dışı."); setSwitches(false); return; }
    setSwitches(true);
    const st = gst.stats || { passed: 0, blocked: 0, by_rule: {} }, tot = st.passed + st.blocked, max = Math.max(1, ...Object.values(st.by_rule || {}));
    const modeTr = { normal: ["ok", "Normal koruma"], workshop: ["warn", "Atölye (tanı açık)"], locked: ["bad", "Kilit (tamper)"] }[gst.mode] || ["", gst.mode];
    host.innerHTML = `<div class="gwtop"><span class="tag ${modeTr[0]}">${modeTr[1]}</span><span class="dim">geçen <b class="mono">${st.passed}</b> · engellenen <b class="mono">${st.blocked}</b> · engelleme oranı <b class="mono">% ${tot ? nf((st.blocked / tot) * 100, 1) : "0,0"}</b></span></div>
      <div class="gwcols"><div><div class="vh2">Kurala göre engellenen</div><div class="bars">${Object.entries(st.by_rule || {}).sort((a, b) => b[1] - a[1]).map(([r, n]) => `<div class="bar"><span class="bl"><b>${esc(r)}</b>${esc(window.VEH_GW_RULE_TR[r] || "")}</span><span class="track"><span class="fill" style="width:${(n / max) * 100}%"></span></span><span class="bv">${n}</span></div>`).join("") || `<div class="dim">Henüz engellenen kare yok.</div>`}</div></div>
      <div><div class="vh2">Son olaylar</div><div class="gwev mono" tabindex="0">${(gst.events || []).slice(-12).reverse().map((e) => `<div class="${e.ev === "BLOCK" ? "bad-t" : ""}">${nf(e.t, 2)} ${esc(e.ev)} ${esc(e.rule || "")} ${esc(e.dir || "")} ${esc(e.id || "")}${e.source === "hardware" ? " [donanım]" : ""}</div>`).join("") || `<span class="dim">Olay yok.</span>`}</div></div></div>`;
    $("swWs").checked = !!gst.workshop_key; $("swTamper").checked = !!gst.tamper;
  }
  function setSwitches(on) { ["swWs", "swTamper"].forEach((i) => { $(i).disabled = !on; }); }
  async function sendMode() {
    try { gst = await api("POST", "/api/guard/mode", { workshop_key: $("swWs").checked, tamper: $("swTamper").checked, clear_lockdown: !$("swTamper").checked }); toast("Gateway modu güncellendi"); loadGuard(); }
    catch (e) { toast("Mod değiştirilemedi: " + e.message, true); loadGuard(); }
  }

  let hwInit = false;
  function initHw() {
    hwInit = true;
    $("p-hw").innerHTML = `
      <div class="notice">${ico("info")}<span><b>Tasarım aşamasında:</b> GÖK-TN1, GÖK-GW1 ve GÖK-PI1 kartları henüz üretilmedi ve prototiplenmedi. Bu sekme tasarımı, kablolamayı ve kartlar gelince panelde göreceklerini anlatır. <a class="link" href="#hw" data-jump="guide">Doğrudan “Nasıl kullanılır?” bölümüne git ↓</a></span></div>
      <div class="panel"><div class="panel-h"><h2>Kartlar</h2><span class="hint-r" id="bNote"></span></div><div class="bgrid" id="bGrid"></div></div>
      <div class="panel"><div class="panel-h"><h2>GÖK-GW1 canlı durum</h2><span class="hint-r">2 sn’de bir yenilenir</span></div>
        <div class="gwsw"><label class="chk"><span class="switch"><input type="checkbox" id="swWs" disabled><i></i></span><span>Atölye anahtarı etkin (tanı serbest)</span></label>
        <label class="chk"><span class="switch"><input type="checkbox" id="swTamper" disabled><i></i></span><span>Tamper (kilit modu)</span></label></div>
        <div id="gwLive"></div></div>
      <div class="panel" id="hwGuide"><div class="panel-h"><h2>Nasıl kullanılır?</h2><span class="hint-r">adım adım kılavuz</span></div>${guideHtml()}
        <h4>Karttaki konnektörler</h4><div id="bConn"></div></div>
      <div class="panel"><div class="panel-h"><h2>Hangi saldırıyı nasıl durdurur?</h2></div><div class="tw"><table class="dense"><thead><tr><th>Saldırı</th><th>GÖK-GW1 kuralları</th><th>Sahada sonuç</th><th>Neden</th></tr></thead><tbody>${Object.entries(window.VEH_ATLAS).map(([k, a]) => { const [c, t] = window.VEH_VERDICT[a.v]; return `<tr><td><b>${esc(atkName(k))}</b></td><td>${a.gw.map((r) => `<span class="rtag mono" title="${esc(window.VEH_GW_RULE_TR[r])}">${r}</span>`).join("") || "—"}</td><td><span class="tag ${c}">${t.replace("GÖK-GW1 sahada ", "")}</span></td><td class="sm">${esc(a.gwText)}</td></tr>`; }).join("")}</tbody></table></div>
        <p class="note">Kural kimlikleri: ${Object.entries(window.VEH_GW_RULE_TR).map(([k, v]) => `<span class="mono">${k}</span> ${v}`).join(" · ")}.</p></div>
      <div class="panel"><div class="panel-h"><h2>Blok diyagram</h2></div><div class="vscroll" tabindex="0" role="group" aria-label="Blok diyagram, dar ekranda yatay kaydırılabilir">${BLOCK_SVG}</div></div>`;
    $("swWs").addEventListener("change", sendMode); $("swTamper").addEventListener("change", sendMode);
    $("p-hw").addEventListener("click", (e) => {
      const v = e.target.closest("[data-view]"); if (v) { const c = v.closest(".bcard"); c.querySelector("[data-img]").src = v.dataset.view; c.querySelector(".bimg").classList.remove("bad"); c.querySelectorAll("[data-view]").forEach((x) => x.setAttribute("aria-pressed", x === v)); return; }
      const t = e.target.closest("[data-topo]"); if (t) { t.parentNode.querySelectorAll("button").forEach((x) => x.setAttribute("aria-checked", x === t)); $("gtn").hidden = t.dataset.topo !== "tn"; $("ggw").hidden = t.dataset.topo !== "gw"; return; }
      if (e.target.closest("[data-jump]")) { e.preventDefault(); $("hwGuide").scrollIntoView({ behavior: RMq() ? "auto" : "smooth" }); }
    });
  }
  const RMq = () => window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  async function loadHw() {
    if (!hwInit) initHw();
    await loadBoards();
    $("bGrid").innerHTML = boards.map(boardCard).join("");
    $("bNote").textContent = boardsOk ? "hw/boards.json" : "Görseller ve BOM henüz yayınlanmadı (hw/boards.json yok); kısa tasarım özeti gösteriliyor";
    const conns = boards.filter((b) => (b.connectors || []).length);
    $("bConn").innerHTML = conns.length ? conns.map((b) => `<h5>${esc(b.name)}</h5>${wt(b.connectors.map((c) => [esc(c.ref), esc(c.name), esc((c.pins || []).join(", ")), esc(c.note_tr || "")]), ["Ref", "Ad", "Pinler", "Not"])}`).join("") : `<p class="dim">Konnektör tablosu hw/boards.json yayınlanınca burada görünür; şimdilik yukarıdaki kablolama tablosuna bak.</p>`;
    await loadGuard();
  }
  let miss = 0;
  setInterval(() => { if (document.body.dataset.tab === "hw" && !document.hidden && (gst || miss++ % 8 === 0)) loadGuard().catch(() => {}); }, 2000);

  window.Hw = { show: loadHw, coverage: loadCoverage };
  $("covRun").addEventListener("click", runCoverage);
  const cur = document.body.dataset.tab; if (cur === "hw") loadHw(); if (cur === "cov") loadCoverage();
})();
