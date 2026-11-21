// GÖK CAN-IDS Lab — sanal test tezgâhı istemcisi (saf JS, harici istek yok; yazı tipleri hariç).
// Arayüz yalnızca Türkçedir. I18N yalnızca gösterge başlıklarını tutar (EN sözlüğü ileride dil seçimi için bırakıldı).

const I18N = {
  tr: { speedometer: "HIZ GÖSTERGESİ", tachometer: "MOTOR DEVRİ", brake_g: "FREN BASINCI", temp_g: "SOĞUTMA SUYU", steer_g: "DİREKSİYON AÇISI" },
  en: { speedometer: "SPEEDOMETER", tachometer: "TACHOMETER", brake_g: "BRAKE PRESSURE", temp_g: "COOLANT", steer_g: "STEERING ANGLE" },
};
const lang = "tr";
const t = (k) => (I18N[lang] && I18N[lang][k]) || k;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nf = (n, d = 1, g = true) => (Number.isFinite(+n) ? (+n).toLocaleString("tr-TR", { minimumFractionDigits: d, maximumFractionDigits: d, useGrouping: g }) : "—");
const pctf = (v, d = 1) => (v == null ? "—" : nf(v * 100, d) + " %");
const ico = (n) => `<svg class="ico"><use href="#i-${n}"/></svg>`;

const SEV_TR = { LOW: "Düşük", MEDIUM: "Orta", HIGH: "Yüksek", CRITICAL: "Kritik" };
const CAT_TR = { spoofing: "Sahtecilik", replay: "Tekrar oynatma", dos: "Hizmet engelleme", fuzzing: "Fuzzing", tampering: "Kurcalama", injection: "Enjeksiyon", diagnostic: "Tanı (UDS)" };
const ATK_TR = {
  speed_spoof: ["Hız sahteciliği", "Gerçek hızın çok üstünde sahte hız kareleri (0x244) basılır; gösterge yanlış hızı okur."],
  speed_spoof_stealth: ["Hız maskeleme", "ABS susturulur, yerine yavaş yavaş kayan sahte hız verilir. Periyot doğru, sıçrama yok: kare katmanları görmez, yalnızca fizik analizi yakalar."],
  spoof_id: ["Keyfi ID sahteciliği", "Seçilen bir CAN ID’sine saldırgan yükü yüksek hızda yollanır."],
  replay: ["Kaydet ve tekrar oynat", "Gerçek motor, fren ve hız kareleri kaydedilir, sonra olduğu gibi tekrar yollanır."],
  flooding: ["Taşkın (DoS)", "En yüksek öncelikli ID 0x000 ile bus doyurulur; meşru kareler arbitrasyonu kaybeder."],
  fuzzing: ["CAN fuzzing", "Rastgele ID ve yüklerle ECU’lar zorlanır, beklenmeyen davranış aranır."],
  counter_crc_desync: ["Fren sayaç / CRC kurcalama", "Fren mesajının (0x200) canlı sayaç ve CRC alanları bozulur."],
  unauthorized_id: ["Yabancı tanı ID’si", "DBC’de bulunmayan 0x6F1 ID’si ile kare enjekte edilir."],
  uds_diagnostic_attack: ["UDS oturumu ve kaba kuvvet", "Tanı oturumu açılır, SecurityAccess anahtarı sürekli denenir."],
  uds_reflash: ["Çok çerçeveli UDS reflash", "UDS 0x34 ile ISO-TP üzerinden yazılım yazma girişimi."],
  headlight_can_injection_unlock: ["Kapı kilidi enjeksiyonu", "Gövde verisi yoluna kapı kilidi açma kareleri (0x320) enjekte edilir."],
  brake_spoof: ["Sahte fren basıncı", "Gaz sıfırken sahte yüksek fren basıncı kareleri yollanır."],
};
const atkName = (id, fb) => (ATK_TR[id] ? ATK_TR[id][0] : fb || id);
const LAYER_TR = {
  "CAN-IDS-01": ["ID beyaz liste", "DBC’de olmayan ID’leri yakalar"], "CAN-IDS-02": ["Zamanlama sapması", "Periyodu bozan kareleri yakalar"],
  "CAN-IDS-03": ["Kinematik sıçrama", "Fiziksel olarak imkânsız sinyal sıçramaları"], "CAN-IDS-04": ["Sayaç / CRC / SecOC", "Canlı sayaç ve doğrulama alanları"],
  "CAN-IDS-05": ["Bus yükü taşkını", "Anormal kare yoğunluğu"], "CAN-IDS-06": ["Tekrar penceresi", "Birebir tekrarlanan kare dizileri"],
  "CAN-IDS-07": ["ISO-TP / UDS güvenlik duvarı", "Riskli tanı servisleri ve çok çerçeveli aktarım"],
};
const VBA_TR = {
  "VBA-01": "Fren basılı ve gaz sıfırken ivmelenme", "VBA-02": "Hız, devir ve vitesle uyumsuz", "VBA-03": "Fren basıncı var, yavaşlama yok",
  "VBA-04": "Gerçekçi olmayan direksiyon hızı", "VBA-05": "Gösterge hızı tekerlek hızından farklı", "VBA-06": "Motor sıcaklığında ani sıçrama",
};
const RULE_TYPE_TR = { signal_threshold: "Sinyal eşiği", signal_delta: "Sinyal değişimi", rate: "Kare hızı", payload_match: "Yük deseni", dlc_mismatch: "DLC uyumsuzluğu" };
const ruleTitle = (a) => (LAYER_TR[a.rule_id] ? LAYER_TR[a.rule_id][0] : VBA_TR[a.rule_id] || a.rule_name || a.rule_id);
const idHue = (id) => (Math.imul(id | 0, 137) >>> 0) % 360;

function toast(msg, err) {
  const el = $("toast"); el.textContent = msg; el.className = "toast show" + (err ? " err" : "");
  clearTimeout(toast._t); toast._t = setTimeout(() => (el.className = "toast"), err ? 5000 : 2200);
}
async function api(method, url, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(url, opt);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) { const d = data && data.detail; throw new Error(typeof d === "string" ? d : JSON.stringify(d || data)); }
  return data;
}
const act = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

function setTheme(th) {
  document.documentElement.dataset.theme = th; try { localStorage.setItem("canlab.theme", th); } catch (e) {}
  $("themeBtn").innerHTML = ico(th === "dark" ? "sun" : "moon"); $("themeBtn").title = th === "dark" ? "Açık temaya geç" : "Koyu temaya geç";
}
(function initTheme() {
  let th = null; try { th = localStorage.getItem("canlab.theme"); } catch (e) {}
  if (th !== "light" && th !== "dark") th = "dark";   // varsayılan: grafit siyahı; açık tema düğmeyle seçilir
  setTheme(th);
})();

const polar = (r, deg) => [150 + r * Math.cos((deg * Math.PI) / 180), 150 + r * Math.sin((deg * Math.PI) / 180)];
const arcPath = (r, a0, a1) => { const [x0, y0] = polar(r, a0), [x1, y1] = polar(r, a1); return `M${x0.toFixed(2)} ${y0.toFixed(2)}A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`; };

function buildDial(host, c) {
  const S = c.start ?? 135, W = c.sweep ?? 270, span = c.max - c.min;
  const ang = (v) => S + ((Math.max(c.min, Math.min(c.max, v)) - c.min) / span) * W;
  const zoneOf = (v) => (c.zones || []).find((z) => v >= z.from && v <= z.to);
  let h = `<svg class="dial" viewBox="0 0 300 300" role="img" aria-label="${esc(c.title)}"><circle class="face" cx="150" cy="150" r="144"/>`;
  (c.zones || []).forEach((z) => { h += `<path class="zone ${z.cls}" d="${arcPath(134, ang(z.from), ang(z.to))}"/>`; });
  const n = Math.round(span / c.minor), per = Math.round(c.major / c.minor), lblEvery = Math.round((c.lbl || c.major) / c.minor);
  for (let i = 0; i <= n; i++) {
    const v = c.min + i * c.minor, a = ang(v), maj = i % per === 0;
    const [x0, y0] = polar(126, a), [x1, y1] = polar(maj ? 108 : 117, a);
    h += `<line class="tick${maj ? " maj" : ""}" x1="${x0.toFixed(1)}" y1="${y0.toFixed(1)}" x2="${x1.toFixed(1)}" y2="${y1.toFixed(1)}"/>`;
    if (i % lblEvery === 0) { const [lx, ly] = polar(c.lr || 88, a); h += `<text class="lbl" x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" font-size="${c.lf || 16}">${nf(v / (c.div || 1), 0)}</text>`; }
  }
  if (c.ghost || c.wheel) h += `<polygon class="ghost" points="262,150 276,143 276,157"/>`;
  if (c.wheel) h += `<g class="wheel"><circle cx="150" cy="150" r="40"/><path d="M112 146H188M150 150V190"/><path class="mk" d="M150 106V118"/></g>`;
  else {
    const nl = c.nl || 112;
    h += `<polygon class="needle" points="132,146 ${150 + nl},148.6 ${150 + nl},151.4 132,154"/><circle class="hub" cx="150" cy="150" r="11"/>`;
  }
  if (!c.noval) {
    h += `<text class="ttl" x="150" y="198" font-size="14" letter-spacing=".08em">${esc(c.title)}</text><text class="val" x="150" y="252" font-size="${c.vf || 44}">0</text><text class="unit" x="150" y="276" font-size="16">${esc(c.unit)}</text>`;
  }
  host.insertAdjacentHTML("afterbegin", h + "</svg>");
  const svg = host.querySelector("svg.dial"), q = (s) => svg.querySelector(s);
  const needle = q(".needle"), val = q(".val"), ghost = q(".ghost"), wheel = q(".wheel");
  let lastCls = "";
  return {
    set(v, o = {}) {
      v = +v || 0; const z = zoneOf(v), cls = z ? z.cls : "";
      const a = ang(v), rot = (el, deg) => { el.style.transform = `rotate(${deg}deg)`; };
      if (needle) { rot(needle, a.toFixed(1)); if (cls !== lastCls) needle.setAttribute("class", "needle " + cls); }
      if (val) { val.textContent = nf(v, c.dec || 0, false); if (cls !== lastCls) val.setAttribute("class", "val " + cls); }
      lastCls = cls;
      if (wheel) rot(wheel, v.toFixed(1));
      if (ghost) {
        const g = o.ghost ?? v; rot(ghost, ang(g).toFixed(1));
        ghost.setAttribute("class", "ghost" + (o.ghostOff ? " off" : ""));
        ghost.style.display = c.wheel || o.ghost != null ? "" : "none";
      }
    },
  };
}

// Pano göstergeleri
const DIALS = {};
function buildCluster() {
  DIALS.speed = buildDial($("dialSpeed"), { title: "HIZ", unit: "km/h", min: 0, max: 240, major: 20, minor: 10, lbl: 40, zones: [{ from: 200, to: 240, cls: "alarm" }], ghost: true });
  DIALS.rpm = buildDial($("dialRpm"), { title: "DEVİR  ×1000", unit: "dev/dk", min: 0, max: 8000, major: 1000, minor: 500, lbl: 1000, div: 1000, zones: [{ from: 5500, to: 6500, cls: "warn" }, { from: 6500, to: 8000, cls: "alarm" }] });
  const mini = (id, cfg, label, unit, sub) => {
    const el = $(id); el.innerHTML = `<div class="dial-host" style="width:128px;flex:none"></div><div class="mini-t"><div class="l">${label}</div><div><span class="n">0</span><span class="u">${unit}</span></div><div class="s">${sub}</div></div>`;
    const d = buildDial(el.querySelector(".dial-host"), { ...cfg, noval: true, lf: 22, lr: 84 }); d.n = el.querySelector(".n"); d.dec = cfg.dec || 0; return d;
  };
  DIALS.brake = mini("dialBrake", { title: t("brake_g"), min: 0, max: 120, major: 40, minor: 10, lbl: 40, dec: 1, zones: [{ from: 100, to: 120, cls: "alarm" }], nl: 100 }, "Fren basıncı", "bar", "CAN 0x200");
  DIALS.temp = mini("dialTemp", { title: t("temp_g"), min: 60, max: 130, major: 10, minor: 5, lbl: 20, dec: 1, zones: [{ from: 100, to: 110, cls: "warn" }, { from: 110, to: 130, cls: "alarm" }], nl: 100 }, "Soğutma suyu sıcaklığı", "°C", "CAN 0x180");
  DIALS.steer = mini("dialSteer", { title: t("steer_g"), min: -180, max: 180, major: 90, minor: 45, lbl: 90, dec: 1, wheel: true, lr: 78, lf: 20 }, "Direksiyon açısı", "°", "CAN 0x0C4");
  DIALS.atk = buildDial($("dialSpeedAtk"), { title: "HIZ", unit: "km/h", min: 0, max: 240, major: 40, minor: 20, lbl: 80, ghost: true, vf: 52, lf: 20, lr: 84, zones: [{ from: 200, to: 240, cls: "alarm" }] });
  $("gearBox").innerHTML = ["N", "1", "2", "3", "4", "5", "6"].map((g) => `<span>${g}</span>`).join("");
  $("lamps").innerHTML = [["gauge", "Hız aşımı"], ["disc", "Fren"], ["thermo", "Sıcaklık"]].map(([i, l]) => `<div class="lamp">${ico(i)}<span>${l}</span></div>`).join("");
}
let lastVeh = null;
function paintVehicle(v) {
  lastVeh = v;
  const clu = v.cluster_speed_kmh, diff = Math.abs((clu ?? 0) - (v.speed_kmh || 0)), off = diff > 10;
  DIALS.speed.set(v.speed_kmh || 0, { ghost: clu, ghostOff: off });
  DIALS.rpm.set(v.engine_rpm || 0);
  [["brake", v.brake_bar || 0], ["temp", v.engine_temp || 60], ["steer", v.steering_deg || 0]].forEach(([k, x]) => { DIALS[k].set(x); DIALS[k].n.textContent = nf(x, DIALS[k].dec); });
  $("clusterSpd").textContent = nf(clu, 0) + " km/h"; $("trueSpd").textContent = nf(v.speed_kmh, 0) + " km/h"; $("odoVal").textContent = nf(v.odometer_km, 1) + " km";
  $("spoofNote").hidden = !off;
  const gs = $("gearBox").children; for (let i = 0; i < gs.length; i++) gs[i].className = i === v.gear ? "on" + (v.shifting ? " shift" : "") : "";
  [...$("lamps").children].forEach((e, i) => e.classList.toggle("on", !!(v.lamps & (1 << i))));
  if (document.body.dataset.tab === "attack" || !$("p-attack").hidden) {
    DIALS.atk.set(v.speed_kmh || 0, { ghost: clu, ghostOff: off });
    $("aTrue").textContent = nf(v.speed_kmh, 0) + " km/h"; $("aClu").textContent = nf(clu, 0) + " km/h";
    const e = $("aErr"); e.textContent = nf(diff, 0) + " km/h"; e.className = "mono" + (off ? " bad" : "");
  }
  const sc = v.scenario || "normal"; $("scenarioVal").textContent = sc === "normal" ? "Normal sürüş" : atkName(sc);
}

const loadHist = []; // [wallMs, %]
const WINDOW_MS = 30000;
function drawLoad() {
  const el = $("loadChart"), W = Math.max(280, el.clientWidth), H = el.clientHeight || 220, p = { l: 44, r: 12, t: 12, b: 24 };
  if (!loadHist.length) return;
  const now = loadHist[loadHist.length - 1][0], t0 = now - WINDOW_MS;
  const peak = Math.max(...loadHist.map((x) => x[1]), 1), ymax = [10, 20, 30, 50, 100].find((s) => s >= peak * 1.25) || 100;
  const X = (ts) => p.l + ((ts - t0) / WINDOW_MS) * (W - p.l - p.r), Y = (v) => p.t + (1 - v / ymax) * (H - p.t - p.b);
  const pts = loadHist.filter((x) => x[0] >= t0).map((x) => `${X(x[0]).toFixed(1)},${Y(x[1]).toFixed(1)}`);
  if (pts.length < 2) return;
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Bus yükü, son 30 saniye">`;
  const step = ymax / 4;
  for (let i = 0; i <= 4; i++) { const v = step * i; s += `<line class="grid" x1="${p.l}" x2="${W - p.r}" y1="${Y(v).toFixed(1)}" y2="${Y(v).toFixed(1)}"/><text class="axl" x="${p.l - 8}" y="${(Y(v) + 4).toFixed(1)}" text-anchor="end">${nf(v, ymax < 20 ? 1 : 0)}</text>`; }
  [[-30, "−30 sn"], [-20, "−20"], [-10, "−10"], [0, "şimdi"]].forEach(([d, l]) => { const x = X(now + d * 1000); s += `<text class="axl" x="${x.toFixed(1)}" y="${H - 6}" text-anchor="${d === 0 ? "end" : d === -30 ? "start" : "middle"}">${l}</text>`; });
  const last = pts[pts.length - 1].split(",");
  s += `<polygon class="area" points="${pts[0].split(",")[0]},${Y(0)} ${pts.join(" ")} ${last[0]},${Y(0)}"/><polyline class="ln" points="${pts.join(" ")}"/>`;
  if (75 <= ymax) s += `<line class="thr" x1="${p.l}" x2="${W - p.r}" y1="${Y(75).toFixed(1)}" y2="${Y(75).toFixed(1)}"/><text class="thr-l" x="${W - p.r - 4}" y="${(Y(75) - 6).toFixed(1)}" text-anchor="end">Eşik %75</text>`;
  else s += `<text class="thr-l" x="${W - p.r - 4}" y="${p.t + 12}" text-anchor="end">Doygunluk eşiği %75 bu ölçeğin üstünde</text>`;
  el.innerHTML = s + "</svg>";
}

let alertTotal = 0, lastAlert = null; const alertArrivals = [];
const calmHtml = () => `<div class="calm">${ico("shield")}<b>Sistem normal</b><span>Şu ana kadar tespit edilen anomali yok. Saldırı Lab’dan bir senaryo başlatınca alarmlar burada akar.</span>
  <div class="chips">${Object.keys(LAYER_TR).map((k) => `<span>K${k.slice(-2)}</span>`).join("")}<span>VBA</span></div></div>`;
function alertHtml(a) {
  const sev = a.severity || "LOW";
  return `<div class="al ${esc(sev)}"><i></i><div><div class="al-h"><span class="al-t">${esc(ruleTitle(a))}</span><span class="al-s">${esc(SEV_TR[sev] || sev)}</span></div>
    <div class="al-m"><span class="mono">${nf(a.timestamp, 1)} sn</span><span class="mono">${esc(a.rule_id)}</span>${a.hex_id ? `<span class="mono">${esc(a.hex_id)} ${esc(a.message_name || "")}</span>` : ""}${a.observed_value ? `<span class="mono">${esc(a.observed_value)}</span>` : ""}</div>
    ${a.evidence ? `<div class="al-e">${esc(a.evidence)}</div>` : ""}</div></div>`;
}
function feedInsert(feedId, list, max) {
  const feed = $(feedId); if (feed.querySelector(".calm")) feed.innerHTML = "";
  feed.insertAdjacentHTML("afterbegin", list.map(alertHtml).join(""));
  while (feed.children.length > max) feed.lastChild.remove();
}
function pushAlerts(list, fresh = true) {
  if (!list || !list.length) return;
  const show = list.slice(-6).reverse();
  feedInsert("alertFeed", show, 40); feedInsert("alertFeedAtk", show, 20);
  alertTotal += list.length; $("alertCountBadge").textContent = alertTotal; $("atkAlertCount").textContent = alertTotal;
  if (fresh) { lastAlert = { a: list[list.length - 1], at: Date.now() }; list.forEach(() => alertArrivals.push(Date.now())); }
  if (list.some((a) => String(a.rule_id).startsWith("VBA")) && !$("p-behavior").hidden) loadBehavior().catch(() => {});
  if (window.Veh && fresh) Veh.onAlerts(list);
  updateAlarmBand();
}
function updateAlarmBand() {
  const now = Date.now(); while (alertArrivals.length && alertArrivals[0] < now - 30000) alertArrivals.shift();
  const n = alertArrivals.length; $("alarmCount").textContent = n; $("alarmSeg").classList.toggle("alarm", n > 0);
  $("alertCountBadge").classList.toggle("hot", alertTotal > 0 && n > 0);
  const band = $("alarmBand");
  if (lastAlert && now - lastAlert.at < 30000) {
    const a = lastAlert.a; band.className = "alarmband sev-" + (a.severity || "LOW");
    band.querySelector("svg").innerHTML = `<use href="#i-alert"/>`;
    $("alarmBandText").textContent = `${SEV_TR[a.severity] || a.severity} · ${ruleTitle(a)}${a.hex_id ? " · " + a.hex_id : ""}${a.message_name ? " " + a.message_name : ""} (son 30 sn: ${n} alarm)`;
    $("alarmBandAge").textContent = `${Math.round((now - lastAlert.at) / 1000)} sn önce`;
  } else {
    band.className = "alarmband"; band.querySelector("svg").innerHTML = `<use href="#i-shield"/>`;
    $("alarmBandText").textContent = alertTotal ? `Aktif alarm yok — oturumda toplam ${alertTotal} alarm görüldü.` : "Alarm yok — 7 IDS katmanı ve davranış analizi izliyor."; $("alarmBandAge").textContent = "";
  }
}
setInterval(updateAlarmBand, 1000);

let ws = null, paused = false;
function connectWebSocket() {
  ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/telemetry`);
  ws.onopen = () => { $("wsState").textContent = "Canlı"; $("wsDot").className = "dot live"; };
  ws.onmessage = (ev) => { try { onTelemetry(JSON.parse(ev.data)); } catch (e) { console.error(e); } };
  ws.onclose = () => { $("wsState").textContent = "Yeniden bağlanıyor"; $("wsDot").className = "dot bad"; setTimeout(connectWebSocket, 2000); };
}
let seeded = false;
function onTelemetry(p) {
  window.LAST_TEL = { v: p.vehicle, at: Date.now() };   // 3B Araç sekmesi ayrı istek atmadan bunu kullanır
  paintVehicle(p.vehicle);
  const bus = p.bus || {}, load = bus.current_bus_load_pct || 0, nowMs = Date.now();
  if (!seeded && bus.load_history) { seeded = true; const n = bus.load_history.length; bus.load_history.forEach((v, i) => loadHist.push([nowMs - (n - i) * 40, v])); }
  loadHist.push([nowMs, load]); while (loadHist.length && loadHist[0][0] < nowMs - WINDOW_MS - 1000) loadHist.shift();
  const m = Math.floor(p.timestamp / 60), s = p.timestamp - m * 60; $("simClock").textContent = `${String(m).padStart(2, "0")}:${nf(s, 1).padStart(4, "0")}`;
  $("busLoadVal").textContent = `% ${nf(load, 1)}`; $("loadNow").textContent = `% ${nf(load, 1)}`;
  $("totalFramesVal").textContent = (bus.total_frames_sent || 0).toLocaleString("tr-TR"); $("loadPeak").textContent = `% ${nf(bus.peak_load_pct, 1)}`;
  const hb = $("busHealthBadge"); hb.textContent = load > 75 ? "Doygun" : load > 40 ? "Yoğun" : "Normal"; hb.className = "tag " + (load > 75 ? "bad" : load > 40 ? "warn" : "");
  if (!$("p-dash").hidden) drawLoad();
  pushAlerts(p.new_alerts);
  if (!$("p-bus").hidden) paintBusStats(bus);
  if (!$("p-attack").hidden) { paintAttackStatus(p.attacks); $("aLoad").textContent = `% ${nf(load, 1)}`; }
}
window.addEventListener("resize", () => { if (!$("p-dash").hidden) drawLoad(); });

const TABS = ["dash", "veh", "car3d", "bus", "attack", "atlas", "behavior", "dbc", "rules", "bench", "cov", "hw", "integ"];
const ALIAS = { pano: "dash", dash: "dash", bus: "bus", saldiri: "attack", attack: "attack", davranis: "behavior", behavior: "behavior", dbc: "dbc", kural: "rules", rules: "rules", benchmark: "bench", bench: "bench", entegrasyon: "integ", integ: "integ", arac: "veh", veh: "veh", car3d: "car3d", arac3b: "car3d", atlas: "atlas", kapsam: "cov", cov: "cov", donanim: "hw", hw: "hw" };
let hashArg = "";
function parseHash() { const [a, b] = location.hash.slice(1).split("/"); return [ALIAS[(a || "").toLowerCase()] || "dash", b || ""]; }
function showTab(name, arg = "") {
  hashArg = arg; document.body.dataset.tab = name;
  TABS.forEach((n) => { $("p-" + n).hidden = n !== name; $("t-" + n).setAttribute("aria-selected", n === name); $("t-" + n).tabIndex = n === name ? 0 : -1; });
  try { history.replaceState(null, "", "#" + name + (arg ? "/" + arg : "")); } catch (e) {}
  const run = { dash: () => { drawLoad(); pollTrace(); }, bus: loadBus, attack: loadAttack, behavior: loadBehavior, dbc: loadDbc, rules: loadRules, bench: loadBench, integ: loadInteg, veh: () => window.Veh && Veh.show(), car3d: () => window.Car3D && Car3D.show(), atlas: () => window.Veh && Veh.atlas(), cov: () => window.Hw && Hw.coverage(), hw: () => window.Hw && Hw.show() }[name];
  Promise.resolve(run && run()).catch((e) => toast(e.message, true));
  window.scrollTo(0, 0);
}
$("tabs").addEventListener("click", (e) => { const b = e.target.closest("button[role=tab]"); if (b) showTab(b.id.slice(2)); });
$("tabs").addEventListener("keydown", (e) => {
  const i = TABS.findIndex((n) => $("t-" + n).getAttribute("aria-selected") === "true");
  const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0; if (!d) return;
  const n = TABS[(i + d + TABS.length) % TABS.length]; showTab(n); $("t-" + n).focus();
});
document.addEventListener("click", (e) => { const a = e.target.closest("[data-goto]"); if (a) { e.preventDefault(); showTab(a.dataset.goto); } });
window.addEventListener("hashchange", () => { const [n, a] = parseHash(); if (document.body.dataset.tab !== n || a !== hashArg) showTab(n, a); });

let drvMode = "auto";
async function sendDriver() {
  const tg = $("drvTarget").value;
  $("manualCtl").style.opacity = drvMode === "manual" ? 1 : 0.6;
  $("oThr").textContent = `${$("drvThr").value} %`; $("oBrk").textContent = `${$("drvBrk").value} %`; $("oStr").textContent = `${$("drvStr").value}°`;
  await api("POST", "/api/bench/driver", { mode: drvMode, target_speed_kmh: tg === "" ? null : +tg, throttle_pct: +$("drvThr").value, brake_pct: +$("drvBrk").value, steering_deg: +$("drvStr").value });
}
document.querySelectorAll(".seg-ctl button").forEach((b) => b.addEventListener("click", act(() => {
  drvMode = b.dataset.mode; document.querySelectorAll(".seg-ctl button").forEach((x) => x.setAttribute("aria-checked", x === b)); return sendDriver();
})));
["drvTarget", "drvThr", "drvBrk", "drvStr"].forEach((id) => $(id).addEventListener("input", act(sendDriver)));
$("pauseBtn").addEventListener("click", act(async () => {
  paused = !paused; await api("POST", `/api/bench/pause?pause=${paused}`);
  $("pauseBtn").innerHTML = ico(paused ? "play" : "pause"); $("pauseBtn").title = $("pauseBtn").ariaLabel = paused ? "Benzetimi sürdür" : "Benzetimi duraklat";
}));
$("stopBtn").addEventListener("click", act(async () => { await api("POST", "/api/attacks/stop"); toast("Tüm saldırılar durduruldu"); if (!$("p-attack").hidden) loadAttack(); }));
$("themeBtn").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));

let dbcCache = null, selTrace = null, frozen = false, traceRows = [];
async function ensureDbc() { if (!dbcCache) { const d = await api("GET", "/api/dbc"); dbcCache = d.messages; } return dbcCache; }
const trKey = (r) => r.timestamp + ":" + r.arbitration_id;
function traceRow(r) {
  const sig = Object.entries(r.signals || {}).map(([k, v]) => `${k}=${v}`).join("  ");
  const cls = (r.attack ? "atk-row " : "") + (selTrace && selTrace.k === trKey(r) ? "sel" : "");
  return `<tr class="${cls}" data-k="${trKey(r)}" title="${esc(sig || r.data_hex)}"><td>${nf(r.timestamp, 4)}</td><td class="idc" style="--h:${idHue(r.arbitration_id)}">${esc(r.hex_id)}${r.is_fd ? " FD" : ""}</td><td>${esc(r.name || "—")}</td><td class="r">${r.dlc}</td><td>${esc(r.data_hex)}</td><td class="sigc">${esc(sig)}</td><td class="r">${nf(r.latency_us, 0)} µs${r.arb_losses ? ` <span class="bad-t">−${r.arb_losses}</span>` : ""}</td><td>${esc(r.source)}</td></tr>`;
}
async function pollTrace() {
  try {
    if (!$("p-dash").hidden) {
      const rows = await api("GET", "/api/bus/trace?limit=10");
      $("miniTrace").innerHTML = rows.reverse().map((r) => `<tr class="${r.attack ? "atk-row" : ""}"><td>${nf(r.timestamp, 3)}</td><td class="idc" style="--h:${idHue(r.arbitration_id)}">${esc(r.hex_id)}</td><td>${esc(r.source)}</td><td>${esc(r.data_hex)}</td></tr>`).join("");
    } else if (!$("p-bus").hidden && !frozen) {
      const f = $("traceFilter").value.trim().toLowerCase().replace(/^0x/, "").replace(/^0+/, "");
      let rows = await api("GET", "/api/bus/trace?limit=300");
      if (f) rows = rows.filter((r) => r.hex_id.toLowerCase().replace("0x", "").replace(/^0+/, "").includes(f));
      traceRows = rows.slice(-120).reverse(); $("traceBody").innerHTML = traceRows.map(traceRow).join("");
    }
  } catch (e) {}
}
$("traceBody").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-k]"); if (!tr) return;
  const r = traceRows.find((x) => trKey(x) === tr.dataset.k); if (!r) return;
  selTrace = { k: tr.dataset.k, r }; $("traceBody").querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel")); tr.classList.add("sel"); paintTraceDetail(r);
});
async function paintTraceDetail(r) {
  const msgs = await ensureDbc().catch(() => []); const m = msgs.find((x) => x.id_dec === r.arbitration_id);
  const unit = (n) => ((m && m.signals.find((s) => s.name === n)) || {}).unit || "";
  const sig = Object.entries(r.signals || {});
  $("traceDetail").innerHTML = `<h3 style="color:hsl(${idHue(r.arbitration_id)} 60% var(--idl))">${esc(r.hex_id)}</h3><div>${esc(r.name || "DBC’de tanımsız kare")}</div>
    <dl class="kv"><dt>Kaynak</dt><dd>${esc(r.source)}</dd><dt>Zaman</dt><dd>${nf(r.timestamp, 4)} sn</dd><dt>DLC</dt><dd>${r.dlc}${r.is_fd ? " (CAN FD)" : ""}</dd><dt>Kuyruk gecikmesi</dt><dd>${nf(r.latency_us, 0)} µs</dd><dt>Arbitrasyon kaybı</dt><dd>${r.arb_losses || 0}</dd><dt>Durum</dt><dd>${r.attack ? "Saldırı karesi" : r.alerted ? "Alarm üretti" : "Meşru"}</dd></dl>
    <div class="mutedt" style="font-size:12px">Ham veri</div><div class="bytes">${r.data_hex.split(" ").map((b) => `<span>${esc(b)}</span>`).join("")}</div>
    ${sig.length ? sig.map(([k, v]) => `<div class="sigbar"><span>${esc(k)}</span><b>${nf(v, Number.isInteger(+v) ? 0 : 2)} <small class="mutedt" style="font:12px var(--sans)">${esc(unit(k))}</small></b></div>`).join("") : `<div class="empty-s">Çözümlenecek sinyal yok.</div>`}`;
}
function paintBusStats(b) {
  const L = b.current_bus_load_pct ?? b.load_pct, items = [["Yük", `% ${nf(L)}`, L > 75 ? "bad" : L > 40 ? "warn" : ""], ["Tepe yük", `% ${nf(b.peak_load_pct)}`], ["Toplam kare", (b.total_frames_sent ?? b.total_frames ?? 0).toLocaleString("tr-TR")],
    ["Arbitrasyon kaybı", b.arbitration_losses ?? 0], ["Düşen kare", b.dropped_frames ?? 0, b.dropped_frames ? "bad" : ""], ["Ort. gecikme", `${nf(b.avg_latency_us, 0)} µs`], ["Azami gecikme", `${nf(b.max_latency_us, 0)} µs`], ["Bit hızı", `${b.bitrate_kbps ?? 500} kbit/s`]];
  $("busStats").innerHTML = items.map(([k, v, c]) => `<div class="stat ${c || ""}"><span class="k">${k}</span><b>${esc(v)}</b></div>`).join("");
}
async function loadBus() {
  const st = await api("GET", "/api/bench/state"); paintBusStats(st.bus); pollTrace(); ensureDbc().catch(() => {});
  $("ecuBody").innerHTML = st.ecus.map((e) => `<tr><td title="${esc(e.description)}"><b>${esc(e.name)}</b></td><td class="mono">${e.messages.map((m) => `${esc(m.id)}·${m.period_ms}ms`).join("  ")}</td><td class="r mono">${e.tx}</td><td class="r mono">${e.arb_losses ?? 0}</td><td class="r mono">${e.dropped ?? 0}</td>
    <td><label class="sw chk"><span class="switch"><input type="checkbox" data-ecu="${esc(e.name)}" ${e.online ? "checked" : ""} aria-label="${esc(e.name)} çevrimiçi"><i></i></span><span>${e.online ? "Çevrimiçi" : "Çevrimdışı"}</span></label></td></tr>`).join("");
}
$("ecuBody").addEventListener("change", act(async (e) => { const n = e.target.dataset.ecu; if (n) { await api("POST", `/api/bench/ecu/${n}/online?online=${e.target.checked}`); loadBus(); } }));
$("traceFilter").addEventListener("input", pollTrace);
$("traceFreeze").addEventListener("click", () => { frozen = !frozen; const b = $("traceFreeze"); b.setAttribute("aria-pressed", frozen); b.querySelector("span").textContent = frozen ? "Sürdür" : "Dondur"; b.querySelector("use").setAttribute("href", frozen ? "#i-play" : "#i-pause"); });

let catalog = [], selAttack = null, activeIds = new Set();
function cardHtml(a) {
  const [n, d] = ATK_TR[a.id] || [a.name, a.description];
  const lay = a.expected_layers.length ? "Beklenen: " + a.expected_layers.map((l) => "K" + l.slice(-2)).join(" · ") : "Kare katmanı yok · yalnızca fizik analizi";
  return `<div class="card" role="radio" tabindex="0" aria-checked="false" data-id="${esc(a.id)}"><div class="c-top"><span class="cat">${esc(CAT_TR[a.category] || a.category)}</span><span class="tag" hidden>Çalışıyor</span></div>
    <div class="c-name">${esc(n)}</div><div class="c-desc">${esc(d)}</div><div class="c-lay">${esc(lay)}</div>
    <div class="c-act"><button class="btn primary sm" type="button" data-run="${esc(a.id)}">${ico("play")}<span>Başlat</span></button><button class="btn sm" type="button" data-stop hidden>${ico("square")}<span>Durdur</span></button></div></div>`;
}
async function loadAttack() {
  if (!catalog.length) {
    catalog = await api("GET", "/api/attacks");
    $("attackList").innerHTML = catalog.map(cardHtml).join("");
    selectAttack(ATK_TR[hashArg] ? hashArg : catalog[0].id);
  } else if (ATK_TR[hashArg]) selectAttack(hashArg);
  if (lastVeh) paintVehicle(lastVeh);
  paintAttackStatus(await api("GET", "/api/attacks/status"));
}
function selectAttack(id) {
  selAttack = catalog.find((a) => a.id === id) || catalog[0];
  document.querySelectorAll(".card").forEach((b) => b.setAttribute("aria-checked", b.dataset.id === selAttack.id));
  $("atkParams").value = JSON.stringify(selAttack.defaults, null, 1);
}
async function runAttack(id) {
  const a = catalog.find((x) => x.id === id); let params = a.defaults;
  if (selAttack && selAttack.id === id) { try { params = JSON.parse($("atkParams").value || "{}"); } catch (e) { throw new Error("Parametreler geçerli JSON değil"); } }
  await api("POST", "/api/attacks/run", { attack: id, duration: +$("atkDur").value, params, combine: $("atkCombine").checked });
  toast(`${atkName(id, a.name)} başlatıldı`); paintAttackStatus(await api("GET", "/api/attacks/status"));
}
$("attackList").addEventListener("click", act(async (e) => {
  const run = e.target.closest("[data-run]"); if (run) { selectAttack(run.dataset.run); return runAttack(run.dataset.run); }
  if (e.target.closest("[data-stop]")) { await api("POST", "/api/attacks/stop"); return loadAttack(); }
  const c = e.target.closest(".card"); if (c) selectAttack(c.dataset.id);
}));
$("attackList").addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target.classList.contains("card")) { e.preventDefault(); selectAttack(e.target.dataset.id); } });
$("atkStop").addEventListener("click", act(async () => { await api("POST", "/api/attacks/stop"); loadAttack(); }));
function paintAttackStatus(s) {
  if (!s) return;
  activeIds = new Set(s.active.map((a) => a.id));
  document.querySelectorAll(".card").forEach((c) => { const on = activeIds.has(c.dataset.id); c.classList.toggle("running", on); c.querySelector(".tag").hidden = !on; c.querySelector("[data-stop]").hidden = !on; });
  const tag = $("atkLiveTag"); tag.textContent = s.active.length ? `Çalışıyor: ${atkName(s.active[0].id, s.active[0].name)}` : "Beklemede"; tag.className = "tag " + (s.active.length ? "bad" : "");
  const all = [...s.active.map((a) => ({ ...a, live: true })), ...[...s.recent].reverse().filter((r) => !s.active.some((a) => a.id === r.id && a.started_at === r.started_at)).map((a) => ({ ...a, live: false }))].slice(0, 6);
  $("attackStatus").innerHTML = all.length ? all.map((a) => `<div class="res ${a.live ? "run" : a.detected ? "det" : "miss"}"><div class="res-h"><span>${esc(atkName(a.id, a.name))}</span><span class="tag ${a.live ? "warn" : ""}">${a.live ? "Sürüyor" : "Bitti"}</span> <span class="tag ${a.detected ? "info" : "bad"}">${a.detected ? "Tespit edildi" : "Kaçırıldı"}</span></div>
    <dl><dt>Enjekte edilen kare</dt><dd>${a.injected_frames}</dd><dt>Tespit gecikmesi</dt><dd>${a.detection_delay_ms == null ? "—" : nf(a.detection_delay_ms, 1) + " ms"}</dd>
    <dt>Alarmlar</dt><dd>${esc(Object.entries(a.alerts_by_rule).map(([k, v]) => (k.startsWith("CAN-IDS") ? "K" + k.slice(-2) : k) + "×" + v).join(" ") || "—")}</dd>
    <dt>Gösterge sapması (azami)</dt><dd>${nf(a.effects.max_cluster_speed_error_kmh, 1)} km/h</dd><dt>Düşen meşru kare</dt><dd>${a.effects.legit_frames_dropped}</dd>
    <dt>Meşru kuyruk gecikmesi</dt><dd>${nf(a.effects.legit_max_queue_latency_ms, 2)} ms</dd><dt>Tepe bus yükü</dt><dd>% ${nf(a.effects.peak_bus_load_pct, 1)}</dd></dl></div>`).join("")
    : `<div class="empty-s">Henüz saldırı çalıştırılmadı. Bir kartta “Başlat”a bas.</div>`;
}

async function loadBehavior() {
  const b = await api("GET", "/api/behavior");
  $("vbaRules").innerHTML = Object.entries(b.rules).map(([k, v]) => { const h = b.rule_hits[k] || 0;
    return `<div class="vb ${esc(v.severity)}"><i></i><span class="id">${k}</span><span class="nm">${esc(VBA_TR[k] || v.name)}<span class="en">${esc(SEV_TR[v.severity] || v.severity)} önem</span></span><span class="hits ${h ? "on" : ""}">${h}<small>tetik</small></span></div>`; }).join("");
  $("vbaCount").textContent = b.alerts.length;
  $("vbaFeed").innerHTML = b.alerts.length ? [...b.alerts].reverse().map((a) => alertHtml({ ...a, hex_id: "", message_name: "" })).join("")
    : `<div class="calm">${ico("gauge")}<b>Davranış anomalisi yok</b><span>Gaz, fren, hız, devir ve sıcaklık sinyalleri birbiriyle tutarlı.</span></div>`;
}
setInterval(() => { if (!$("p-behavior").hidden) loadBehavior().catch(() => {}); }, 2000);

let dbcMsgs = [], selMsg = null, selSig = null;
const num = (v) => (v === "" || v == null ? 0 : +v);
const sigHue = (i) => (i * 47 + 190) % 360;
function sigBits(s) { const o = []; let n = s.start_bit; for (let k = 0; k < s.length; k++) { o.push(n); n = s.endian === "little" ? n + 1 : n % 8 === 0 ? n + 15 : n - 1; } return o; }
async function loadDbc() {
  const d = await api("GET", "/api/dbc"); dbcMsgs = d.messages; dbcCache = d.messages;
  if (selMsg == null || !dbcMsgs.some((m) => m.id_dec === selMsg)) { const want = hashArg ? parseId(hashArg) : null; selMsg = dbcMsgs.some((m) => m.id_dec === want) ? want : dbcMsgs.length ? dbcMsgs[0].id_dec : null; }
  paintMsgList(); paintBitGrid(); paintSignals();
}
function paintMsgList() {
  const q = $("dbcSearch").value.trim().toLowerCase(); $("dbcCount").textContent = dbcMsgs.length;
  $("dbcMsgs").innerHTML = dbcMsgs.filter((m) => !q || m.name.toLowerCase().includes(q) || m.id_hex.toLowerCase().includes(q)).map((m) =>
    `<button class="msg" role="option" aria-selected="${selMsg === m.id_dec}" data-id="${m.id_dec}" style="--h:${idHue(m.id_dec)}"><i></i><span class="mid">${esc(m.id_hex)}</span><span class="mn">${esc(m.name)}</span><span class="mm">${m.dlc}B · ${m.cycle_time_ms ?? "—"}ms · ${m.signals.length}s</span></button>`).join("");
}
function paintBitGrid() {
  const m = dbcMsgs.find((x) => x.id_dec === selMsg);
  if (!m) { $("bitGrid").innerHTML = ""; $("bitLegend").innerHTML = ""; $("dbcTitle").textContent = "Bit düzeni"; $("dbcMeta").textContent = "—"; return; }
  $("dbcTitle").textContent = `${m.id_hex}  ${m.name}`; $("dbcMeta").textContent = `${m.dlc} bayt · ${m.cycle_time_ms ?? "—"} ms · gönderen ${m.transmitter || "—"} · ${m.asil_level || ""}`;
  const rows = Math.max(1, Math.min(64, m.dlc)), cell = new Array(rows * 8).fill(null).map(() => []);
  m.signals.forEach((s, i) => sigBits(s).forEach((n) => { if (n >= 0 && n < rows * 8) cell[(n >> 3) * 8 + (7 - (n & 7))].push(i); }));
  let h = `<span class="bg-h"></span>` + [7, 6, 5, 4, 3, 2, 1, 0].map((b) => `<span class="bg-h">${b}</span>`).join("");
  for (let r = 0; r < rows; r++) {
    h += `<span class="bg-r">Bayt ${r}</span>`;
    for (let c = 0; c < 8;) {
      const own = cell[r * 8 + c];
      if (own.length === 1) { let e = c + 1; while (e < 8 && cell[r * 8 + e].length === 1 && cell[r * 8 + e][0] === own[0]) e++;
        const s = m.signals[own[0]]; h += `<span class="bc${selSig === s.name ? " sel" : ""}" data-sig="${esc(s.name)}" style="grid-column:span ${e - c};background:hsl(${sigHue(own[0])} 55% 66%)" title="${esc(s.name)} · bit ${r * 8 + (7 - e + 1)}–${r * 8 + (7 - c)}">${e - c > 1 ? esc(s.name) : ""}</span>`; c = e; }
      else if (own.length > 1) { h += `<span class="bc ov" title="Çakışma: ${esc(own.map((i) => m.signals[i].name).join(" + "))}">!</span>`; c++; }
      else { h += `<span class="bc free" title="Boş bit ${r * 8 + (7 - c)}">${r * 8 + (7 - c)}</span>`; c++; }
    }
  }
  $("bitGrid").innerHTML = h;
  $("bitLegend").innerHTML = m.signals.length ? m.signals.map((s, i) => { const b = sigBits(s); return `<button class="lg-i" type="button" data-sig="${esc(s.name)}"><i style="background:hsl(${sigHue(i)} 55% 66%)"></i><span>${esc(s.name)}</span><span class="r">${s.length} bit · ${s.endian === "little" ? "Intel" : "Motorola"} @${b[0]}</span></button>`; }).join("") : `<div class="empty-s">Bu mesajda sinyal yok. Tablodan ekleyebilirsin.</div>`;
}
function sigRow(s, isNew) {
  const inp = (n, v) => `<td><input data-f="${n}" value="${esc(v)}" aria-label="${n}"></td>`;
  return `<tr data-name="${esc(s.name)}" class="${selSig === s.name && !isNew ? "sel" : ""}">${inp("name", s.name)}${inp("start_bit", s.start_bit)}${inp("length", s.length)}
  <td><select data-f="endian" aria-label="bayt sırası"><option value="little" ${s.endian === "little" ? "selected" : ""}>Intel</option><option value="big" ${s.endian === "big" ? "selected" : ""}>Motorola</option></select></td>
  <td><input type="checkbox" data-f="is_signed" ${s.is_signed ? "checked" : ""} aria-label="işaretli"></td>${inp("scale", s.scale)}${inp("offset", s.offset)}${inp("min", s.min)}${inp("max", s.max)}${inp("unit", s.unit)}
  <td><button class="btn" data-act="save" type="button" aria-label="${isNew ? "Ekle" : "Kaydet"}">${ico(isNew ? "plus" : "check")}</button>${isNew ? "" : `<button class="btn danger" data-act="del" type="button" aria-label="Sil">${ico("x")}</button>`}</td></tr>`;
}
function paintSignals() {
  const m = dbcMsgs.find((x) => x.id_dec === selMsg);
  $("sigBody").innerHTML = m ? m.signals.map((s) => sigRow(s, false)).join("") + sigRow({ name: "", start_bit: 0, length: 8, endian: "little", is_signed: false, scale: 1, offset: 0, min: 0, max: 0, unit: "" }, true) : "";
  if (m) { const f = $("msgForm").elements; f.id.value = m.id_hex; f.name.value = m.name; f.dlc.value = m.dlc; f.cycle.value = m.cycle_time_ms ?? 0; f.tx.value = m.transmitter || ""; }
}
function pickMsg(id) { selMsg = id; selSig = null; paintMsgList(); paintBitGrid(); paintSignals(); try { history.replaceState(null, "", "#dbc/0x" + id.toString(16).toUpperCase()); } catch (e) {} }
function pickSig(name) { selSig = name; paintBitGrid(); $("sigBody").querySelectorAll("tr").forEach((r) => r.classList.toggle("sel", r.dataset.name === name && name)); }
$("dbcMsgs").addEventListener("click", (e) => { const b = e.target.closest(".msg"); if (b) pickMsg(+b.dataset.id); });
$("dbcSearch").addEventListener("input", paintMsgList);
$("bitGrid").addEventListener("click", (e) => { const c = e.target.closest("[data-sig]"); if (c) pickSig(c.dataset.sig); });
$("bitLegend").addEventListener("click", (e) => { const c = e.target.closest("[data-sig]"); if (c) pickSig(c.dataset.sig); });
$("sigBody").addEventListener("focusin", (e) => { const tr = e.target.closest("tr"); if (tr && tr.dataset.name && tr.dataset.name !== selSig) pickSig(tr.dataset.name); });
$("sigBody").addEventListener("click", act(async (e) => {
  const b = e.target.closest("button[data-act]"); if (!b) return;
  const tr = b.closest("tr"), name0 = tr.dataset.name, g = (f) => tr.querySelector(`[data-f=${f}]`);
  if (b.dataset.act === "del") { await api("DELETE", `/api/dbc/messages/${selMsg}/signals/${encodeURIComponent(name0)}`); toast("Sinyal silindi"); return loadDbc(); }
  const sig = { name: g("name").value.trim(), start_bit: num(g("start_bit").value), length: num(g("length").value), endian: g("endian").value, is_signed: g("is_signed").checked,
    scale: g("scale").value === "" ? 1 : +g("scale").value, offset: num(g("offset").value), min: num(g("min").value), max: num(g("max").value), unit: g("unit").value };
  if (name0) await api("PUT", `/api/dbc/messages/${selMsg}/signals/${encodeURIComponent(name0)}`, sig); else await api("POST", `/api/dbc/messages/${selMsg}/signals`, sig);
  toast("Kaydedildi"); selSig = sig.name; loadDbc();
}));
const parseId = (s) => (/^0x/i.test(s) || /[a-f]/i.test(s) ? parseInt(s, 16) : parseInt(s, 10));
$("msgForm").addEventListener("submit", act(async (e) => {
  e.preventDefault(); const f = e.target.elements, id = parseId(f.id.value.trim());
  const body = { id_dec: id, name: f.name.value.trim(), dlc: +f.dlc.value, cycle_time_ms: +f.cycle.value || null, transmitter: f.tx.value.trim() || "Vector__XXX" };
  if (dbcMsgs.some((m) => m.id_dec === id)) await api("PUT", `/api/dbc/messages/${id}`, body); else await api("POST", "/api/dbc/messages", { ...body, signals: [] });
  selMsg = id; toast("Kaydedildi"); loadDbc();
}));
$("msgDel").addEventListener("click", act(async () => { if (selMsg == null) return; if (!confirm("Seçili mesaj silinsin mi?")) return; await api("DELETE", `/api/dbc/messages/${selMsg}`); selMsg = null; toast("Silindi"); loadDbc(); }));
$("decBtn").addEventListener("click", act(async () => { if (selMsg == null) return; $("decOut").textContent = JSON.stringify(await api("POST", "/api/dbc/decode", { id: selMsg, data_hex: $("decHex").value }), null, 1); }));
$("dbcExport").addEventListener("click", act(async () => { const txt = await api("GET", "/api/dbc/export"); $("dbcText").value = txt; $("dbcDownload").href = URL.createObjectURL(new Blob([txt], { type: "text/plain" })); }));
$("dbcImport").addEventListener("click", act(async () => { const r = await api("POST", "/api/dbc/import", { text: $("dbcText").value }); toast(`${r.messages} mesaj, ${r.signals} sinyal içe aktarıldı`); selMsg = null; loadDbc(); }));
$("dbcReset").addEventListener("click", act(async () => { if (!confirm("Varsayılan DBC’ye dönülsün mü?")) return; await api("POST", "/api/dbc/reset"); selMsg = null; loadDbc(); }));

const RULE_FIELDS = {
  signal_threshold: [["signal", "Sinyal adı", "speed_kmh"], ["op", "Karşılaştırma", ">"], ["value", "Değer", "120"]],
  signal_delta: [["signal", "Sinyal adı", "speed_kmh"], ["max_delta", "Azami fark / kare", "20"]],
  rate: [["max_count", "Azami kare sayısı", "5"], ["window_ms", "Pencere (ms)", "100"]],
  payload_match: [["pattern_hex", "Desen (hex)", "00"], ["mask_hex", "Maske (hex, isteğe bağlı)", ""]],
  dlc_mismatch: [],
};
function paintRuleFields() {
  const ty = $("ruleType").value;
  $("ruleDyn").innerHTML = RULE_FIELDS[ty].map(([n, l, ph]) => n === "op"
    ? `<label class="fld"><span>${l}</span><select name="op">${[">", "<", ">=", "<=", "==", "!="].map((o) => `<option>${o}</option>`).join("")}</select></label>`
    : `<label class="fld"><span>${l}</span><input name="${n}" placeholder="${ph}" ${n === "mask_hex" ? "" : "required"}></label>`).join("");
}
$("ruleType").addEventListener("change", paintRuleFields);
function ruleBody() { const o = {}; new FormData($("ruleForm")).forEach((v, k) => { if (v !== "") o[k] = v; }); return o; }
async function loadRules() {
  paintRuleFields();
  const ls = await api("GET", "/api/rules/layers");
  $("layerList").innerHTML = ls.map((l) => { const [n, d] = LAYER_TR[l.id] || [l.name, ""];
    return `<div class="layer ${l.enabled ? "" : "off"}"><span class="lid">${esc(l.id.replace("CAN-IDS-", "K"))}</span><span class="ln">${esc(n)}<small>${esc(d)}</small></span><span class="h ${l.hits ? "on" : ""}">${l.hits} vuruş</span>
    <label class="switch"><input type="checkbox" data-layer="${esc(l.id)}" ${l.enabled ? "checked" : ""} aria-label="${esc(n)} katmanı"><i></i></label></div>`; }).join("");
  const rs = await api("GET", "/api/rules/custom");
  $("ruleBody").innerHTML = rs.length ? rs.map((r) => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.name)}</td><td>${esc(RULE_TYPE_TR[r.type] || r.type)}</td><td>${esc(SEV_TR[r.severity] || r.severity)}</td><td class="r mono">${r.hits}</td>
    <td style="white-space:nowrap"><label class="switch"><input type="checkbox" data-rule="${esc(r.id)}" ${r.enabled ? "checked" : ""} aria-label="${esc(r.name)}"><i></i></label> <button class="btn danger sm" data-del="${esc(r.id)}" type="button" aria-label="Sil">${ico("trash")}</button></td></tr>`).join("")
    : `<tr><td colspan="6" class="cell-na">Henüz özel kural yok. Aşağıdaki formdan ilkini tasarla.</td></tr>`;
}
$("layerList").addEventListener("change", act(async (e) => { const id = e.target.dataset.layer; if (id) { await api("POST", `/api/rules/layers/${id}?enabled=${e.target.checked}`); loadRules(); } }));
$("ruleBody").addEventListener("change", act(async (e) => { const id = e.target.dataset.rule; if (id) { await api("PUT", `/api/rules/custom/${id}`, { enabled: e.target.checked }); loadRules(); } }));
$("ruleBody").addEventListener("click", act(async (e) => { const b = e.target.closest("[data-del]"); if (b) { await api("DELETE", `/api/rules/custom/${b.dataset.del}`); toast("Silindi"); loadRules(); } }));
$("ruleForm").addEventListener("submit", act(async (e) => { e.preventDefault(); await api("POST", "/api/rules/custom", ruleBody()); toast("Kural kaydedildi"); loadRules(); }));
$("ruleTest").addEventListener("click", act(async () => {
  const id = parseId($("rtId").value.trim()); const r = await api("POST", "/api/rules/custom/test", { rule: ruleBody(), id, data_hex: $("rtHex").value });
  $("ruleTestOut").textContent = r.match ? `Eşleşti: ${r.alerts[0].evidence}` : "Eşleşmedi";
}));

let benchTimer = null, benchAuto = false;
$("bRun").addEventListener("click", act(startBench));
async function startBench() {
  await api("POST", "/api/benchmark/run", { seed: +$("bSeed").value, duration: +$("bDur").value, attack_start: +$("bStart").value, attack_len: +$("bLen").value });
  $("bRun").disabled = true; pollBench();
}
async function pollBench() {
  clearTimeout(benchTimer);
  const s = await api("GET", "/api/benchmark/status");
  if (s.status === "idle" && !s.result && !benchAuto) { benchAuto = true; $("bStage").textContent = "İlk açılış: örnek koşu otomatik başlatılıyor…"; return startBench(); }
  $("bStage").textContent = s.status === "running" ? `Çalışıyor… ${s.stage}` : s.status === "error" ? s.error : "";
  if (s.status === "running") { $("bRun").disabled = true; if (!$("benchOut").innerHTML) $("benchOut").innerHTML = `<div class="panel" style="margin-top:16px"><div class="empty-s">Benchmark çalışıyor, sonuçlar birkaç saniye içinde burada.</div></div>`; benchTimer = setTimeout(act(pollBench), 800); return; }
  $("bRun").disabled = false; if (s.result) paintBench(s.result);
}
const loadBench = act(pollBench);
function bar(label, id, v, max, text, cls) { return `<div class="bar"><span class="bl"><b>${esc(id)}</b>${esc(label)}</span><span class="track"><span class="fill ${cls || ""}" style="width:${Math.max(0, Math.min(100, (v / max) * 100)).toFixed(1)}%"></span></span><span class="bv">${esc(text)}</span></div>`; }
function paintBench(r) {
  const L = r.layers, keys = Object.keys(L).filter((k) => k.startsWith("CAN-IDS")), sc = r.scenarios.slice(1), all = [...keys, "ALL"];
  const nm = (k) => (k === "ALL" ? ["TÜM", "Tüm katmanlar"] : [k.replace("CAN-IDS-", "K"), LAYER_TR[k] ? LAYER_TR[k][0] : L[k].name]);
  const maxLat = Math.max(...[...all, "BASELINE"].map((k) => L[k].latency_us.p95), 1);
  const caught = sc.filter((s) => L.ALL.per_scenario[s].detected).length;
  const kpi = (k, v, s) => `<div class="kpi"><span class="k">${k}</span><b>${v}</b><small>${s}</small></div>`;
  const dash = (k, ...rest) => rest;
  $("benchOut").innerHTML = `<div class="kpis">${kpi("Tüm katmanlar · TPR", pctf(L.ALL.tpr_primary), "saldırı karelerinin yakalanma oranı")}${kpi("Yakalanan saldırı", `${caught} / ${sc.length}`, "en az bir karede alarm")}
    ${kpi("Yanlış alarm (FPR)", pctf(L.ALL.fpr), `${r.frames.benign.toLocaleString("tr-TR")} temiz kare`)}${kpi("Gecikme (p95)", `${nf(L.ALL.latency_us.p95, 1)} µs`, "kare başına işlem süresi")}</div>
    <div class="charts3">
    <div class="panel"><div class="panel-h"><h2>TPR · doğru tespit</h2><span class="hint-r">yüksek iyi</span></div><div class="bars">${all.map((k) => bar(nm(k)[1], nm(k)[0], L[k].tpr_primary ?? 0, 1, L[k].tpr_primary == null ? "yok" : pctf(L[k].tpr_primary, 0), "")).join("")}</div><p class="note">Katmanın kendi hedef senaryolarındaki kare düzeyi TPR; “Tüm” satırı tüm saldırılar üzerindendir.</p></div>
    <div class="panel"><div class="panel-h"><h2>FPR · yanlış alarm</h2><span class="hint-r">düşük iyi · ölçek %0–5</span></div><div class="bars">${all.map((k) => bar(nm(k)[1], nm(k)[0], L[k].fpr, 0.05, pctf(L[k].fpr), L[k].fpr > 0 ? "bad" : "")).join("")}</div><p class="note">Temiz trafikte yanlış alarm oranı. Davranış analizi yanlış alarmı: ${L.BEHAVIOR.false_alarms_benign}.</p></div>
    <div class="panel"><div class="panel-h"><h2>Gecikme · p95</h2><span class="hint-r">µs / kare</span></div><div class="bars">${[...all, "BASELINE"].map((k) => bar(k === "BASELINE" ? "Temel (yalnız çözümleme)" : nm(k)[1], k === "BASELINE" ? "TEM" : nm(k)[0], L[k].latency_us.p95, maxLat, `${nf(L[k].latency_us.p95, 1)}`, k === "BASELINE" ? "dim" : "warn")).join("")}</div><p class="note">Medyan ve p95; ölçüm bu makinedeki işlem süresidir.</p></div></div>
    <div class="panel" style="margin-top:16px"><div class="panel-h"><h2>Katman × senaryo</h2><span class="hint-r">tespit · kare TPR · ilk tespit gecikmesi (ms)</span></div><div class="tw"><table class="mx dense"><thead><tr><th>Katman</th>${sc.map((s) => `<th title="${esc(s)}">${esc(atkName(s))}</th>`).join("")}<th>FPR</th></tr></thead><tbody>` +
    all.map((k) => `<tr><td><b class="mono">${nm(k)[0]}</b> ${esc(nm(k)[1])}</td>${sc.map((s) => { const c = L[k].per_scenario[s]; return `<td class="${c.detected ? "yes" : "no"}">${c.detected ? "Evet" : "Hayır"} · ${pctf(c.tpr, 0)}${c.delay_ms != null ? " · " + nf(c.delay_ms, 0) : ""}</td>`; }).join("")}<td>${pctf(L[k].fpr)}</td></tr>`).join("") +
    `<tr><td><b class="mono">DAV</b> Araç davranış analizi</td>${sc.map((s) => { const c = L.BEHAVIOR.per_scenario[s]; return `<td class="${c.detected ? "yes" : "no"}">${c.detected ? "Evet" : "Hayır"}${c.delay_ms != null ? " · " + nf(c.delay_ms, 0) : ""}</td>`; }).join("")}<td>${L.BEHAVIOR.false_alarms_benign} alarm</td></tr></tbody></table></div>
    <ul class="notes">${r.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></div>`;
}

async function loadInteg() {
  const s = await api("GET", "/api/socketcan/status");
  $("scStatus").innerHTML = `<div class="state ${s.available ? "ok" : "warn"}">${ico(s.available ? "check" : "alert")}<span>${s.available ? "SocketCAN kullanılabilir" : "SocketCAN kullanılamıyor"}</span><span class="tag" style="margin-left:auto">${s.backend === "simulator" ? "Simülatör" : esc(s.backend)}</span></div>
    <dl class="kvgrid"><dt>Platform</dt><dd>${esc(s.platform)}</dd><dt>python-can</dt><dd>${s.python_can_installed ? "kurulu" : "kurulu değil"}</dd><dt>Kanal</dt><dd>${esc(s.channel)}</dd><dt>Yedek</dt><dd>${s.fallback === "simulator" ? "bellek içi simülatör" : esc(s.fallback || "—")}</dd><dt>Aynalanan kare (TX)</dt><dd>${s.frames_mirrored}</dd><dt>Alınan kare (RX → IDS)</dt><dd>${s.frames_received ?? 0}</dd></dl>
    <label class="fld chk"><input type="checkbox" id="scRx" ${s.rx_enabled ? "checked" : ""} ${s.available ? "" : "disabled"}> <span>Arayüzden gelen kareleri IDS’e ver (kaynak: <span class="mono">${esc(s.rx_source || "SOCKETCAN")}</span>)</span></label>
    ${s.available ? "" : `<p class="note">SocketCAN yalnızca Linux’ta çalışır; şu an bellek içi simülatör kullanılıyor. Linux’ta sanal arayüzü şöyle kurabilirsin:</p><pre class="out">${esc(s.setup_hint || "")}</pre>`}`;
  const u = await api("GET", "/api/uds/log");
  $("udsBody").innerHTML = u.length ? [...u].reverse().slice(0, 40).map((m) => `<tr><td>${nf(m.timestamp, 3)}</td><td class="idc" style="--h:${idHue(m.arbitration_id ?? 0)}">${esc(m.hex_id)}</td><td>${esc(m.service_name)}${m.negative_response ? " (NRC " + m.nrc + ")" : ""}</td><td class="${m.risk === "CRITICAL" ? "bad-t" : ""}">${esc(SEV_TR[m.risk] || m.risk)}</td><td class="r">${m.length}</td><td>${m.reassembled ? "Evet" : "—"}</td><td>${esc(m.payload_hex)}</td></tr>`).join("")
    : `<tr><td colspan="7"><div class="empty-cta">${ico("lock")}<span>Henüz UDS trafiği yok. Çok çerçeveli bir yazılım yazma saldırısı üretip ISO-TP birleştirmesini gör.</span><button class="btn primary" id="udsDemo" type="button">${ico("play")}<span>Örnek UDS trafiği üret</span></button></div></td></tr>`;
}
$("udsBody").addEventListener("click", act(async (e) => { if (e.target.closest("#udsDemo")) { await api("POST", "/api/attacks/run", { attack: "uds_reflash", duration: 6, params: {}, combine: false }); toast("UDS saldırısı başlatıldı"); setTimeout(() => loadInteg().catch(() => {}), 2500); } }));
$("scProbe").addEventListener("click", act(async () => { await api("POST", "/api/socketcan/connect"); loadInteg(); }));
$("scStatus").addEventListener("change", act(async (e) => { if (e.target.id === "scRx") { await api("POST", "/api/socketcan/rx", { enabled: e.target.checked }); loadInteg(); } }));
function fdBody(send) { return { id: parseId($("fdId").value.trim()), data_hex: $("fdHex").value, brs: $("fdBrs").checked, pad: $("fdPad").checked, send }; }
function paintFd(r) {
  const rows = [["Arbitrasyon ID", "0x" + r.arbitration_id.toString(16).toUpperCase()], ["Yük", r.payload_len + " bayt"], ["DLC kodu", r.dlc_code], ["BRS", r.brs ? "açık" : "kapalı"], ["CAN FD süresi", nf(r.fd_time_us, 1) + " µs"],
    ["Klasik CAN eşdeğeri", r.classic_equivalent_frames + " kare · " + nf(r.classic_time_us, 1) + " µs"], ["Hızlanma", nf(r.speedup_vs_classic, 2) + "×"], ["Doldurulan bayt", r.padded_bytes], ["Yük (hex)", r.payload_hex]];
  $("fdOut").innerHTML = rows.map(([k, v]) => `<span class="k">${k}</span><span class="v">${esc(v)}</span>`).join("") + `<span class="k">Not</span><span class="v">Kablodaki süre tahmindir (en kötü bit doldurma); bit düzeyinde denetleyici modeli değildir.</span>`;
}
$("fdCalc").addEventListener("click", act(async () => paintFd(await api("POST", "/api/canfd/encode", fdBody(false)))));
$("fdSend").addEventListener("click", act(async () => { paintFd(await api("POST", "/api/canfd/encode", fdBody(true))); toast("CAN FD karesi bus’a gönderildi (Bus İzleme’de FD etiketli)"); }));

setInterval(pollTrace, 800);
setInterval(() => { if (!$("p-integ").hidden) loadInteg().catch(() => {}); }, 3000);
buildCluster(); connectWebSocket();
api("GET", "/api/alerts").then((l) => { if (Array.isArray(l) && l.length) { pushAlerts(l.slice(-15), false); alertTotal = l.length; $("alertCountBadge").textContent = alertTotal; $("atkAlertCount").textContent = alertTotal; updateAlarmBand(); } else { $("alertFeed").innerHTML = calmHtml(); $("alertFeedAtk").innerHTML = calmHtml(); } }).catch(() => { $("alertFeed").innerHTML = calmHtml(); });
{ const [n, a] = parseHash(); showTab(n, a); }
sendDriver().catch(() => {});
