// GÖK CAN-IDS Lab — 3B Araç: canlı sürüş, saldırı sonucu canlandırması, kartların araçtaki yeri.
// Yerel three.js (r160) kullanır; harici CDN yok. Araç prosedürel ilkel geometrilerden kurulur (gerçek marka/model değildir).
import * as THREE from "./vendor/three.module.min.js";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const RM = window.matchMedia ? matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const lerp = (a, b, t) => a + (b - a) * t;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nf = (v, d = 0) => (Number.isFinite(v) ? v.toLocaleString("tr-TR", { minimumFractionDigits: d, maximumFractionDigits: d }) : "—");
const cssv = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const toast = (m, e) => { if (typeof window.toast === "function") window.toast(m, e); };
async function api(method, url, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(url, opt); const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(typeof data === "object" && data && data.detail ? String(data.detail) : "HTTP " + r.status);
  return data;
}

/* ---------------- saldırı tanımları ---------------- */
const STEER_SPOOF = { id: "steer_spoof", attack: "spoof_id", params: { target_id: 196, payload_hex: "38 18 F4 01", rate_hz: 100 }, fx: "steer", name: "Direksiyon kimlik sahteciliği (0x0C4)",
  manip: "0x0C4 (direksiyon) kimliğiyle sahte +120° açı kareleri saniyede 100 kez basılıyor.", impact: "Şerit takip / EPS sahte açıya uyuyor; araç şeridinden kayıyor." };
const FXMAP = { speed_spoof: "speed", speed_spoof_stealth: "stealth", spoof_id: "engine", replay: "replay", flooding: "flood", fuzzing: "fuzz", counter_crc_desync: "crc",
  unauthorized_id: "unauth", uds_diagnostic_attack: "udsd", uds_reflash: "udsr", headlight_can_injection_unlock: "unlock", brake_spoof: "brake" };
const FXCAP = {
  steer: "Canlandırma: şerit takip / EPS sahte açıya tepki veriyor; araç şeridinden çıkıp bariyere yöneliyor.",
  brake: "Canlandırma: sahte fren basıncı ani fren yaptırıyor; arkadaki araç yaklaşıyor, çarpışma riski doğuyor.",
  speed: "Canlandırma: araç normal gidiyor ama gösterge yanlış hız okuyor; hıza bağlı sistemler yanlış karar verebilir.",
  stealth: "Canlandırma: gösterge hızı fark edilmeden gerçekten uzaklaşıyor; yalnızca davranış analizi yakalar.",
  engine: "Canlandırma: devir göstergesi zıplıyor, motor titriyor, uyarı lambaları yanıyor.",
  fuzz: "Canlandırma: rastgele kareler motoru ve göstergeleri öngörülemez davrandırıyor.",
  crc: "Canlandırma: sayaç/CRC bozulunca ABS/ESP uyarı lambası yanıyor, fren desteği devre dışı kalıyor.",
  flood: "Canlandırma: bus doyuyor; gösterge donuyor, tüm lambalar yanıyor, araç “limp mode” ile yavaşlıyor.",
  replay: "Canlandırma: göstergeler geçmiş değerlere atlıyor; araç şimdiki an yerine eski sürüş anını yaşıyor sanılıyor.",
  unauth: "Canlandırma: doğrudan zarar yok; “ağda yabancı cihaz” uyarısı çıkıyor.",
  udsd: "Canlandırma: tanı oturumu zorlanıyor; ECU yazılım yükleme ikonu yanıyor, motor kesiliyor, araç boşta yavaşlıyor.",
  udsr: "Canlandırma: ECU yazılımı yazılıyor; motor kesiliyor, araç boşta yavaşlıyor.",
  unlock: "Canlandırma: kapı kilitleri açılıyor; dörtlü flaşör ve iç aydınlatma yanıyor.",
};
const RECON = "Saldırgan aracın OBD-II portuna bir dongle takar ve ağı dinler: hangi ID’ler, hangi sıklıkta konuşuyor?";
const ACCESS = "Dongle A domaininin (güvenilmez hat) üzerine karışır; bilgi-eğlence ve dongle’lar burada yaşar.";
const STEPS = ["Keşif", "Erişim", "Manipülasyon", "Etki"];
const LAMPS = [["check", "Motor arızası", ""], ["abs", "ABS", ""], ["esp", "ESP", ""], ["bassist", "Fren desteği kapalı", ""], ["limp", "Limp mode", "w"], ["ecu", "ECU yazılım yükleniyor", "i"],
  ["lka", "EPS sahte açıda", "w"], ["lane", "Şerit ihlali", ""], ["coll", "Çarpışma riski", ""], ["speedsys", "Hız bilgisi tutarsız", "w"], ["lock", "Kapı kilidi açık", "w"], ["net", "Ağda yabancı cihaz", "i"]];

/* ---------------- kartlar ve ECU’lar (araçtaki yerleri) ---------------- */
// p: araç yerel koordinatı (x: + sağ, y: yukarı, z: − ön). dom: A | B | G (ağ geçidi) | T (dinleyici) | P (araç dışı)
const PARTS = {
  tn1: { n: "GÖK-TN1", s: "TN1", f: "OBD kartı", dom: "T", p: [-0.52, 0.5, -0.56], tag: "kart", t: "GÖK-TN1 · OBD dinleyici kart",
    where: "OBD-II (J1962) portuna takılır: sürücü tarafında, gösterge panelinin altında, diz hizasında. Port sürücü koltuğuna yakın olmak zorundadır; kart kablonun ucundaki küçük kutudur.",
    how: "Porta fişlenir (CANH pin 6, CANL pin 14, +12 V pin 16, şasi pin 4/5). Yalnızca dinler (listen-only), Wi-Fi ile bu panele akıtır; araçta hiçbir şey söylemez.", sim: "Kulak: araçta konuşulanları dinler.", hw: true },
  gw1: { n: "GÖK-GW1", s: "GW1", f: "ağ geçidi", dom: "G", p: [-0.06, 0.82, -1.0], tag: "kart", t: "GÖK-GW1 · Güvenli CAN ağ geçidi",
    where: "Ön konsolun/torpidonun arkasında, aracın mevcut merkezi ağ geçidinin (central gateway) yanında: OBD/bilgi-eğlence (A) kablo demeti ile güç aktarma/fren (B) demetinin ayrıldığı noktada.",
    how: "İki domain arasına hat içi girer: A demeti bir yanından, B demeti öbür yanından bağlanır; kural listesine uymayan kare öbür tarafa geçmez. Aracın beyni değil: ECU’lar arasındaki kapıdaki görevli.", sim: "Kapıdaki görevli: geçebilecek kareyi geçirir, şüphelisini durdurur.", hw: true },
  pi1: { n: "GÖK-PI1", s: "PI1", f: "araçta değil", dom: "P", p: null, tag: "kart", t: "GÖK-PI1 · Test tezgâhı kartı (araçta değil)",
    where: "Araçta değildir: masadaki test tezgâhında Raspberry Pi ile çalışır. Aracın kablo demetine bağlanmaz.",
    how: "Tezgâhta sanal ya da gerçek CAN denemeleri için kullanılır; araca dokunmadan kural ve saldırı denemesi yapılır.", sim: "Laboratuvar tezgâhı: araca zarar vermeden deneme yeri.", hw: true },
  motor: { n: "Motor ECU", s: "Motor", f: "", dom: "B", p: [0.28, 0.82, -1.62], tag: "ECU", t: "Motor ECU", where: "Motor bölmesinde, motorun üstünde/yanında.", how: "B domaini (güç aktarma) CAN hattına bağlıdır; 0x180 kimliğiyle devir, sıcaklık ve gaz yayınlar.", sim: "Kalp: aracın temposunu belirler." },
  fren: { n: "Fren / ABS", s: "ABS", f: "", dom: "B", p: [-0.56, 0.8, -1.36], tag: "ECU", t: "Fren / ABS ECU", where: "Ön sol motor bölmesinde, fren hidrolik ünitesinin üzerinde.", how: "B domaini hattına bağlıdır; 0x200 ve 0x244 ile fren basıncı ve araç hızını yayınlar.", sim: "Refleks sistemi: tekerleklerin kilitlenmesini önler." },
  eps: { n: "Direksiyon EPS", s: "EPS", f: "", dom: "B", p: [-0.42, 0.96, -0.74], tag: "ECU", t: "Direksiyon EPS ECU", where: "Direksiyon kolonunda (sürücü önünde).", how: "B domaini hattına bağlıdır; 0x0C4 ile direksiyon açısını yayınlar, şerit takip bu açıya güvenir.", sim: "Elin uzantısı: aracın nereye döneceğini söyler." },
  trans: { n: "Şanzıman", s: "Şnz", f: "", dom: "B", p: [0.02, 0.4, -0.12], tag: "ECU", t: "Şanzıman ECU", where: "Aracın altında, orta hatta, şanzıman gövdesinin yanında.", how: "B domaini hattına bağlıdır; 0x2A0 ile vites ve yağ sıcaklığını yayınlar.", sim: "Dişli kutusu: gücü tekerleğe uygun oranda iletir." },
  cluster: { n: "Gösterge", s: "Gst", f: "", dom: "A", p: [-0.44, 1.08, -0.9], tag: "ECU", t: "Gösterge ECU", where: "Ön panelde, direksiyonun arkasında.", how: "A domaini hattına bağlıdır; 0x3C0 ile hız ve uyarı lambalarını gösterir. Kendi karar vermez, başkalarının söylediğini okur.", sim: "Aracın kadranı." },
  bcm: { n: "Gövde / BCM", s: "BCM", f: "", dom: "A", p: [-0.68, 0.74, -0.9], tag: "ECU", t: "Gövde (BCM) ECU", where: "Sürücü tarafında, ön panelin altında.", how: "A domaini hattına bağlıdır; 0x320 ile kapı kilidi, sinyal ve dörtlü flaşörü yönetir.", sim: "Kapıcı: kapıları açar-kapatır." },
};
const PART_ORDER = ["tn1", "gw1", "pi1", "motor", "fren", "eps", "trans", "cluster", "bcm"];
const DOM_TR = { A: "A domaini (güvenilmez)", B: "B domaini (korunan)", G: "A ile B arası", T: "A domaini (OBD)", P: "araç dışı" };

/* ---------------- durum ---------------- */
const S = {
  inited: false, gl: false, raf: 0, tick: 0, last: 0, tel: null, telOk: null, hist: [], clean: null, hold: null,
  v: 25, vF: 25, gap: 14, x: 0, psi: 0, accel: 0, vSeen: [], follAccel: 0, wheelSpin: 0, fSpin: 0, steerVis: 0, steerEff: 0,
  xray: false, doors: false, doorOpen: [0, 0, 0, 0], gwOn: true, playing: false, cancel: false, catalog: [],
  fx: null, ids: null, gw: null, sel: null, hudAcc: 0, eventsSeen: new Set(), shield: 0, t: 0, hazard: false, hit: 0,
};
let R = null; // render nesneleri
const active = () => document.body.dataset.tab === "car3d" && !document.hidden;

/* ---------------- animasyon etkileri ---------------- */
function mods() {
  const m = { lamps: [] }; const f = S.fx; if (!f || f.k === 0) return m;
  const t = (performance.now() - f.t0) / 1000, k = f.k, c = S.clean || S.tel || {};
  const base = (S.tel && S.tel.speed_kmh) || 90;
  switch (f.key) {
    case "steer": m.bias = 120 * k * Math.min(1, t / 0.5); m.noLka = k >= 0.5; m.steerBase = 0; m.lamps.push("lka"); break;
    case "brake": m.capKmh = lerp(base, 15, k); m.decel = 8; m.brake = true; m.brakeBar = 80 * k; break;
    case "speed": m.clusterOff = 110 * k; m.lamps.push("speedsys"); break;
    case "stealth": m.clusterOff = Math.min(45, 8 * t) * k; if (t > 3) m.lamps.push("speedsys"); break;
    case "engine": m.rpm = "jump"; m.shake = 0.014 * k; m.lamps.push("check"); break;
    case "fuzz": { m.rpm = "fuzz"; m.shake = 0.01 * k; const pool = ["check", "abs", "esp", "ecu", "bassist"]; const i = Math.floor(t * 2.2); m.lamps.push(pool[(i * 7) % pool.length], pool[(i * 3 + 2) % pool.length]); break; }
    case "crc": m.lamps.push("abs", "esp", "bassist"); break;
    case "flood": m.freeze = true; m.capKmh = lerp(base, 30, k); m.decel = 2.2; m.limp = true; m.lamps.push("check", "abs", "esp", "bassist", "limp", "net"); m.allLamps = true; break;
    case "replay": m.replay = true; break;
    case "unauth": m.lamps.push("net"); break;
    case "unlock": m.unlock = true; m.hazard = true; m.lamps.push("lock"); break;
    case "udsd": case "udsr": { const cutAt = f.key === "udsd" ? 2.5 : 1.2; m.lamps.push("ecu"); if (t > cutAt) { m.rpm = "cut"; m.capKmh = lerp(base, 0, k); m.decel = 1.15; m.lamps.push("check"); } break; }
  }
  return m;
}

/* ---------------- sahne ---------------- */
function th() { return { A: cssv("--warn") || "#F2B33D", B: cssv("--accent") || "#4FC3D9", OK: cssv("--ok") || "#4CC38A", DIAG: cssv("--diag") || "#6AA9F5", ALARM: cssv("--alarm") || "#F0605D", light: document.documentElement.dataset.theme === "light" }; }
function glowTex(color) { const c = document.createElement("canvas"); c.width = c.height = 64; const g = c.getContext("2d"), r = g.createRadialGradient(32, 32, 0, 32, 32, 32); r.addColorStop(0, color); r.addColorStop(1, "rgba(0,0,0,0)"); g.fillStyle = r; g.fillRect(0, 0, 64, 64); return new THREE.CanvasTexture(c); }
function box(w, h, d, mat, x = 0, y = 0, z = 0, parent) { const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), mat); m.position.set(x, y, z); if (parent) parent.add(m); return m; }
function quadGeo(a, b, c, d) { const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.Float32BufferAttribute([...a, ...b, ...c, ...a, ...c, ...d], 3)); g.computeVertexNormals(); return g; }

function bodyGeo() {
  const sh = new THREE.Shape(), pts = [[0, 0.3]];
  const arch = (uc, r) => { for (let i = 0; i <= 10; i++) { const a = Math.PI - (i / 10) * Math.PI; pts.push([uc + r * Math.cos(a), 0.3 + 0.5 * Math.sin(a)]); } };
  arch(0.85, 0.42); arch(3.5, 0.42);
  pts.push([4.4, 0.3], [4.4, 0.62], [4.1, 0.86], [3.25, 0.98], [2.65, 1.42], [1.15, 1.42], [0.35, 0.95], [0, 0.78]);
  sh.moveTo(pts[0][0], pts[0][1]); pts.slice(1).forEach((p) => sh.lineTo(p[0], p[1])); sh.closePath();
  const g = new THREE.ExtrudeGeometry(sh, { depth: 1.7, bevelEnabled: true, bevelThickness: 0.05, bevelSize: 0.05, bevelSegments: 2 });
  g.translate(-2.2, 0, -0.85); g.rotateY(Math.PI / 2); return g;
}

function buildCar(opts) {
  const T = opts.T, car = new THREE.Group(), api2 = { group: car, mats: {}, doors: [], wheels: [], front: [], parts: {}, interior: new THREE.Group() };
  const bodyM = new THREE.MeshStandardMaterial({ color: opts.color, roughness: 0.5, metalness: 0.25 });
  const glassM = new THREE.MeshStandardMaterial({ color: T.light ? "#2c3e50" : "#0f1a24", roughness: 0.15, metalness: 0.4, transparent: true, opacity: 0.78, side: THREE.DoubleSide, polygonOffset: true, polygonOffsetFactor: -2, polygonOffsetUnits: -2, emissive: "#ffcf70", emissiveIntensity: 0 });
  const panelM = new THREE.MeshStandardMaterial({ color: opts.color, roughness: 0.45, metalness: 0.25, polygonOffset: true, polygonOffsetFactor: -1, polygonOffsetUnits: -1 });
  const tireM = new THREE.MeshStandardMaterial({ color: "#14161a", roughness: 0.9 }), rimM = new THREE.MeshStandardMaterial({ color: "#aab2ba", roughness: 0.3, metalness: 0.8 });
  api2.mats = { body: bodyM, glass: glassM, panel: panelM };
  car.add(new THREE.Mesh(bodyGeo(), bodyM));
  // cam yüzeyleri: ön / arka
  car.add(new THREE.Mesh(quadGeo([-0.8, 0.99, -1.06], [0.8, 0.99, -1.06], [0.8, 1.41, -0.46], [-0.8, 1.41, -0.46]), glassM));
  car.add(new THREE.Mesh(quadGeo([-0.78, 0.96, 1.85], [-0.78, 1.41, 1.06], [0.78, 1.41, 1.06], [0.78, 0.96, 1.85]), glassM));
  // kapılar (4): [taraf, menteşe z, yön (+1: menteşeden arkaya), açılma işareti]
  const defs = [[-1, -0.85, 1, -1], [-1, 1.1, -1, 1], [1, -0.85, 1, 1], [1, 1.1, -1, -1]];
  defs.forEach(([side, hz, dir, sg], i) => {
    const g = new THREE.Group(); g.position.set(side * 0.93, 0, hz);
    const L = dir > 0 ? 1.0 : 0.95;
    box(0.04, 0.56, L, panelM, 0, 0.76, dir * L / 2, g);
    const pl = dir > 0 ? [[0.02, 1.04], [0.4, 1.4], [0.97, 1.4], [0.97, 1.04]] : [[0.02, 1.04], [0.02, 1.38], [0.93, 1.4], [0.93, 1.04]];
    const s = new THREE.Shape(); pl.forEach((p, j) => (j ? s.lineTo(-dir * p[0], p[1]) : s.moveTo(-dir * p[0], p[1]))); s.closePath();
    const gg = new THREE.ShapeGeometry(s); gg.rotateY(Math.PI / 2); const gm = new THREE.Mesh(gg, glassM); gm.position.x = side * 0.012; g.add(gm);
    const hnd = box(0.05, 0.04, 0.16, rimM, side * 0.02, 1.0, dir * (L - 0.2), g);
    car.add(g); api2.doors.push({ g, sign: sg, side });
  });
  // tekerlekler
  [[-1, -1.3, true], [1, -1.3, true], [-1, 1.35, false], [1, 1.35, false]].forEach(([side, z, fr]) => {
    const piv = new THREE.Group(); piv.position.set(side * 0.82, 0.34, z); const spin = new THREE.Group(); piv.add(spin);
    const tire = new THREE.Mesh(new THREE.CylinderGeometry(0.34, 0.34, 0.24, 20), tireM); tire.rotation.z = Math.PI / 2; spin.add(tire);
    const rim = new THREE.Mesh(new THREE.CylinderGeometry(0.21, 0.21, 0.26, 12), rimM); rim.rotation.z = Math.PI / 2; spin.add(rim);
    for (let a = 0; a < 5; a++) { const sp = box(0.27, 0.05, 0.3, tireM, 0, 0, 0, spin); sp.rotation.x = (a * Math.PI) / 5; }
    car.add(piv); api2.wheels.push(spin); if (fr) api2.front.push(piv);
  });
  // lambalar
  const headM = new THREE.MeshStandardMaterial({ color: "#fff6dc", emissive: "#fff2c0", emissiveIntensity: 0.9 });
  const tailM = new THREE.MeshStandardMaterial({ color: "#7a0f10", emissive: "#ff2a1a", emissiveIntensity: 0.5 });
  const sigM = new THREE.MeshStandardMaterial({ color: "#6b4a00", emissive: "#ffb000", emissiveIntensity: 0.0 });
  [-1, 1].forEach((s) => { box(0.3, 0.1, 0.06, headM, s * 0.58, 0.68, -2.24, car); box(0.3, 0.1, 0.06, tailM, s * 0.58, 0.72, 2.24, car); box(0.14, 0.08, 0.07, sigM, s * 0.78, 0.6, -2.25, car); box(0.14, 0.08, 0.07, sigM, s * 0.78, 0.6, 2.25, car); });
  api2.mats.tail = tailM; api2.mats.sig = sigM;
  const gl = new THREE.SpriteMaterial({ map: R.glowRed, color: "#ff3020", transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending });
  [-1, 1].forEach((s) => { const sp = new THREE.Sprite(gl); sp.scale.set(0.8, 0.8, 1); sp.position.set(s * 0.58, 0.72, 2.35); car.add(sp); });
  api2.mats.glow = gl;
  const gs = new THREE.SpriteMaterial({ map: R.glowAmber, color: "#ffb000", transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending });
  [[-1, -1], [1, -1], [-1, 1], [1, 1]].forEach(([sx, sz]) => { const sp = new THREE.Sprite(gs); sp.scale.set(0.8, 0.8, 1); sp.position.set(sx * 0.8, 0.62, sz * 2.4); car.add(sp); });
  api2.mats.sigGlow = gs;
  // gölge
  const sh = new THREE.Mesh(new THREE.PlaneGeometry(2.4, 5.2), R.shadowM); sh.rotation.x = -Math.PI / 2; sh.position.y = 0.02; car.add(sh);
  if (opts.interior) buildInterior(api2, T);
  return api2;
}

function buildInterior(a, T) {
  const I = a.interior, car = a.group; car.add(I);
  const seatM = new THREE.MeshStandardMaterial({ color: "#3a4048", roughness: 0.9 }), dashM = new THREE.MeshStandardMaterial({ color: "#2a2f35", roughness: 0.8 });
  const engM = new THREE.MeshStandardMaterial({ color: "#59616a", roughness: 0.6, metalness: 0.5 }), cenM = new THREE.MeshStandardMaterial({ color: "#8a949e", roughness: 0.5, metalness: 0.4 });
  box(1.6, 0.34, 0.4, dashM, 0, 0.9, -0.95, I);
  [-0.42, 0.42].forEach((x) => { box(0.46, 0.14, 0.5, seatM, x, 0.56, 0.1, I); box(0.46, 0.55, 0.12, seatM, x, 0.86, 0.38, I); });
  box(1.5, 0.14, 0.5, seatM, 0, 0.56, 1.1, I); box(1.5, 0.5, 0.12, seatM, 0, 0.84, 1.45, I);
  const ev = new THREE.Mesh(new THREE.BoxGeometry(0.62, 0.42, 0.7), engM); ev.position.set(0.1, 0.62, -1.55); I.add(ev);
  const col = new THREE.Group(); col.position.set(-0.42, 1.0, -0.66); col.rotation.x = 0.95; I.add(col);
  const sw = new THREE.Mesh(new THREE.TorusGeometry(0.19, 0.026, 8, 24), dashM); col.add(sw); a.steerWheel = sw;
  [0, 1, 2].forEach((i) => { const sp = box(0.36, 0.03, 0.03, dashM, 0, 0, 0, sw); sp.rotation.z = (i * Math.PI) / 3; });
  const cyl = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 0.15, 0.9, 12), engM); cyl.rotation.x = Math.PI / 2; cyl.position.set(0.02, 0.4, -0.12); I.add(cyl);
  box(0.28, 0.14, 0.34, cenM, 0.28, 0.82, -1.0, I); // mevcut merkezi ağ geçidi
  // işaretli noktalar (ECU / kart kutuları)
  const colorOf = (d) => ({ A: T.A, B: T.B, G: T.OK, T: T.DIAG }[d]);
  const mk = (k, sz) => { const P = PARTS[k]; if (!P.p) return; const m = new THREE.MeshStandardMaterial({ color: colorOf(P.dom), emissive: colorOf(P.dom), emissiveIntensity: 0.45, roughness: 0.4 });
    const b = new THREE.Mesh(new THREE.BoxGeometry(...sz), m); b.position.set(...P.p); I.add(b); a.parts[k] = b; };
  mk("tn1", [0.24, 0.14, 0.18]); mk("gw1", [0.3, 0.17, 0.22]); mk("motor", [0.24, 0.12, 0.18]); mk("fren", [0.22, 0.12, 0.16]); mk("eps", [0.16, 0.12, 0.12]); mk("trans", [0.24, 0.12, 0.18]); mk("cluster", [0.34, 0.14, 0.1]); mk("bcm", [0.2, 0.12, 0.14]);
  // OBD-II portu + TN1 kablosu
  const obd = box(0.12, 0.07, 0.05, cenM, -0.64, 0.66, -0.82, I); a.obd = obd;
  a.tubes = [];
  const tube = (pts, dom, rad = 0.024) => { const m = new THREE.MeshStandardMaterial({ color: dom === "A" ? T.A : dom === "B" ? T.B : "#222", emissive: dom === "A" ? T.A : dom === "B" ? T.B : "#000", emissiveIntensity: 0.35 });
    const mesh = new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts.map((p) => new THREE.Vector3(...p))), 28, rad, 6), m); I.add(mesh); a.tubes.push({ mesh, dom }); };
  const v = (k) => PARTS[k].p;
  tube([[-0.64, 0.66, -0.82], v("tn1")], "T", 0.018);
  tube([[-0.64, 0.66, -0.82], [-0.68, 0.7, -0.88], v("bcm"), [-0.58, 0.8, -0.95], v("cluster"), [-0.3, 0.9, -1.0], v("gw1")], "A");
  tube([v("gw1"), [0.1, 0.82, -1.15], v("motor"), [-0.1, 0.8, -1.5], v("fren")], "B");
  tube([v("gw1"), [-0.22, 0.9, -0.85], v("eps")], "B");
  tube([v("gw1"), [0.04, 0.6, -0.7], v("trans")], "B");
  I.visible = false;
}

function buildBench(T) {
  const g = new THREE.Group(); g.position.set(-9.6, 0, 3.4);
  const base = new THREE.Mesh(new THREE.CylinderGeometry(2.1, 2.1, 0.1, 28), new THREE.MeshStandardMaterial({ color: T.light ? "#c9ced3" : "#2b3138", roughness: 0.9 })); base.position.y = 0.05; g.add(base);
  const wood = new THREE.MeshStandardMaterial({ color: "#8a6a47", roughness: 0.8 }), dark = new THREE.MeshStandardMaterial({ color: "#20252b", roughness: 0.6 });
  box(1.9, 0.07, 0.95, wood, 0, 0.82, 0, g); [[-0.85, -0.4], [0.85, -0.4], [-0.85, 0.4], [0.85, 0.4]].forEach(([x, z]) => box(0.07, 0.72, 0.07, dark, x, 0.46, z, g));
  const pi = new THREE.MeshStandardMaterial({ color: "#1f8a4c", roughness: 0.5 }); box(0.46, 0.035, 0.3, pi, -0.35, 0.88, 0.05, g);
  box(0.1, 0.03, 0.1, new THREE.MeshStandardMaterial({ color: "#222" }), -0.25, 0.915, 0.05, g); box(0.1, 0.06, 0.12, new THREE.MeshStandardMaterial({ color: "#b8c0c8", metalness: 0.8, roughness: 0.3 }), -0.52, 0.9, 0.05, g);
  box(0.64, 0.03, 0.44, dark, 0.45, 0.875, 0.05, g); const scr = box(0.64, 0.42, 0.025, new THREE.MeshStandardMaterial({ color: "#10161c", emissive: T.B, emissiveIntensity: 0.25 }), 0.45, 1.08, -0.15, g); scr.rotation.x = -0.18;
  R.scene.add(g); return g;
}

function initScene() {
  const T = th(), cv = $("c3Canvas");
  let renderer; try { renderer = new THREE.WebGLRenderer({ canvas: cv, antialias: true }); } catch (e) { return false; }
  if (!renderer.getContext()) return false;
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  const scene = new THREE.Scene(), camera = new THREE.PerspectiveCamera(36, 16 / 9, 0.1, 200);
  R = { renderer, scene, camera, T, scroll: [], pulse: [], glowRed: glowTex("rgba(255,60,40,1)"), glowAmber: glowTex("rgba(255,176,0,1)") };
  const sc = document.createElement("canvas"); sc.width = sc.height = 64; const sg = sc.getContext("2d"), gr = sg.createRadialGradient(32, 32, 4, 32, 32, 30); gr.addColorStop(0, "rgba(0,0,0,.55)"); gr.addColorStop(1, "rgba(0,0,0,0)"); sg.fillStyle = gr; sg.fillRect(0, 0, 64, 64);
  R.shadowM = new THREE.MeshBasicMaterial({ map: new THREE.CanvasTexture(sc), transparent: true, depthWrite: false });
  R.hemi = new THREE.HemisphereLight(0xffffff, 0x445566, 0.9); scene.add(R.hemi);
  R.sun = new THREE.DirectionalLight(0xffffff, 1.0); R.sun.position.set(-6, 12, 5); scene.add(R.sun);
  R.dome = new THREE.PointLight(0xffd080, 0, 5); R.dome.position.set(0, 1.25, 0.3);
  // yol
  R.roadTex = new THREE.CanvasTexture(document.createElement("canvas")); R.roadTex.wrapS = R.roadTex.wrapT = THREE.RepeatWrapping; R.roadTex.anisotropy = 4; R.roadTex.repeat.set(1, 16);
  R.road = new THREE.Mesh(new THREE.PlaneGeometry(10.5, 192), new THREE.MeshStandardMaterial({ map: R.roadTex, roughness: 0.95 })); R.road.rotation.x = -Math.PI / 2; R.road.position.set(0, 0, -60); scene.add(R.road);
  R.ground = new THREE.Mesh(new THREE.PlaneGeometry(240, 240), new THREE.MeshStandardMaterial({ roughness: 1 })); R.ground.rotation.x = -Math.PI / 2; R.ground.position.y = -0.02; scene.add(R.ground);
  // şerit ihlali çizgileri
  R.lineWarn = [-1.75, 1.75].map((x) => { const m = new THREE.Mesh(new THREE.PlaneGeometry(0.22, 192), new THREE.MeshBasicMaterial({ color: 0xff3b30, transparent: true, opacity: 0, depthWrite: false })); m.rotation.x = -Math.PI / 2; m.position.set(x, 0.015, -60); scene.add(m); return m; });
  // bariyer
  R.railM = new THREE.MeshStandardMaterial({ roughness: 0.5, metalness: 0.6 }); R.postM = new THREE.MeshStandardMaterial({ roughness: 0.7 });
  [-1, 1].forEach((s) => { const r = new THREE.Mesh(new THREE.BoxGeometry(0.1, 0.28, 192), R.railM); r.position.set(s * 6.3, 0.62, -60); scene.add(r); const r2 = r.clone(); r2.position.y = 0.3; r2.scale.y = 0.5; scene.add(r2); });
  const LEN = 120, Z0 = -90;
  const addScroll = (obj, z) => { obj.position.z = z; scene.add(obj); R.scroll.push(obj); };
  for (let i = 0; i < 30; i++) [-1, 1].forEach((s) => { const p = new THREE.Mesh(new THREE.BoxGeometry(0.12, 0.7, 0.12), R.postM); p.position.set(s * 6.3, 0.35, 0); addScroll(p, Z0 + i * 4); });
  // ağaç ve direkler
  R.leafM = new THREE.MeshStandardMaterial({ roughness: 0.9 }); R.trunkM = new THREE.MeshStandardMaterial({ color: "#5a4632", roughness: 1 });
  R.lampM = new THREE.MeshStandardMaterial({ color: "#c8d0d8", roughness: 0.5, metalness: 0.5 }); R.bulbM = new THREE.MeshStandardMaterial({ color: "#fff4d0", emissive: "#ffe9a8", emissiveIntensity: 1 });
  let seed = 7; const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  for (let i = 0; i < 26; i++) { const s = i % 2 ? 1 : -1, g = new THREE.Group(), h = 1.8 + rnd() * 1.6;
    const tr = new THREE.Mesh(new THREE.CylinderGeometry(0.12, 0.16, 1, 6), R.trunkM); tr.position.y = 0.5; g.add(tr);
    const lf = new THREE.Mesh(new THREE.ConeGeometry(0.9 + rnd() * 0.5, h, 7), R.leafM); lf.position.y = 1 + h / 2; g.add(lf); const lf2 = new THREE.Mesh(new THREE.ConeGeometry(0.7, h * 0.7, 7), R.leafM); lf2.position.y = 1 + h * 0.85; g.add(lf2);
    g.position.x = s * (8.5 + rnd() * 5); addScroll(g, Z0 + (i / 26) * LEN + rnd() * 3); }
  for (let i = 0; i < 6; i++) [-1].forEach((s) => { const g = new THREE.Group(); const pole = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.07, 5.2, 6), R.lampM); pole.position.y = 2.6; g.add(pole);
    const arm = box(1.3, 0.06, 0.06, R.lampM, -s * 0.6, 5.15, 0, g); box(0.34, 0.08, 0.2, R.bulbM, -s * 1.2, 5.1, 0, g); g.position.x = s * 7.2; addScroll(g, Z0 + i * 20); });
  R.LEN = LEN; R.Z0 = Z0; R.scrollMax = 30;
  // tepeler (sabit)
  R.hillM = new THREE.MeshStandardMaterial({ roughness: 1, flatShading: true });
  for (let i = 0; i < 7; i++) { const h = new THREE.Mesh(new THREE.ConeGeometry(14 + rnd() * 10, 8 + rnd() * 8, 6), R.hillM); h.position.set(-60 + i * 22, 3, -85 - rnd() * 15); scene.add(h); }
  // araçlar
  R.ego = buildCar({ T, color: T.light ? "#2f6e8f" : "#8aa4b8", interior: true }); scene.add(R.ego.group); R.ego.group.add(R.dome);
  R.fol = buildCar({ T, color: T.light ? "#6b4fa0" : "#9a88c8", interior: false }); scene.add(R.fol.group); R.fol.group.rotation.y = 0;
  R.bench = buildBench(T);
  // kalkan (GÖK-GW1 engellediğinde)
  R.shield = new THREE.Mesh(new THREE.IcosahedronGeometry(1, 1), new THREE.MeshBasicMaterial({ color: T.OK, wireframe: true, transparent: true, opacity: 0, depthWrite: false })); R.shield.scale.set(1.5, 1.1, 3.0); R.shield.position.set(0, 0.8, 0); R.ego.group.add(R.shield);
  R.fill = new THREE.Mesh(new THREE.SphereGeometry(1, 20, 14), new THREE.MeshBasicMaterial({ color: T.OK, transparent: true, opacity: 0, depthWrite: false, side: THREE.BackSide })); R.fill.scale.copy(R.shield.scale); R.fill.position.copy(R.shield.position); R.ego.group.add(R.fill);
  // kamera
  R.cam = { yaw: 2.3, pitch: 0.34, dist: 19, tx: -1.8, ty: 0.9, tz: 6 }; R.camT = { ...R.cam }; R.camDef = { ...R.cam };
  applyTheme(); return true;
}

function drawRoad() {
  const T = R.T, c = R.roadTex.image, g = c.getContext("2d"); c.width = 512; c.height = 512;
  g.fillStyle = T.light ? "#6b7078" : "#3a3e44"; g.fillRect(0, 0, 512, 512);
  for (let i = 0; i < 1800; i++) { g.fillStyle = `rgba(${T.light ? "255,255,255" : "0,0,0"},${Math.random() * 0.07})`; g.fillRect(Math.random() * 512, Math.random() * 512, 2, 2); }
  const X = (x) => ((x + 5.25) / 10.5) * 512;
  g.fillStyle = "#f2f2f0"; [-1.75, 1.75].forEach((x) => g.fillRect(X(x) - 3, 0, 6, 512 * (4 / 12)));
  g.fillRect(X(-4.95) - 3, 0, 6, 512); g.fillRect(X(4.95) - 3, 0, 6, 512);
  R.roadTex.needsUpdate = true;
}
function applyTheme() {
  if (!R) return; const T = (R.T = th()), L = T.light;
  const sky = document.createElement("canvas"); sky.width = 4; sky.height = 256; const g = sky.getContext("2d"), gr = g.createLinearGradient(0, 0, 0, 256);
  gr.addColorStop(0, L ? "#6fa9d8" : "#0b0b0d"); gr.addColorStop(0.7, L ? "#cfe3f2" : "#1a1a1e"); gr.addColorStop(1, L ? "#e3eef6" : "#29292e"); g.fillStyle = gr; g.fillRect(0, 0, 4, 256);
  const tx = new THREE.CanvasTexture(sky); tx.colorSpace = THREE.SRGBColorSpace; R.scene.background = tx; R.scene.fog = new THREE.Fog(L ? "#d6e6f2" : "#1c1c20", 28, 88);
  R.hemi.color.set(L ? "#ffffff" : "#b4b4bc"); R.hemi.groundColor.set(L ? "#8a9a8a" : "#1e1e22"); R.hemi.intensity = L ? 1.05 : 1.35; R.sun.color.set(L ? "#fff1d6" : "#c8c8d0"); R.sun.intensity = L ? 1.4 : 1.7;
  R.ground.material.color.set(L ? "#86ad7c" : "#191b19"); R.leafM.color.set(L ? "#3f8a4a" : "#24382c"); R.hillM.color.set(L ? "#7d9fb5" : "#1d1d21");
  R.railM.color.set(L ? "#9aa3ab" : "#7d8791"); R.postM.color.set(L ? "#6d747b" : "#4b535b"); R.bulbM.emissiveIntensity = L ? 0.2 : 1.4;
  R.ego.mats.body.color.set(L ? "#2f6e8f" : "#8aa4b8"); R.ego.mats.panel.color.set(L ? "#2f6e8f" : "#8aa4b8"); R.fol.mats.body.color.set(L ? "#6b4fa0" : "#9a88c8"); R.fol.mats.panel.color.set(L ? "#6b4fa0" : "#9a88c8");
  [R.ego, R.fol].forEach((c) => c.mats.glass.color.set(L ? "#2c3e50" : "#111114"));
  R.shield.material.color.set(T.OK); R.fill.material.color.set(T.OK);
  const col = { A: T.A, B: T.B }; R.ego.tubes.forEach((t) => { const c = t.dom === "A" ? T.A : t.dom === "B" ? T.B : "#889"; t.mesh.material.color.set(c); t.mesh.material.emissive.set(t.dom === "T" ? "#000" : c); });
  const dc = { A: T.A, B: T.B, G: T.OK, T: T.DIAG }; Object.entries(R.ego.parts).forEach(([k, m]) => { m.material.color.set(dc[PARTS[k].dom]); m.material.emissive.set(dc[PARTS[k].dom]); });
  drawRoad(); setXray(S.xray);
}

/* ---------------- kamera ---------------- */
function camPlace() {
  const c = R.cam, T = R.camT, k = 0.12;
  if (RM.matches) Object.assign(c, T); else for (const n of ["yaw", "pitch", "dist", "tx", "ty", "tz"]) c[n] += (T[n] - c[n]) * k;
  const cx = c.tx + S.x * 0.5, cp = Math.cos(c.pitch);
  R.camera.position.set(cx + c.dist * Math.sin(c.yaw) * cp, c.ty + c.dist * Math.sin(c.pitch), c.tz + c.dist * Math.cos(c.yaw) * cp);
  R.camera.lookAt(cx, c.ty, c.tz);
}
function bindCamera(cv) {
  let drag = null;
  cv.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY }; cv.setPointerCapture(e.pointerId); });
  cv.addEventListener("pointermove", (e) => { if (!drag) return; const dx = e.clientX - drag.x, dy = e.clientY - drag.y; drag.x = e.clientX; drag.y = e.clientY; R.camT.yaw -= dx * 0.0065; R.camT.pitch = clamp(R.camT.pitch + dy * 0.005, 0.06, 1.25); S.focusOn = false; kick(); });
  const up = () => { drag = null; }; cv.addEventListener("pointerup", up); cv.addEventListener("pointercancel", up);
  cv.addEventListener("wheel", (e) => { e.preventDefault(); R.camT.dist = clamp(R.camT.dist * Math.exp(e.deltaY * 0.0012), 3.5, 24); kick(); }, { passive: false });
  cv.addEventListener("keydown", (e) => {
    const m = { ArrowLeft: () => (R.camT.yaw += 0.12), ArrowRight: () => (R.camT.yaw -= 0.12), ArrowUp: () => (R.camT.pitch = clamp(R.camT.pitch - 0.08, 0.06, 1.25)), ArrowDown: () => (R.camT.pitch = clamp(R.camT.pitch + 0.08, 0.06, 1.25)), "+": () => (R.camT.dist = clamp(R.camT.dist * 0.88, 3.5, 24)), "-": () => (R.camT.dist = clamp(R.camT.dist * 1.14, 3.5, 24)) }[e.key];
    if (m) { e.preventDefault(); m(); kick(); }
  });
}
function camReset() { Object.assign(R.camT, R.camDef); S.focusOn = false; S.sel && select(null, true); kick(); }
function camFocus(k) {
  const P = PARTS[k]; if (!R || !P) return;
  if (!P.p) { Object.assign(R.camT, { tx: -9.6, ty: 1.0, tz: 3.4, dist: 7.5, yaw: 2.2 }); return; }
  S.xray || setXray(true, false);
  const v = new THREE.Vector3(...P.p); R.ego.group.localToWorld(v); Object.assign(R.camT, { tx: v.x - S.x * 0.5, ty: v.y, tz: v.z, dist: 5.4 }); S.focusOn = true;
}

/* ---------------- röntgen / kapılar ---------------- */
function setXray(on, cam) {
  S.xray = on; if (cam && R && !S.focusOn) Object.assign(R.camT, on ? { yaw: 2.75, pitch: 0.5, dist: R.camDef.dist > 20 ? 7.6 : 6.4, tx: -0.1, ty: 0.75, tz: -0.95 } : R.camDef); const b = $("c3Xray"); if (b) b.setAttribute("aria-pressed", on);
  if (!R) return updateLabels(true);
  [R.ego.mats.body, R.ego.mats.panel].forEach((m) => { m.transparent = on; m.opacity = on ? 0.16 : 1; m.depthWrite = !on; m.needsUpdate = true; });
  R.ego.mats.glass.opacity = on ? 0.1 : 0.78; R.ego.mats.glass.needsUpdate = true; R.ego.interior.visible = on; R.shadowM.opacity = 1;
  updateLabels(true); kick();
}

/* ---------------- etiketler (3B noktalara bağlı HTML) ---------------- */
function buildLabels() {
  const host = $("c3Labels"); host.innerHTML = PART_ORDER.map((k) => { const P = PARTS[k];
    return `<button type="button" class="c3-lab d${P.dom}" data-k="${k}" aria-label="${esc(P.t)}: ne, nereye takılır"><span class="n">${esc(P.n)}</span><span class="s">${esc(P.s)}</span><span class="f">${esc(P.f ? "· " + P.f : "")}</span></button>`; }).join("");
  R.labels = PART_ORDER.map((k) => ({ k, el: host.querySelector(`[data-k="${k}"]`), w: 80, h: 28 }));
  $("c3Leaders").innerHTML = PART_ORDER.map((k) => `<line data-l="${k}" x1="0" y1="0" x2="0" y2="0"/>`).join("");
  R.leads = Object.fromEntries(PART_ORDER.map((k) => [k, $("c3Leaders").querySelector(`[data-l="${k}"]`)]));
  host.addEventListener("click", (e) => { const b = e.target.closest("[data-k]"); if (b) select(b.dataset.k); });
}
function updateLabels(measure) {
  if (!R || !R.labels) return;
  R.labels.forEach((l) => { const show = l.k === "pi1" || S.xray; l.el.hidden = !show; l.el.tabIndex = show ? 0 : -1; if (!show) R.leads[l.k].setAttribute("x2", R.leads[l.k].getAttribute("x1")); });
  const st = $("c3Stage"); st.classList.toggle("narrow", st.clientWidth < 560);
  if (measure) R.labels.forEach((l) => { if (!l.el.hidden) { l.w = l.el.offsetWidth; l.h = l.el.offsetHeight; } });
}
const _v = new THREE.Vector3();
function placeLabels() {
  const st = $("c3Stage"), w = st.clientWidth, h = st.clientHeight, items = [];
  R.labels.forEach((l) => {
    if (l.el.hidden) return;
    if (l.k === "pi1") _v.set(-9.6, 1.3, 3.4); else { _v.set(...PARTS[l.k].p); R.ego.group.localToWorld(_v); }
    _v.project(R.camera); const px = (_v.x * 0.5 + 0.5) * w, py = (-_v.y * 0.5 + 0.5) * h, ok = _v.z < 1 && px > -20 && px < w + 20 && py > -20 && py < h + 20;
    l.el.style.visibility = ok ? "visible" : "hidden"; if (ok) items.push({ l, px, py, lx: px + 12, ly: py - 34 });
  });
  // Çağrı etiketleri: noktanın tarafına göre sol/sağ sütun, her sütunda yukarıdan aşağı sıralı ve çakışmasız.
  const gap = 4, top = 4, bottom = h - 40;
  [items.filter((o) => o.px < w / 2), items.filter((o) => o.px >= w / 2)].forEach((col, side) => {
    col.sort((p, q) => p.py - q.py);
    let y = top;
    col.forEach((o) => { o.lx = side ? w - o.l.w - 8 : 8; o.ly = Math.max(y, o.py - o.l.h / 2); y = o.ly + o.l.h + gap; });
    if (col.length) { const last = col[col.length - 1], over = last.ly + last.l.h - bottom, room = col[0].ly - top; if (over > 0) col.forEach((o) => { o.ly -= Math.min(over, room); }); }
  });
  items.forEach((o) => {
    o.lx = clamp(o.lx, 4, Math.max(4, w - o.l.w - 4)); o.ly = clamp(o.ly, 4, Math.max(4, h - o.l.h - 40));
    o.l.el.style.transform = `translate(${o.lx.toFixed(0)}px,${o.ly.toFixed(0)}px)`;
    const ln = R.leads[o.l.k]; const ax = clamp(o.px, o.lx, o.lx + o.l.w), ay = clamp(o.py, o.ly, o.ly + o.l.h);
    ln.setAttribute("x1", o.px.toFixed(0)); ln.setAttribute("y1", o.py.toFixed(0)); ln.setAttribute("x2", ax.toFixed(0)); ln.setAttribute("y2", ay.toFixed(0));
  });
}

/* ---------------- seçili parça paneli ---------------- */
function select(k, silent) {
  S.sel = k; paintInfo();
  document.querySelectorAll("#p-car3d [data-k]").forEach((n) => { const on = n.dataset.k === k; n.classList.toggle("sel", on); if (n.matches(".vchip")) n.setAttribute("aria-pressed", on); });
  if (k && !silent) camFocus(k); else if (!k && !silent) { Object.assign(R.camT, R.camDef); S.focusOn = false; }
  kick();
}
function paintInfo() {
  const box = $("c3Info"), k = S.sel, P = PARTS[k];
  if (!P) { box.innerHTML = `<p class="dim">Röntgen modunda bir etikete (ya da listeden bir kartın adına) tıkla: ne olduğunu, araçta nereye takıldığını ve nasıl bağlandığını burada gör.</p>`; return; }
  const extra = k === "gw1" ? `<p><b>Hat içi:</b> iki CAN hattı (A sarı, B mavi) bu noktada birleşir; GW1 ikisinin arasındadır.</p>` : k === "tn1" ? `<p>Kartın bağlandığı OBD-II portu (gri kutu) sürücü tarafında, gösterge panelinin altındadır.</p>` : "";
  box.innerHTML = `<h3>${esc(P.t)} <span class="tag ${P.dom === "A" || P.dom === "T" ? "warn" : P.dom === "P" ? "" : "info"}">${esc(DOM_TR[P.dom])}</span></h3>
    <p class="sim">${esc(P.sim)}</p>
    <dl><dt>Nereye takılır?</dt><dd>${esc(P.where)}</dd><dt>Nasıl bağlanır?</dt><dd>${esc(P.how)}</dd></dl>${extra}
    ${P.hw ? `<a class="link" href="#hw" data-goto="hw">Kılavuz için Donanım sekmesine git →</a>` : `<p class="dim">${P.tag === "ECU" ? "Aracın kendi ECU’sudur; bizim kartlar bu ağın etrafına bağlanır." : ""}</p>`}`;
}

/* ---------------- HUD ve lambalar ---------------- */
function paintHud(m, disp) {
  const set = (id, h, cls = "") => { const n = $(id); if (!n) return; n.querySelector("b").textContent = h[0]; n.querySelector("small").textContent = h[1] || ""; n.className = "c3-t " + cls; };
  const diff = disp.cluster - disp.speed, bad = Math.abs(diff) > 15, fz = m.freeze ? "freeze" : "";
  set("hSpd", [nf(disp.speed, 0) + " km/sa", m.freeze ? "donuk" : m.replay ? "tekrar oynatılan" : "gerçek hız"], fz);
  set("hClu", [nf(disp.cluster, 0) + " km/sa", bad ? `${diff > 0 ? "+" : ""}${nf(diff, 0)} yanlış` : "gösterge"], bad ? "bad" : fz);
  set("hRpm", [nf(disp.rpm, 0), m.rpm === "cut" ? "motor kesik" : m.rpm ? "bozuk" : "d/dk"], m.rpm ? "warn" : fz);
  set("hGear", [disp.gear, m.rpm === "cut" ? "boşta" : "vites"], fz);
  set("hBrk", [nf(disp.brake, 1) + " bar", disp.brake > 20 && !(S.tel && S.tel.brake_bar > 20) ? "sahte" : "fren basıncı"], disp.brake > 20 ? "warn" : "");
  set("hStr", [nf(disp.steer, 0) + "°", m.bias ? "sahte açı" : "direksiyon"], m.bias ? "bad" : "");
  set("hGap", [nf(S.gap, 1) + " m", S.gap < 6 ? "çarpışma riski" : "arkadaki araç"], S.gap < 6 ? "bad" : "");
  set("hLane", [(S.x >= 0 ? "+" : "") + nf(S.x, 1) + " m", Math.abs(S.x) > 0.85 ? "şerit dışı" : "şerit ortası"], Math.abs(S.x) > 0.85 ? "bad" : "");
}
function paintLamps(on) {
  const host = $("c3Lamps"); if (!host.children.length) host.innerHTML = LAMPS.map(([k, n, c]) => `<span class="c3-lamp ${c}" data-lp="${k}"><i></i>${esc(n)}</span>`).join("");
  host.querySelectorAll("[data-lp]").forEach((n) => { const o = on.has(n.dataset.lp); if (n.classList.contains("on") !== o) n.classList.toggle("on", o); });
}
function say(t) { const c = $("c3Cap"); if (c && c.textContent !== t) c.textContent = t; }
function badges() {
  const set = (id, txt, cls, show = true) => { const n = $(id); if (!n) return; n.hidden = !show || !txt; if (txt) { n.textContent = txt; n.className = "c3-bd " + cls; } };
  const f = S.fx || S.fxLast;
  set("bdDemo", "Canlandırma: gerçek araçta olası etki", "demo", S.playing || !!S.fx || !!S.gw);
  if (S.gw) { const g = S.gw; const vt = (g.verdict_tr || "").replace(/^GÖK-GW1 sahada [^:]*:\s*/, "");
    if (g.v === "blocks") set("bdGw", `GÖK-GW1 engelledi (${(g.rules || []).join(", ") || "kural"}) · araç normal gidiyor`, "ok");
    else if (g.v === "partial") set("bdGw", `GÖK-GW1 kısmen engelledi (${(g.rules || []).join(", ")}) · etki azaldı`, "warn");
    else set("bdGw", "GÖK-GW1 bu saldırıyı göremez: " + (vt.length > 150 ? vt.slice(0, 147) + "…" : vt), "bad"); } else set("bdGw", "", "", false);
  const i = S.ids; set("bdIds", i && i.rules.length ? `IDS tespit etti: ${i.rules.slice(0, 3).join(", ")}${i.rules.length > 3 ? " +" + (i.rules.length - 3) : ""}${i.lat != null ? " · ≤ " + nf(i.lat, 1) + " sn" : ""}` : S.playing && S.fx ? "IDS izliyor…" : "", "info");
  const lane = Math.abs(S.x) > 0.85, bar = Math.abs(S.x) > 4.7;
  set("bdLane", bar ? "BARİYERE ÇOK YAKIN" : lane ? "ŞERİT İHLALİ" : "", "bad blink"); set("bdColl", S.gap < 6 ? (S.gap < 2.6 ? "ÇARPIŞMA!" : "ÇARPIŞMA RİSKİ: arkadaki araç çok yakın") : "", "bad blink");
  const wf = $("c3Warn"); if (wf) wf.classList.toggle("on", (lane || S.gap < 6) && !RM.matches);
}
function narrate(m) {
  const f = S.fx; if (!f) return;
  const once = (key, txt) => { if (!S.eventsSeen.has(key)) { S.eventsSeen.add(key); say(txt); } };
  if (f.key === "steer") { if (Math.abs(S.x) > 4.7) once("bar", "Araç bariyere yaklaştı: sahte açı sürerse çarpma kaçınılmaz."); else if (Math.abs(S.x) > 2.7) once("far", "Araç yan şeride geçti; sürücü müdahale etmezse bariyere gider."); else if (Math.abs(S.x) > 0.85) once("lane", "Şerit çizgisi aşıldı: şerit çıkış uyarısı veriyor, EPS yine de sahte açıyı izliyor."); }
  if (f.key === "brake" && S.gap < 6) once("gap", "Arkadaki araç çok yaklaştı: ani fren arkadan çarpma riski doğuruyor.");
  if (f.key === "speed" && f.k > 0) once("spd", "Gösterge yanlış hız gösteriyor; hıza bağlı sistemler (kapı kilidi, direksiyon yardımı) yanlış karar verebilir.");
}

/* ---------------- sim + çizim ---------------- */
function kick() { if (!S.raf && !S.tick && active()) loopStart(); }
function frame(dt) {
  const m = mods(), tel = S.tel || demoTel(); S.t += dt;
  const base = S.hold || tel, noise = S.hold ? Math.sin(S.t * 0.7) * 0.5 : 0;
  // hız
  let tgt = ((base.speed_kmh || 0) + noise) / 3.6; if (m.capKmh != null) tgt = Math.min(tgt, m.capKmh / 3.6);
  const dl = (m.decel || 7) * dt, vOld = S.v; S.v = clamp(S.v + clamp(tgt - S.v, -dl, 3 * dt), 0, 80); S.accel = lerp(S.accel, (S.v - vOld) / Math.max(dt, 1e-3), 0.15);
  // yanal dinamik
  const sb = m.steerBase != null ? m.steerBase : base.steering_deg || 0, vl = 9 * clamp(S.v / 22, 0.25, 1), steerTel = sb * 0.5, bias = m.bias || 0, steerEff = sb + bias; S.steerEff = steerEff;
  const dRad = ((steerTel + bias) / 16) * (Math.PI / 180), lka = m.noLka ? 0 : 1;
  S.psi += ((vl / 2.7) * Math.tan(dRad) + lka * (0.9 * S.x - 2.0 * S.psi)) * dt; S.psi = clamp(S.psi, -0.14, 0.14);
  S.x += -vl * Math.sin(S.psi) * dt; if (S.x < -5.15) { S.x = -5.15; S.psi = Math.max(S.psi, 0); S.hit = 1; } else if (S.x > 5.15) { S.x = 5.15; S.psi = Math.min(S.psi, 0); S.hit = 1; }
  S.hit = Math.max(0, S.hit - dt * 2);
  // arkadaki araç
  S.vSeen.push(S.v); if (S.vSeen.length > 120) S.vSeen.shift();
  const seen = S.vSeen[Math.max(0, S.vSeen.length - 1 - Math.round((S.fx && S.fx.key === "brake" ? 1.5 : 0.4) / Math.max(dt, 0.016)))] ?? S.v;
  const slow = S.fx && S.fx.key === "brake", tF = Math.max(0, seen + 0.35 * (S.gap - 14)), aF = clamp((tF - S.vF) / 0.6, slow ? -4 : -9, 2.5); S.vF = Math.max(0, S.vF + aF * dt); S.follAccel = aF;
  S.gap += (S.v - S.vF) * dt; if (S.gap < 1.7) { S.gap = 1.7; S.vF = Math.min(S.vF, S.v); } S.gap = Math.min(S.gap, 40);
  // gösterilen değerler
  const capped = m.capKmh != null, bs = base.speed_kmh != null ? base.speed_kmh : S.v * 3.6, bc = base.cluster_speed_kmh != null ? base.cluster_speed_kmh : bs;
  let d = { speed: capped ? S.v * 3.6 : bs, cluster: capped ? S.v * 3.6 + (bc - bs) : bc, rpm: base.engine_rpm || 0, gear: base.gear != null ? String(base.gear) : "—", brake: Math.max(base.brake_bar || 0, m.brakeBar || 0), steer: steerEff };
  if (m.clusterOff) d.cluster = d.speed + m.clusterOff;
  if (m.rpm === "jump") d.rpm = base.engine_rpm * (0.35 + ((Math.floor(S.t * 6) * 7919) % 100) / 60);
  if (m.rpm === "fuzz") d.rpm = ((Math.floor(S.t * 8) * 7919) % 6800) + 400;
  if (m.rpm === "cut") { d.rpm = lerp(S.rpmCut ?? d.rpm, 0, 0.1); S.rpmCut = d.rpm; d.gear = "N"; d.brake = 0; } else S.rpmCut = null;
  if (m.replay && S.hist.length > 6) { const i = Math.max(0, S.hist.length - 1 - 12 - (Math.floor(S.t * 2.5) % 12)), h = S.hist[i]; d = { ...d, speed: h.speed_kmh, cluster: h.cluster_speed_kmh, rpm: h.engine_rpm, gear: String(h.gear), brake: h.brake_bar, steer: h.steering_deg }; }
  if (m.freeze) { if (!S.frozen) S.frozen = { ...d }; d = { ...S.frozen }; } else S.frozen = null;
  // 3B
  const mv = m.shake ? Math.sin(S.t * 38) * m.shake : 0;
  if (R && S.gl) {
    const rm = RM.matches, vis = rm ? 0 : S.v, car = R.ego.group;
    R.roadTex.offset.y += (vis * 0.8 * dt) / 12; R.scroll.forEach((o) => { o.position.z += vis * 0.8 * dt; if (o.position.z > R.scrollMax) o.position.z -= R.LEN; });
    S.steerVis = lerp(S.steerVis, clamp(steerEff * 0.006, -0.6, 0.6), rm ? 1 : 0.2);
    const sway = rm ? 0 : Math.sin(S.t * 0.6) * 0.1;
    car.position.set(S.x + sway, mv * 0.6, 0); car.rotation.y = S.psi + S.steerVis * 0.05; car.rotation.x = -clamp(-S.accel * 0.012 + (m.brake ? 0.02 : 0), -0.01, 0.07) + (rm ? 0 : mv * 0.4); car.rotation.z = clamp(-S.psi * 0.1, -0.03, 0.03) + mv * 0.5;
    S.wheelSpin += rm ? 0 : (S.v * dt) / 0.34; S.fSpin += rm ? 0 : (S.vF * dt) / 0.34;
    R.ego.wheels.forEach((w) => (w.rotation.x = -S.wheelSpin)); R.fol.wheels.forEach((w) => (w.rotation.x = -S.fSpin)); R.ego.front.forEach((p) => (p.rotation.y = S.steerVis));
    if (R.ego.steerWheel) R.ego.steerWheel.rotation.z = -clamp(steerEff, -540, 540) * (Math.PI / 180) * 0.35;
    R.fol.group.position.set(S.x * 0.4, 0, 4.4 + S.gap); 
    // lambalar
    const brakeOn = !!m.brake || S.accel < -2.2 || (base.brake_bar || 0) > 8, folBrake = S.follAccel < -1.2;
    const set = (a, on) => { a.mats.tail.emissiveIntensity = on ? 3 : 0.5; a.mats.glow.opacity = on ? 0.9 : 0; }; set(R.ego, brakeOn); set(R.fol, folBrake);
    const blink = !RM.matches && Math.sin(S.t * 9) > 0, hz = m.hazard ? (RM.matches ? true : blink) : false; R.ego.mats.sig.emissiveIntensity = hz ? 3 : 0; R.ego.mats.sigGlow.opacity = hz ? 0.9 : 0; S.hazard = !!m.hazard;
    R.dome.intensity = m.unlock ? 1.6 : 0; R.ego.mats.glass.emissiveIntensity = m.unlock ? 0.55 : 0;
    // kapılar
    const t = S.fx ? (performance.now() - S.fx.t0) / 1000 : 0;
    R.ego.doors.forEach((dr, i) => { const want = S.doors ? 0.75 : m.unlock && t > 0.5 + i * 0.5 ? 0.42 : 0; S.doorOpen[i] = rm ? want : lerp(S.doorOpen[i], want, 0.1); dr.g.rotation.y = dr.sign * S.doorOpen[i]; });
    const ln = Math.abs(S.x) > 0.85; R.lineWarn.forEach((l, i) => { l.material.opacity = ln && (i === 0 ? S.x < 0 : S.x > 0) ? (rm ? 0.8 : 0.45 + 0.4 * Math.sin(S.t * 10)) : 0; });
    // kalkan
    if (S.fx && S.fx.k === 0) { S.shieldT = (S.shieldT || 0) + dt; if (rm) S.shield = 0.6; else if (S.shieldT > 1.4) { S.shieldT = 0; S.shield = 1; } }
    S.shield = rm && S.fx && S.fx.k === 0 ? 0.6 : Math.max(0, S.shield - dt * 0.9); R.shield.material.opacity = S.shield * 0.8; R.fill.material.opacity = S.shield * 0.16; R.shield.rotation.y += dt * 0.7;
    // seçili parça nabzı
    Object.entries(R.ego.parts).forEach(([k, mesh]) => { const sel = S.sel === k; mesh.scale.setScalar(sel ? 1.5 + (rm ? 0 : 0.2 * Math.sin(S.t * 6)) : 1); mesh.material.emissiveIntensity = sel ? 1.2 : 0.45; });
    camPlace(); R.renderer.render(R.scene, R.camera); placeLabels();
  }
  // metin ve HUD (seyrek)
  S.hudAcc += dt;
  if (S.hudAcc > 0.12 || RM.matches) {
    S.hudAcc = 0; paintHud(m, d);
    const on = new Set(m.lamps); if (Math.abs(S.x) > 0.85) on.add("lane"); if (S.gap < 6) on.add("coll"); if (S.fx) { }
    if (m.allLamps) LAMPS.forEach(([k]) => { if (["check", "abs", "esp", "bassist", "limp", "net"].includes(k)) on.add(k); }); paintLamps(on); badges(); narrate(m);
  }
}
function demoTel() { const t = performance.now() / 1000; return { speed_kmh: 88 + Math.sin(t * 0.4) * 5, cluster_speed_kmh: 88 + Math.sin(t * 0.4) * 5, engine_rpm: 3000 + Math.sin(t * 0.4) * 250, gear: 4, throttle_pct: 40, brake_bar: 0, steering_deg: Math.sin(t * 0.3) * 12 }; }

function loop(ts) {
  S.raf = 0; if (!active()) { S.last = 0; return; }
  const dt = Math.min(0.05, (ts - (S.last || ts)) / 1000); S.last = ts; frame(dt); S.raf = requestAnimationFrame(loop);
}
function loopStart() {
  if (!active() || S.raf || S.tick) return; S.last = 0;
  if (RM.matches) { S.tick = setInterval(() => { if (!active()) { clearInterval(S.tick); S.tick = 0; return; } frame(0.4); }, 400); frame(0.4); }
  else S.raf = requestAnimationFrame(loop);
}
function loopStop() { if (S.raf) cancelAnimationFrame(S.raf); S.raf = 0; if (S.tick) clearInterval(S.tick); S.tick = 0; }

/* ---------------- telemetri ---------------- */
let telBusy = false;
async function pollTel() {
  if (!active() || telBusy) return; telBusy = true;
  // WebSocket telemetrisi tazeyse (app.js) onu kullan; yoksa (bağlantı kopuk) REST'e düş.
  const ws = window.LAST_TEL;
  try { const t = ws && Date.now() - ws.at < 1000 ? ws.v : await api("GET", "/api/telemetry"); S.tel = t; S.telOk = true; S.hist.push({ speed_kmh: t.speed_kmh, cluster_speed_kmh: t.cluster_speed_kmh, engine_rpm: t.engine_rpm, gear: t.gear, brake_bar: t.brake_bar, steering_deg: t.steering_deg }); if (S.hist.length > 80) S.hist.shift(); if (!S.fx && !S.playing) S.clean = t; }
  catch (e) { if (S.telOk !== false) { S.telOk = false; say("Telemetri alınamadı: örnek sürüş değerleri gösteriliyor."); } S.tel = null; }
  telBusy = false;
}

/* ---------------- saldırı oynat ---------------- */
function stepsHtml() { return STEPS.map((s, i) => `<li data-i="${i}"><span class="n">${i + 1}</span><span class="tx"><b>${s}</b><span class="d"></span></span></li>`).join(""); }
function setStep(i, text) {
  document.querySelectorAll("#c3Steps li").forEach((li, j) => { li.classList.toggle("on", j === i); li.classList.toggle("done", j < i); if (j === i) li.querySelector(".d").textContent = text; });
  if (text) say(`${STEPS[i]}: ${text}`);
}
async function loadCatalog() { if (!S.catalog.length) { try { S.catalog = await api("GET", "/api/attacks"); } catch (e) { S.catalog = []; } } return S.catalog; }
async function waitPoll(ms, base) {
  const t0 = Date.now(); let last = 0;
  while (Date.now() - t0 < ms) { if (S.cancel) return true; await sleep(120); if (base && Date.now() - last > 250) { last = Date.now(); await pollAlerts(base); } }
  return S.cancel;
}
async function pollAlerts(b) {
  try {
    const l = await api("GET", "/api/alerts?limit=40"), fresh = (Array.isArray(l) ? l : []).filter((a) => a.id > b.maxId);
    if (fresh.length) { const rules = [...new Set(fresh.map((a) => a.rule_id))]; if (!S.ids) S.ids = { rules, lat: (performance.now() - b.t0) / 1000 }; else S.ids.rules = rules; }
  } catch (e) { /* sessiz */ }
}
function defOf(key) {
  if (key === "steer_spoof") return STEER_SPOOF;
  return { id: key, attack: key, params: null, fx: FXMAP[key] || "unauth" };
}
async function play(key) {
  if (S.playing) return; const def = defOf(key), A = (window.VEH_ATLAS || {})[def.attack] || {};
  S.playing = true; S.cancel = false; S.ids = null; S.gw = null; S.eventsSeen = new Set(); S.clean = S.tel || S.clean || demoTel(); S.frozen = null;
  const btn = $("c3Play"), sel = $("c3Sel"); btn.disabled = true; sel.disabled = true; $("c3Stop").hidden = false; $("c3Res").hidden = true; $("c3Res").innerHTML = "";
  document.querySelectorAll("#c3Steps li").forEach((li) => { li.classList.remove("on", "done"); li.querySelector(".d").textContent = ""; }); badges(); kick();
  let ran = false;
  try {
    setStep(0, RECON); if (await waitPoll(1700)) return; setStep(1, ACCESS); if (await waitPoll(1700)) return;
    // GÖK-GW1 kararı
    const cat = (await loadCatalog()).find((x) => x.id === def.attack), params = def.params || (cat && cat.defaults) || {};
    let ev = null, v = null;
    if (S.gwOn) {
      try { ev = await api("POST", "/api/guard/evaluate", { attack: def.attack, params }); v = ev.verdict; }
      catch (e) { v = A.v === "block" ? "blocks" : A.v === "partial" ? "partial" : A.v ? "cannot" : "cannot"; ev = { rules: A.gw || [], verdict_tr: A.gwText || "", source: "atlas" }; }
      S.gw = { v, rules: ev.rules || [], verdict_tr: ev.verdict_tr || "", blocked: ev.blocked, total: ev.total };
    }
    const k = !S.gwOn ? 1 : v === "blocks" ? 0 : v === "partial" ? 0.4 : 1;
    let base = { maxId: 0, t0: performance.now() }; try { const l = await api("GET", "/api/alerts?limit=5"); base.maxId = Math.max(0, ...(Array.isArray(l) ? l : []).map((a) => a.id)); } catch (e) { /* yok say */ }
    await api("POST", "/api/attacks/run", { attack: def.attack, duration: 8, params, combine: false }); ran = true; base.t0 = performance.now(); try { const tr = await api("GET", "/api/bus/trace?limit=1"); base.sim0 = tr.length ? tr[tr.length - 1].timestamp : null; } catch (e) { base.sim0 = null; }
    S.hold = k === 0 ? { ...S.clean } : null; S.fx = { key: def.fx, k, t0: performance.now() }; S.fxLast = S.fx; if (k === 0) S.shield = 1; S.eventsSeen = new Set();
    const manip = def.manip || A.manip || "Saldırı kareleri basılıyor.", impact = def.impact || A.impact || "";
    setStep(2, manip); if (k === 0) { S.shield = 1; say("Manipülasyon: " + manip + " GÖK-GW1 geçitte durduruyor."); }
    if (await waitPoll(2200, base)) return;
    setStep(3, k === 0 ? "GÖK-GW1 kareleri durdurdu: araç normal sürüşüne devam ediyor." : FXCAP[def.fx] || impact);
    if (k === 0) { S.shield = 1; }
    if (await waitPoll(5600, base)) return;
    await pollAlerts(base); await api("POST", "/api/attacks/stop").catch(() => {}); ran = false;
    showResult(def, A, S.gw, k);
  } catch (e) { toast(e.message, true); }
  finally {
    if (ran || S.cancel) await api("POST", "/api/attacks/stop").catch(() => {});
    if (S.cancel) say("Oynatma durduruldu.");
    S.fx = null; S.hold = null; S.playing = false; btn.disabled = false; sel.disabled = false; $("c3Stop").hidden = true; badges();
  }
}
function showResult(def, A, gw, k) {
  const res = $("c3Res"), ids = S.ids && S.ids.rules.length ? `IDS tespit etti: <b class="mono">${esc(S.ids.rules.join(", "))}</b> · tespit süresi ≤ ${nf(S.ids.lat, 1)} sn (örnekleme aralığı dahil).` : `IDS bu saldırıda alarm üretmedi. ${esc(A.detect || "")}`;
  let g = "";
  if (!S.gwOn) g = `<div class="vres gw warn"><span class="tag warn">GÖK-GW1</span><span>Anahtar kapalıydı: etki tam yaşandı.</span></div>`;
  else if (gw) { const cls = gw.v === "blocks" ? "ok" : gw.v === "partial" ? "warn" : "bad", head = gw.v === "blocks" ? "GÖK-GW1 engelledi" : gw.v === "partial" ? "GÖK-GW1 kısmen engelledi" : "GÖK-GW1 bu saldırıyı göremez";
    g = `<div class="vres gw ${cls}"><span class="tag ${cls}">GÖK-GW1</span><span><b>${head}.</b> ${esc((gw.verdict_tr || "").replace(/^GÖK-GW1 sahada [^:]*:\s*/, ""))}</span></div>`; }
  res.innerHTML = `<div class="vres ids"><span class="tag ${S.ids && S.ids.rules.length ? "info" : "warn"}">IDS</span><span>${ids}</span></div>${g}
    <div class="vres"><span class="tag">Etki</span><span>${esc(k === 0 ? "Araç etkilenmedi (canlandırma: gerçek araçta olası etki yok)." : FXCAP[def.fx] || "")}</span></div>`;
  res.hidden = false; say(k === 0 ? "Sonuç: GÖK-GW1 saldırıyı engelledi, araç normal gitti." : "Sonuç: " + (FXCAP[def.fx] || ""));
}

/* ---------------- sekme ---------------- */
function init() {
  const host = $("p-car3d"); if (S.inited) return; S.inited = true;
  host.innerHTML = `
    <div class="c3-grid">
      <div class="panel c3-main">
        <div class="panel-h"><h2>3B araç · canlı sürüş</h2><span class="hint-r">sürükle: döndür · tekerlek: yakınlaştır</span></div>
        <div class="c3-stage" id="c3Stage">
          <canvas id="c3Canvas" tabindex="0" role="img" aria-label="Üç boyutlu araç sahnesi. Ok tuşları kamerayı döndürür, artı ve eksi yakınlaştırır."></canvas>
          <div class="c3-warnfx" id="c3Warn"></div>
          <svg class="c3-leaders" id="c3Leaders" aria-hidden="true"></svg>
          <div class="c3-labels" id="c3Labels"></div>
          <div class="c3-badges" aria-live="polite">
            <div class="c3-bd demo" id="bdDemo" hidden></div><div class="c3-bd" id="bdGw" hidden></div><div class="c3-bd" id="bdIds" hidden></div><div class="c3-bd" id="bdLane" hidden></div><div class="c3-bd" id="bdColl" hidden></div>
          </div>
          <div class="c3-tools">
            <button class="btn" type="button" id="c3Xray" aria-pressed="false" title="Gövdeyi yarı saydam yap: kartları ve ECU’ları göster"><svg class="ico"><use href="#i-search"/></svg><span>Röntgen</span></button>
            <button class="btn" type="button" id="c3Doors" aria-pressed="false" title="Kapıları aç / kapat"><svg class="ico"><use href="#i-lock"/></svg><span>Kapılar</span></button>
            <button class="ibtn" type="button" id="c3Reset" aria-label="Kamerayı sıfırla" title="Kamerayı sıfırla"><svg class="ico"><use href="#i-reset"/></svg></button>
          </div>
          <div class="c3-fallback" id="c3Fb" hidden><div><b>3B görünüm bu tarayıcıda açılamadı</b>WebGL desteklenmiyor ya da kapalı. Canlı HUD, saldırı canlandırması metinleri ve “kartlar araçta nerede” listesi aşağıda ve yanda çalışmaya devam eder.</div></div>
        </div>
        <div class="c3-lamps" id="c3Lamps" aria-label="Gösterge uyarı lambaları"></div>
        <p class="vcap" id="c3Cap" role="status" aria-live="polite">Araç canlı telemetriyle sürüyor: yol hızına, direksiyona ve frene tepki verir. Bir saldırı seçip “Oynat”a bas.</p>
      </div>
      <div class="c3-side">
        <div class="panel"><div class="panel-h"><h2>Canlı HUD</h2><span class="hint-r" id="c3TelSrc">telemetri</span></div>
          <div class="c3-hud" id="c3Hud">${[["hSpd", "Gerçek hız"], ["hClu", "Gösterge hızı"], ["hRpm", "Devir"], ["hGear", "Vites"], ["hBrk", "Fren"], ["hStr", "Direksiyon"], ["hGap", "Takip mesafesi"], ["hLane", "Şerit konumu"]].map(([i, n]) => `<div class="c3-t" id="${i}"><span>${n}</span><b>—</b><small></small></div>`).join("")}</div></div>
        <div class="panel"><div class="panel-h"><h2>Saldırı sonucu canlandırması</h2><span class="hint-r">araçta ne olabilir?</span></div>
          <label class="fld"><span>Saldırı</span><select id="c3Sel"></select></label>
          <div class="c3-ctl"><label class="chk"><span class="switch"><input type="checkbox" id="c3Gw" checked><i></i></span><span>GÖK-GW1 devrede</span></label></div>
          <div class="row" style="margin-top:12px"><button class="btn primary" id="c3Play" type="button"><svg class="ico"><use href="#i-play"/></svg><span>Oynat</span></button><button class="btn" id="c3Stop" type="button" hidden><svg class="ico"><use href="#i-square"/></svg><span>Durdur</span></button></div>
          <p class="c3-note">Canlandırma: gerçek araçta olası etki. Saldırı gerçekten benzetim hattına gönderilir; araçtaki sonuç, GÖK-GW1 kararına göre canlandırılır.</p>
          <ol class="vsteps" id="c3Steps">${stepsHtml()}</ol><div class="c3-res" id="c3Res" hidden></div></div>
        <div class="panel"><div class="panel-h"><h2>Kartlar araçta nerede?</h2><span class="hint-r">röntgen modunda işaretli</span></div>
          <div class="c3-chips" id="c3Chips">${PART_ORDER.map((k) => `<button type="button" class="vchip" data-k="${k}" aria-pressed="false"><span>${esc(PARTS[k].n)}</span></button>`).join("")}</div>
          <div class="c3-info" id="c3Info" style="margin-top:16px"></div>
          <div class="vleg inline" aria-label="Hat renkleri"><span><i class="sw" style="background:var(--warn)"></i>CAN A (OBD / bilgi-eğlence)</span><span><i class="sw" style="background:var(--accent)"></i>CAN B (güç aktarma / fren)</span><span><i class="sw" style="background:var(--ok)"></i>GÖK-GW1</span></div></div>
      </div>
    </div>`;
  // saldırı seçici
  const keys = Object.keys(window.VEH_ATLAS || {}); const nm = (k) => (typeof atkName === "function" ? atkName(k) : k);
  $("c3Sel").innerHTML = `<option value="steer_spoof">${esc(STEER_SPOOF.name)}</option>` + keys.map((k) => `<option value="${k}">${esc(nm(k))}</option>`).join("");
  $("c3Play").addEventListener("click", () => play($("c3Sel").value)); $("c3Stop").addEventListener("click", () => { S.cancel = true; });
  $("c3Gw").addEventListener("change", (e) => { S.gwOn = e.target.checked; say(S.gwOn ? "GÖK-GW1 devrede: önce karar verir, engellenen saldırının etkisi canlandırılmaz." : "GÖK-GW1 devre dışı: saldırı tam etkisiyle canlandırılır."); });
  $("c3Xray").addEventListener("click", () => setXray(!S.xray, true)); $("c3Reset").addEventListener("click", () => camReset());
  $("c3Doors").addEventListener("click", () => { S.doors = !S.doors; $("c3Doors").setAttribute("aria-pressed", S.doors); kick(); });
  $("c3Chips").addEventListener("click", (e) => { const b = e.target.closest("[data-k]"); if (b) select(S.sel === b.dataset.k ? null : b.dataset.k); });
  S.gl = initScene();
  if (S.gl) { buildLabels(); bindCamera($("c3Canvas")); setXray(false); updateLabels(true); const ro = new ResizeObserver(resize); ro.observe($("c3Stage")); resize(); }
  else { $("c3Fb").hidden = false; $("c3Canvas").hidden = true; }
  paintInfo(); paintLamps(new Set());
  new MutationObserver(() => { applyTheme(); kick(); }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
}
function resize() {
  const st = $("c3Stage"), w = st.clientWidth, h = st.clientHeight; if (!R || !w || !h) return;
  R.renderer.setSize(w, h, false); R.camera.aspect = w / h; R.camDef.dist = w / h < 1.4 ? 27 : 19; if (!S.focusOn && !S.sel) R.camT.dist = R.camDef.dist; R.camera.fov = w / h < 1.4 ? 42 : 36; R.camera.updateProjectionMatrix();
  updateLabels(true); kick();
}
function show() {
  if (!S.inited) init();
  S.eventsSeen = new Set(); pollTel(); loopStart(); setTimeout(resize, 30);
  const h = location.hash.split("/")[1]; if (h && $("c3Sel") && [...$("c3Sel").options].some((o) => o.value === h)) $("c3Sel").value = h;
}
setInterval(pollTel, 220);
document.addEventListener("visibilitychange", () => { if (!document.hidden) loopStart(); else loopStop(); });
window.addEventListener("hashchange", () => { setTimeout(() => { if (active()) loopStart(); }, 50); });
RM.addEventListener && RM.addEventListener("change", () => { loopStop(); loopStart(); });
window.Car3D = { show, play, dbg: () => ({ R, S, frame }) };
if (document.body.dataset.tab === "car3d") show();
