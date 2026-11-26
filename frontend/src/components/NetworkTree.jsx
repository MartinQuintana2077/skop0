import { useState, useRef, useCallback, useMemo, useEffect } from "react";



/* ─── UTILIDADES ────────────────────────────────────────────── */

function isPrivateIP(ip) {

  if (!ip) return false;

  const [a, b] = ip.split(".").map(Number);

  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);

}

function getSubnetPrefix(ip) { return ip ? ip.split(".").slice(0, 3).join(".") : ""; }



function chunkArray(arr, size) {

  if (!arr) return [];

  return Array.from({ length: Math.ceil(arr.length / size) }, (v, i) =>

    arr.slice(i * size, i * size + size)

  );

}



function getScoreColor(s) {

  if (!s || s === 0) return "#10b981";

  if (s >= 9.0) return "#f43f5e";

  if (s >= 7.0) return "#f97316";

  if (s >= 4.0) return "#eab308";

  return "#10b981";

}

function getRiskLabel(s) {

  if (!s || s === 0) return "SEGURO";

  if (s >= 9.0) return "CRÍTICO";

  if (s >= 7.0) return "ALTO";

  if (s >= 4.0) return "MEDIO";

  return "BAJO";

}



export function isScannerHost(d, localIp = null) {

  if (!d) return false;

  if (d.es_host_local === true || d.es_scanner === true) return true;

  if (localIp && d.ip === localIp) return true;

  const cat = (d.categoria_nombre || "").toLowerCase();

  const conf = (d.confianza_clasificacion || "").toLowerCase();

  if (cat.includes("host local") || conf.includes("host de escaneo")) return true;

  return false;

}



export function getDeviceConnectionMedium(d, routerIp = null) {
  if (!d) return null;

  // 1. Si el backend ya determino medio_conexion, respetarlo
  if (d.medio_conexion && d.medio_conexion !== "indeterminado") {
    return {
      medio: d.medio_conexion,
      label: d.medio_label || (d.medio_conexion === "wifi" ? "Wi-Fi" : "Ethernet"),
      icono: d.medio_icono || (d.medio_conexion === "wifi" ? "📶" : "🔌"),
      detalle: d.medio_detalle || ""
    };
  }

  // 2. Si es el host escaner (este equipo)
  if (d.es_scanner || d.es_host_local) {
    const iface = (d.interfaz_nombre || "").toLowerCase();
    const isWifi = iface.includes("wi-fi") || iface.includes("wlan") || iface.includes("wireless") || iface.includes("inalambric") || iface.includes("inalámbric");
    return {
      medio: isWifi ? "wifi" : "ethernet",
      label: isWifi ? "Wi-Fi" : "Ethernet",
      icono: isWifi ? "📶" : "🔌",
      detalle: isWifi ? "Adaptador Local Wi-Fi" : "Adaptador Local Ethernet"
    };
  }

  // 3. Si es el Router / Gateway
  if (d.es_gateway === true || (routerIp && d.ip === routerIp)) {
    return {
      medio: "ethernet",
      label: "Ethernet / AP",
      icono: "📡",
      detalle: "Router Gateway (Enlace Central)"
    };
  }

  const f = (d.fabricante || d.vendor || "").toLowerCase();
  const h = (d.hostname || "").toLowerCase();
  const tipo = (d.dispositivo_tipo || d.tipo || d.categoria_nombre || "").toLowerCase();
  const ports = (d.puertos_abiertos || []).map(p => typeof p === "object" ? (p.puerto || p.port) : p).filter(Boolean);

  // 4. Deteccion matematica de MAC Aleatoria (LAA) -> 100% Wi-Fi en smartphones/tablets
  const isRandomMac = (() => {
    if (!d.mac || typeof d.mac !== "string") return false;
    const lower = d.mac.toLowerCase();
    if (lower.includes("desconocid") || lower.includes("detectand") || lower.includes("sondeand") || lower.includes("unknown") || lower.includes("none")) {
      return false;
    }
    const clean = d.mac.replace(/[^0-9A-Fa-f]/g, "");
    if (clean.length !== 12) return false;
    try {
      return (parseInt(clean.slice(0, 2), 16) & 0x02) !== 0;
    } catch {
      return false;
    }
  })();

  if (isRandomMac) {
    return {
      medio: "wifi",
      label: "Wi-Fi",
      icono: "📶",
      detalle: "Direccion MAC Privada (Wi-Fi)"
    };
  }

  // 5. Chipsets y Domotica Exclusivamente Wi-Fi
  const wifiChips = ["espressif", "tuya", "sonoff", "shelly", "broadlink", "smart life", "azurewave", "murata", "liteon", "fn-link", "chiun mai", "ampak"];
  if (wifiChips.some(k => f.includes(k))) {
    return {
      medio: "wifi",
      label: "Wi-Fi",
      icono: "📶",
      detalle: "Chipset Wi-Fi Integrado (IoT)"
    };
  }

  // 6. Streaming sticks, asistentes y camaras Wi-Fi
  const streamingWifi = ["roku", "chromecast", "firestick", "fire tv"];
  if (streamingWifi.some(k => f.includes(k) || h.includes(k))) {
    return {
      medio: "wifi",
      label: "Wi-Fi",
      icono: "📶",
      detalle: "Dispositivo Streaming (Wi-Fi)"
    };
  }

  const smartSpeakers = ["google nest", "google home", "amazon echo", "echo dot", "echo show"];
  if (smartSpeakers.some(k => f.includes(k) || h.includes(k))) {
    return {
      medio: "wifi",
      label: "Wi-Fi",
      icono: "📶",
      detalle: "Altavoz Inteligente (Wi-Fi)"
    };
  }

  const wifiCams = ["tapo", "wyze", "eufy", "ring", "blink", "imou", "yi technology"];
  if (wifiCams.some(k => f.includes(k) || h.includes(k))) {
    return {
      medio: "wifi",
      label: "Wi-Fi",
      icono: "📶",
      detalle: "Camara Wi-Fi Residencial"
    };
  }

  // 7. Smartphones y Tablets (Moviles)
  const mobileBrands = ["apple", "samsung", "xiaomi", "redmi", "poco", "huawei", "motorola", "oppo", "vivo", "oneplus", "realme", "honor", "zte", "pixel", "tecno", "infinix"];
  const mobileHosts = ["iphone", "ipad", "android", "galaxy", "redmi", "pixel", "phone", "mobile", "celular"];
  const isApplePc = f.includes("apple") && (h.includes("macbook") || h.includes("imac") || h.includes("mac"));

  if ((mobileBrands.some(k => f.includes(k)) || mobileHosts.some(k => h.includes(k)) || tipo.includes("phone") || tipo.includes("mobile") || tipo.includes("móvil") || tipo.includes("tablet")) && !isApplePc) {
    return {
      medio: "wifi",
      label: "Wi-Fi",
      icono: "📶",
      detalle: "Dispositivo Movil / Enlace Inalambrico"
    };
  }

  // 8. Infraestructura y Equipos Cableados PoE / Ethernet
  const isVoip = ports.some(p => [5060, 5061].includes(p)) || ["yealink", "grandstream", "polycom", "poly", "fanvil", "snom", "avaya"].some(k => f.includes(k)) || h.includes("sip") || h.includes("voip");
  if (isVoip) {
    return {
      medio: "ethernet",
      label: "Ethernet",
      icono: "🔌",
      detalle: "Telefono IP PoE Cableado"
    };
  }

  const isNvrCctv = ports.some(p => [37777, 34567, 8000, 8001, 8200].includes(p)) || ["hikvision", "dahua", "xiongmai", "uniview", "cctv", "nvr", "dvr"].some(k => f.includes(k) || h.includes(k));
  if (isNvrCctv) {
    return {
      medio: "ethernet",
      label: "Ethernet",
      icono: "🔌",
      detalle: "Grabador NVR/DVR Cableado"
    };
  }

  const isServer = ["synology", "qnap", "truenas", "freenas", "proxmox", "vmware", "esxi", "poweredge", "proliant", "supermicro"].some(k => f.includes(k) || h.includes(k)) || tipo.includes("server") || tipo.includes("nas") || tipo.includes("servidor");
  if (isServer) {
    return {
      medio: "ethernet",
      label: "Ethernet",
      icono: "🔌",
      detalle: "Servidor / NAS Cableado"
    };
  }

  const isSwitchRouter = ["cisco", "fortinet", "palo alto", "pfsense", "juniper", "edgeswitch"].some(k => f.includes(k)) || ["switch", "sw-", "firewall"].some(k => h.includes(k));
  if (isSwitchRouter) {
    return {
      medio: "ethernet",
      label: "Ethernet",
      icono: "🔌",
      detalle: "Switch / Enlace de Red Cableado"
    };
  }

  const isPrinter = ports.some(p => [9100, 515, 631].includes(p)) || ["epson", "brother", "lexmark", "canon", "kyocera", "ricoh", "xerox", "konica"].some(k => f.includes(k)) || tipo.includes("printer") || tipo.includes("impresora");
  if (isPrinter) {
    return {
      medio: "ethernet",
      label: "Ethernet",
      icono: "🔌",
      detalle: "Impresora de Red Cableada"
    };
  }

  // 9. Desktops vs Laptops
  if (["desktop-", "ws-", "workstation", "pc-"].some(k => h.includes(k)) || ["gigabyte", "asrock", "biostar", "micro-star", "msi"].some(k => f.includes(k))) {
    return {
      medio: "ethernet",
      label: "Ethernet",
      icono: "🔌",
      detalle: "PC de Escritorio / Estacion Fija"
    };
  }

  if (["laptop-", "notebook", "macbook", "nb-"].some(k => h.includes(k)) || isApplePc) {
    return {
      medio: "wifi",
      label: "Wi-Fi",
      icono: "📶",
      detalle: "Computadora Portatil (Wi-Fi)"
    };
  }

  // 10. Telemetria de Latencia y Jitter
  if (d.telemetria) {
    const avg = d.telemetria.latency_ms;
    const min = d.telemetria.latency_min;
    const max = d.telemetria.latency_max;
    const loss = d.telemetria.packet_loss || 0;
    if (avg !== null && avg !== undefined && min !== null && min !== undefined && max !== null && max !== undefined) {
      const jitter = max - min;
      if (avg <= 2.5 && jitter <= 2.0 && loss === 0) {
        return {
          medio: "ethernet",
          label: "Ethernet",
          icono: "🔌",
          detalle: `Enlace Cableado (Latencia ${avg} ms, Jitter ${jitter.toFixed(1)} ms)`
        };
      }
      if (avg >= 5.0 || jitter >= 8.0 || loss > 0) {
        return {
          medio: "wifi",
          label: "Wi-Fi",
          icono: "📶",
          detalle: `Enlace Inalambrico (Latencia ${avg} ms, Jitter ${jitter.toFixed(1)} ms)`
        };
      }
    }
  }

  return {
    medio: "ethernet",
    label: "Ethernet",
    icono: "🔌",
    detalle: "Enlace de Red Cableado"
  };
}

export function getDeviceIcon(d, routerIp = null) {
  if (!d) return "💻";
  if (d.es_gateway === true || (routerIp && d.ip === routerIp)) return "📡";

  const f = (d.fabricante || d.vendor || "").toLowerCase();
  const h = (d.hostname || "").toLowerCase();
  const tipo = (d.dispositivo_tipo || d.tipo || d.categoria_nombre || "").toLowerCase();

  // 1. Si d.icono ya viene con un valor
  if (d.icono && typeof d.icono === "string" && d.icono.trim() !== "") {
    const ic = d.icono.trim();
    // Si ya es un emoji
    if (["💻","📱","📡","📺","📷","🖨️","🎮","🗄️","💡","🍎","📞","🌐","🔀","❓"].includes(ic)) {
      return ic;
    }
    // Mapeo seguro de nombres legacy/backend a emoji (NUNCA retornar texto plano "help-circle")
    const iconMap = {
      "pc": "💻", "desktop": "💻", "laptop": "💻", "workstation": "💻",
      "phone": "📱", "smartphone": "📱", "mobile": "📱", "tablet": "📱", "voip": "📞",
      "router": "📡", "gateway": "📡", "ap": "📡", "wifi": "📡", "extender": "📡", "switch": "🔀", "conmutador": "🔀",
      "printer": "🖨️",
      "camera": "📷", "nvr": "📷", "dvr": "📷",
      "tv": "📺", "screen": "📺", "display": "📺",
      "server": "🗄️", "nas": "🗄️", "database": "🗄️",
      "game_console": "🎮", "console": "🎮",
      "iot": "💡",
      "network": "🌐", "generic": "🌐", "device": "🌐",
      "help-circle": "🌐", "help": "🌐", "unknown": "🌐", "desconocido": "🌐"
    };
    if (iconMap[ic.toLowerCase()]) {
      return iconMap[ic.toLowerCase()];
    }
  }

  const ports = (d.puertos_abiertos || []).map(p => {
    if (typeof p === "number") return p;
    if (typeof p === "string" && !isNaN(Number(p))) return Number(p);
    if (p && typeof p === "object") return Number(p.puerto || p.port || 0);
    return 0;
  }).filter(p => p > 0);

  // 2. Puertos de Servidores / DB / SSH / Web Enterprise
  const isServerPort = ports.some(p => [22, 80, 443, 8080, 8443, 5000, 5001, 3306, 5432, 1433, 1521, 27017, 389, 636, 88, 21, 25].includes(p));
  const isServerBrand = ["synology", "qnap", "vmware", "proxmox", "supermicro", "hpe", "dell emc", "red hat", "canonical"].some(k => f.includes(k));
  const isServerHost = ["server", "srv", "nas", "proxmox", "esxi", "docker", "ubiquiti-controller", "dc-", "ad-", "sql", "db-", "mail", "cloud"].some(k => h.includes(k));
  if (isServerPort || isServerBrand || isServerHost || tipo.includes("server") || tipo.includes("nas") || tipo.includes("servidor")) {
    return "🗄️";
  }

  // 3. Telefonía IP / VoIP (SIP 5060, 5061, marcas VoIP)
  const isVoipPort = ports.some(p => [5060, 5061].includes(p));
  const isVoipBrand = ["yealink", "grandstream", "polycom", "poly", "avaya", "fanvil", "snom"].some(k => f.includes(k));
  if (isVoipPort || isVoipBrand || h.includes("sip") || h.includes("voip") || h.includes("yealink") || tipo.includes("voip")) {
    return "📞";
  }

  // 4. Impresoras de Red (Raw 9100, LPD 515, IPP 631)
  const isPrinterPort = ports.some(p => [9100, 515, 631].includes(p));
  const isPrinterBrand = ["epson", "brother", "lexmark", "canon", "kyocera", "ricoh", "xerox", "konica"].some(k => f.includes(k));
  if (isPrinterPort || isPrinterBrand || h.includes("print") || tipo.includes("printer") || tipo.includes("impresora")) {
    return "🖨️";
  }

  // 5. Cámaras de Seguridad / NVR
  const isCameraPort = ports.some(p => [554, 8554, 8899, 8999, 37777, 37778, 34567, 8000, 8001, 8200, 10554].includes(p));
  const isCameraBrand = ["hikvision", "dahua", "axis", "reolink", "amcrest", "foscam", "uniview", "vivotek", "ezviz", "imou", "tiandy", "hanwha", "lorex", "swann", "arlo", "wyze", "xiongmai", "tapo", "eufy", "ring", "blink", "bosch security", "pelco", "vstarcam"].some(k => f.includes(k));
  if (isCameraPort || isCameraBrand || h.includes("cam") || h.includes("nvr") || h.includes("dvr") || h.includes("ipc") || h.includes("cctv") || tipo.includes("camera") || tipo.includes("cámara")) {
    return "📷";
  }

  // 6. Router / Switch / Punto de Acceso
  const isNetBrand = ["cisco", "mikrotik", "ubiquiti", "tp-link", "netgear", "d-link", "aruba", "mercusys", "tenda", "fortinet", "palo alto", "pfsense", "juniper"].some(k => f.includes(k));
  const isNetHost = ["router", "gateway", "ap", "repeater", "extender", "wlan", "switch", "sw-", "firewall"].some(k => h.includes(k));
  if ((ports.includes(53) && ports.some(p => [67, 68, 80, 443].includes(p))) || ports.includes(161) || isNetBrand || isNetHost || tipo.includes("router") || tipo.includes("gateway") || tipo.includes("ap")) {
    return "📡";
  }

  // 7. Smart TV / Pantallas
  const isTvPort = ports.some(p => [8009, 8008, 8060, 1900, 7000, 7676, 7678, 9197].includes(p));
  const isTvBrand = ["roku", "tcl", "hisense", "lg electronics", "vizio", "wuhan", "ipg", "display", "screen", "novastar", "colorlight", "linsn", "skyworth", "sharp", "panasonic"].some(k => f.includes(k));
  const isSamsungTv = f.includes("samsung") && (ports.some(p => [8080, 8001, 8002, 7676, 7678, 9197, 1900].includes(p)) || ["tv", "tizen", "smart", "screen"].some(k => h.includes(k)));
  if (isTvPort || isTvBrand || isSamsungTv || h.includes("tv") || h.includes("chromecast") || tipo.includes("tv") || tipo.includes("streaming")) {
    return "📺";
  }

  // 8. Consolas de Videojuegos
  if (ports.some(p => [3074, 3478, 3479, 3480].includes(p)) || ["nintendo", "playstation"].some(k => f.includes(k)) || ["xbox", "playstation", "ps4", "ps5"].some(k => h.includes(k)) || (h.includes("switch") && f.includes("nintendo")) || tipo.includes("game_console")) {
    return "🎮";
  }

  // 9. Domótica / IoT
  if (ports.some(p => [1883, 5683, 8883].includes(p)) || ["tuya", "sonoff", "shelly", "espressif", "esp32", "esp8266", "philips hue"].some(k => f.includes(k)) || h.includes("iot") || tipo.includes("iot")) {
    return "💡";
  }

  // 10. PC / Laptop / Estaciones de Trabajo
  const hasWindowsPorts = ports.some(p => [135, 139, 445, 3389, 5985, 5986, 5357].includes(p));
  const isPCBrand = ["dell", "lenovo", "asus", "acer", "msi", "gigabyte", "microsoft", "toshiba", "fujitsu", "intel", "hp", "hewlett-packard"].some(k => f.includes(k));
  const isPCHost = ["pc", "desktop", "laptop", "macbook", "win", "workstation", "ws-", "desk", "nb-"].some(k => h.includes(k));
  if (hasWindowsPorts || isPCBrand || isPCHost || tipo.includes("pc") || tipo.includes("laptop") || tipo.includes("workstation")) {
    return "💻";
  }

  // Detección matemática de MAC Aleatoria (LAA / Private Wi-Fi MAC de smartphones/tablets)
  const isRandomMac = (() => {
    if (!d.mac || typeof d.mac !== "string") return false;
    const lower = d.mac.toLowerCase();
    if (lower.includes("desconocid") || lower.includes("detectand") || lower.includes("sondeand") || lower.includes("unknown")) {
      return false;
    }
    const clean = d.mac.replace(/[^0-9A-Fa-f]/g, "");
    if (clean.length !== 12) return false;
    try {
      return (parseInt(clean.slice(0, 2), 16) & 0x02) !== 0;
    } catch {
      return false;
    }
  })();

  // 11. Dispositivos Móviles (Móvil verificado por fabricante, hostname o MAC aleatoria genuina)
  const isMobileBrand = ["apple", "samsung", "xiaomi", "redmi", "poco", "huawei", "motorola", "oppo", "vivo", "oneplus", "realme", "honor", "zte", "google", "pixel", "nokia", "meizu", "tecno", "infinix"].some(k => f.includes(k)) ||
                        ["iphone", "ipad", "android", "galaxy", "redmi", "pixel", "phone", "mobile", "celular"].some(k => h.includes(k));
  if (isMobileBrand || (isRandomMac && !hasWindowsPorts)) {
    if (f.includes("apple") && (h.includes("macbook") || h.includes("mac"))) return "💻";
    if (f.includes("apple")) return "🍎";
    return "📱";
  }

  // 12. Fallback inteligente: dispositivos de red / periféricos (nunca asumir PC sin evidencia)
  if (tipo.includes("network") || tipo.includes("periférico") || tipo.includes("red")) {
    return "🌐";
  }
  if (isRandomMac) {
    return "📱";
  }
  return "🌐";
}

function buildTree(devices, topology) {

  if (!devices?.length && (!topology || !topology.hops_privados?.length)) return null;

  

  const bySubnet = {};

  (devices || []).forEach(d => {

    if (!d || !d.ip) return;

    const p = getSubnetPrefix(d.ip);

    if (!bySubnet[p]) bySubnet[p] = [];

    bySubnet[p].push(d);

  });



  if (topology && topology.hops_privados && topology.hops_privados.length > 0) {

    const hops = topology.hops_privados;

    const mainHop = hops[0];

    const mainPrefix = mainHop ? getSubnetPrefix(mainHop.ip) : null;

    const routerIp = topology.router_principal_ip || mainHop?.ip || (mainPrefix ? `${mainPrefix}.1` : null);

    const routerDevice = (devices || []).find(d => d.ip === routerIp);
    const enrichedGateway = {
      ...mainHop,
      ...(routerDevice ? {
        fabricante: routerDevice.fabricante || routerDevice.vendor || mainHop.fabricante,
        mac: routerDevice.mac || mainHop.mac,
        hostname: mainHop.hostname && !mainHop.hostname.includes("Router Principal (C)") ? mainHop.hostname : (routerDevice.hostname || mainHop.hostname),
        ssid: mainHop.ssid || topology.network_name
      } : {
        ssid: mainHop.ssid || topology.network_name
      })
    };

    const mainDevs = (bySubnet[mainPrefix] || []).filter(d => d.ip !== routerIp);
    const main = mainPrefix ? {

      prefix: mainPrefix,

      gateway: enrichedGateway,

      devices: mainDevs,

      total: (bySubnet[mainPrefix] || []).length

    } : null;



    const upstreamHops = hops.slice(1);

    const cgnatGroup = upstreamHops.length > 0 ? {

      count: upstreamHops.length,

      hops: upstreamHops

    } : null;



    const knownPrefixes = [mainPrefix].filter(Boolean);

    const orphanSubnets = Object.entries(bySubnet)

      .filter(([prefix]) => !knownPrefixes.includes(prefix))

      .map(([prefix, devs]) => {
        const gwIp = `${prefix}.1`;
        const gwDev = devs.find(d => d.ip === gwIp) || { ip: gwIp, hostname: 'Gateway Inferido' };
        const subDevs = devs.filter(d => d.ip !== routerIp && d.ip !== gwIp);
        return {
          prefix,
          gateway: gwDev,
          devices: subDevs,
          total: devs.length,
        };
      });



    const resolvedMain = main || orphanSubnets[0];

    if (!resolvedMain) return null;



    return { 

      isp: topology.router_isp, 

      cgnatGroup,

      main: resolvedMain, 

      extensors: main ? orphanSubnets : orphanSubnets.slice(1) 

    };

  }



  const subnets = Object.entries(bySubnet)

    .map(([prefix, devs]) => {
      const gwIp = `${prefix}.1`;
      const gwDev = devs.find(d => d.ip === gwIp) || null;
      const subDevs = devs.filter(d => d.ip !== gwIp);
      return {
        prefix,
        gateway: gwDev,
        devices: subDevs,
        total: devs.length,
      };
    })

    .sort((a, b) => b.total - a.total);

    

  if (!subnets.length || !subnets[0]) return null;



  return { isp: null, cgnatGroup: null, main: subnets[0], extensors: subnets.slice(1) };

}



/* ─── CARD: CGNAT / PROVEEDOR INTERMEDIO ─────────────────────── */

function CgnatGroupCard({ count, hops, onClick }) {

  const sampleIp = hops && hops.length > 0 ? hops[0].ip : null;



  return (

    <div 

      className="nt-card nt-card--cgnat" 

      onClick={onClick}

      style={{ border: "1px dashed rgba(56,189,248,0.35)", background: "#1e293b", cursor: "pointer" }}

      title="Clic para ver detalle de nodos ISP en el panel lateral"

    >

      <div className="nt-card-icon">📶</div>

      <div className="nt-card-label" style={{ color: "#38bdf8", fontWeight: "bold" }}>

        {count === 1 ? "Red Móvil / Enrutamiento ISP" : `${count} Nodos ISP / CGNAT`}

      </div>

      {sampleIp && sampleIp !== "unknown" && <div className="nt-card-ip">{sampleIp}</div>}

      <div className="nt-badge" style={{ background: "rgba(56,189,248,0.12)", color: "#38bdf8", border: "1px solid rgba(56,189,248,0.25)", marginTop: 4, fontWeight: "bold" }}>

        VER NODOS ISP ↗

      </div>

    </div>

  );

}



/* ─── CARD: INTERNET ────────────────────────────────────────── */

function InternetCard() {

  return (

    <div className="nt-card nt-card--internet">

      <div className="nt-card-icon">🌐</div>

      <div className="nt-card-label">Internet</div>

      <div className="nt-badge" style={{ background: "rgba(56,189,248,0.12)", color: "#38bdf8", border: "1px solid rgba(56,189,248,0.25)" }}>

        INTERNET

      </div>

    </div>

  );

}



/* ─── CARD: GATEWAY ─────────────────────────────────────────── */

function GatewayCard({ ip, hostname, fabricante, mac, ssid, onFocus }) {

  const cardRef = useRef(null);

  const rawTitle = ssid || hostname || "Router Principal";
  const displayTitle = rawTitle.replace(/^Red\s+/i, "");
  const fabDisplay = fabricante && fabricante !== "Desconocido" && !fabricante.includes("Gateway")
    ? `Router • ${fabricante}`
    : "Router Principal / Gateway";

  return (

    <div 

      ref={cardRef}

      className="nt-card nt-card--gateway"

      onClick={() => onFocus && onFocus(cardRef.current)}

      style={{ cursor: "pointer" }}

    >

      <div className="nt-card-icon">🔵</div>

      <div className="nt-card-label" style={{ fontWeight: 700, fontSize: "14px", color: "#f8fafc" }}>
        {displayTitle}
      </div>

      <div className="nt-card-hostname" style={{ fontSize: "12px", color: "#94a3b8" }}>
        {fabDisplay}
      </div>

      <div className="nt-card-ip">{ip}</div>

      {mac && mac !== "Desconocida" && (
        <div className="nt-card-fab" style={{ fontSize: "11px", color: "#64748b", fontFamily: "monospace" }}>
          {mac}
        </div>
      )}

      <div className="nt-badge" style={{ background: "rgba(59,130,246,0.15)", color: "#93c5fd", border: "1px solid rgba(59,130,246,0.3)" }}>

        GATEWAY • ROUTER

      </div>

    </div>

  );

}



/* ─── CARD: EXTENSOR ────────────────────────────────────────── */

function ExtensorCard({ ip, hostname, fabricante, deviceCount, nat_habilitado, onFocus }) {

  const cardRef = useRef(null);

  return (

    <div 

      ref={cardRef}

      className="nt-card nt-card--extensor"

      onClick={() => onFocus && onFocus(cardRef.current)}

      style={{ cursor: "pointer" }}

    >

      <div className="nt-card-icon">📡</div>

      <div className="nt-card-label">{hostname || "Extensor / AP"}</div>

      <div className="nt-card-ip">{ip}</div>

      {fabricante && fabricante !== "Desconocido" && <div className="nt-card-fab">{fabricante}</div>}

      <div style={{ display: "flex", gap: 6, justifyContent: "center", flexWrap: "wrap" }}>

        <div className="nt-badge" style={{ background: "rgba(245,158,11,0.15)", color: "#fbbf24", border: "1px solid rgba(245,158,11,0.3)" }}>

          EXTENSOR

        </div>

        {nat_habilitado && (

          <div className="nt-badge" style={{ background: "rgba(239,68,68,0.15)", color: "#f87171", border: "1px solid rgba(239,68,68,0.3)" }}>

            Doble NAT 🛡️

          </div>

        )}

        <div className="nt-badge" style={{ background: "rgba(255,255,255,0.05)", color: "#94a3b8" }}>

          {deviceCount} dispositivos

        </div>

      </div>

    </div>

  );

}



/* ─── CARD: INVISIBLE ───────────────────────────────────────── */

function InvisibleCard() {

  return (

    <div className="nt-card nt-card--invisible" style={{ opacity: 0.6, border: "1px solid #334155", background: "#1e293b" }}>

      <div className="nt-card-icon" style={{ filter: "grayscale(100%)", opacity: 0.7 }}>👻</div>

      <div className="nt-card-label" style={{ color: "#94a3b8", fontStyle: "italic" }}>Hop Invisible</div>

      <div className="nt-badge" style={{ background: "rgba(255,255,255,0.05)", color: "#94a3b8", border: "1px solid #334155" }}>

        ICMP BLOQUEADO

      </div>

    </div>

  );

}



function InvisibleGroupCard({ count }) {

  const [expanded, setExpanded] = useState(false);

  

  if (expanded) {

    return (

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

        {Array.from({ length: count }).map((_, i) => (

          <InvisibleCard key={i} />

        ))}

        <button onClick={(e) => { e.stopPropagation(); setExpanded(false); }} className="nt-badge" style={{ background: "#334155", color: "#fff", cursor: "pointer", border: "none", margin: "0 auto" }}>

          ▲ Colapsar

        </button>

      </div>

    );

  }



  return (

    <div className="nt-card nt-card--invisible-group" onClick={() => setExpanded(true)} style={{ opacity: 0.8, border: "1px dashed #475569", background: "#1e293b", cursor: "pointer" }}>

      <div className="nt-card-icon" style={{ filter: "grayscale(100%)", opacity: 0.9 }}>🔗</div>

      <div className="nt-card-label" style={{ color: "#cbd5e1", fontWeight: "bold" }}>{count} Hops Invisibles</div>

      <div className="nt-badge" style={{ background: "#334155", color: "#cbd5e1", border: "1px solid #475569" }}>

        HACER CLIC PARA EXPANDIR

      </div>

    </div>

  );

}



/* ─── CARD: DISPOSITIVO EN ÁRBOL ────────────────────────────── */

function DeviceCard({ device, onVulnClick, routerIp, localIp, onFocus }) {

  const [open, setOpen] = useState(false);

  const [isFocused, setIsFocused] = useState(false);

  const cardRef = useRef(null);

  const color = getScoreColor(device.max_score);

  const hasPorts = device.puertos_abiertos?.length > 0;

  const hasVulns = device.total_vulnerabilidades > 0;



  const isSleeping = device.en_reposo || device.estado === "En Reposo";

  const isScanner = isScannerHost(device, localIp);



  const handleClick = (e) => {

    if (e.target.closest('.nt-badge[data-action]')) return;



    if (hasPorts) {

      const willOpen = !open;

      setOpen(willOpen);

      if (willOpen && onFocus && cardRef.current) {

        onFocus(cardRef.current, true);

        setIsFocused(true);

        setTimeout(() => setIsFocused(false), 2000);

      }

    } else {

      if (onFocus && cardRef.current) {

        onFocus(cardRef.current, false);

        setIsFocused(true);

        setTimeout(() => setIsFocused(false), 2000);

      }

    }

  };



  return (

    <div className="nt-device-wrapper" style={isSleeping ? { opacity: 0.85 } : {}}>

      <div

        ref={cardRef}

        className={`nt-card nt-card--device ${isScanner ? 'nt-card--scanner' : ''} ${isFocused ? 'nt-card--focused' : ''}`}

        style={{ 

          "--risk-color": isScanner ? "#ffd700" : color, 

          cursor: "pointer", 

          border: isFocused 

            ? `2px solid ${isScanner ? "#ffd700" : "#38bdf8"}`

            : isScanner 

              ? "1.5px solid rgba(255, 215, 0, 0.75)" 

              : isSleeping 

                ? "1px dashed #475569" 

                : undefined,

          position: "relative",

          transition: "border-color 0.15s"

        }}

        onClick={handleClick}

      >

        <div className="nt-card-icon" style={{ position: "relative", display: "inline-block" }}>

          {getDeviceIcon(device, routerIp)}

          {isScanner && (

            <span 

              title="Equipo Principal (Escáner)" 

              style={{

                position: "absolute",

                top: -12,

                left: "50%",

                transform: "translateX(-50%)",

                fontSize: "16px",

                lineHeight: 1,

                pointerEvents: "none"

              }}

            >

              👑

            </span>

          )}

        </div>

        <div className="nt-card-ip" style={isScanner ? { color: "#ffd700", fontWeight: "bold" } : {}}>

          {device.ip}

        </div>

        {device.hostname && device.hostname !== "Caché Local ARP" && (

          <div className="nt-card-hostname">{device.hostname}</div>

        )}

        {device.fabricante && device.fabricante !== "Desconocido" && (

          <div className="nt-card-fab">{device.fabricante}</div>

        )}

        <div style={{ display: "flex", gap: 5, justifyContent: "center", flexWrap: "wrap" }}>

          {isScanner && (

            <div className="nt-badge" style={{ background: "rgba(255, 215, 0, 0.15)", color: "#ffd700", border: "1px solid rgba(255, 215, 0, 0.4)", fontWeight: 800 }}>

              👑 ESTE EQUIPO

            </div>

          )}

          {(() => {
            const med = getDeviceConnectionMedium(device, routerIp);
            if (!med) return null;
            const isWifi = med.medio === "wifi";
            return (
              <div 
                className="nt-badge" 
                title={med.detalle || `Conexión ${med.label}`}
                style={{
                  background: isWifi ? "rgba(14, 165, 233, 0.15)" : "rgba(168, 85, 247, 0.15)",
                  color: isWifi ? "#38bdf8" : "#c084fc",
                  border: isWifi ? "1px solid rgba(14, 165, 233, 0.35)" : "1px solid rgba(168, 85, 247, 0.35)",
                  fontWeight: 700,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px"
                }}
              >
                <span>{med.icono}</span>
                <span>{med.label}</span>
              </div>
            );
          })()}

          {device.telemetria && (

            <div 

              title={`Telemetría de Red: ${device.telemetria.packets_recv || 0}/${device.telemetria.packets_sent || 4} paquetes recibidos (${device.telemetria.packet_loss || 0}% pérdida). Latencia: ${device.telemetria.latency_ms ?? 0} ms`}

              className="nt-badge" 

              style={{ 

                background: (device.telemetria.packet_loss || 0) >= 100 

                  ? "rgba(239, 68, 68, 0.18)" 

                  : (device.telemetria.packet_loss || 0) > 0 

                    ? "rgba(245, 158, 11, 0.18)" 

                    : "rgba(255, 255, 255, 0.05)", 

                color: (device.telemetria.packet_loss || 0) >= 100 

                  ? "#f87171" 

                  : (device.telemetria.packet_loss || 0) > 0 

                    ? "#fbbf24" 

                    : "#64ffda", 

                border: (device.telemetria.packet_loss || 0) >= 100 

                  ? "1px solid rgba(239, 68, 68, 0.4)" 

                  : (device.telemetria.packet_loss || 0) > 0 

                    ? "1px solid rgba(245, 158, 11, 0.4)" 

                    : "1px solid rgba(255, 255, 255, 0.1)",

                fontWeight: 700 

              }}

            >

              {(device.telemetria.packet_loss || 0) >= 100 

                ? `🔴 0/${device.telemetria.packets_sent || 4}` 

                : (device.telemetria.packet_loss || 0) > 0 

                  ? `⚠️ Pérdida ${device.telemetria.packet_loss}% (${device.telemetria.packets_recv}/${device.telemetria.packets_sent})` 

                  : `● ${device.telemetria.latency_ms !== null && device.telemetria.latency_ms !== undefined ? `${device.telemetria.latency_ms} ms` : "<1 ms"}`}

            </div>

          )}

          {isSleeping ? (

            <div className="nt-badge" style={{ background: "rgba(148,163,184,0.15)", color: "#cbd5e1", border: "1px solid rgba(148,163,184,0.3)" }}>

              💤 EN REPOSO

            </div>

          ) : device.max_score > 0 ? (

            <div className="nt-badge" style={{ background: `${color}22`, color, border: `1px solid ${color}55`, fontWeight: 800 }}>

              {device.max_score.toFixed(1)} {getRiskLabel(device.max_score)}

            </div>

          ) : (

            <div className="nt-badge" style={{ background: "rgba(16,185,129,0.12)", color: "#34d399", border: "1px solid rgba(16,185,129,0.3)" }}>

              ✓ SEGURO

            </div>

          )}

          {hasVulns && (

            <div 

              className="nt-badge" 

              style={{ background: "rgba(239,68,68,0.12)", color: "#f87171", border: "1px solid rgba(239,68,68,0.3)", cursor: "pointer" }}

              onClick={(e) => {

                e.stopPropagation();

                if (onVulnClick) onVulnClick(device.ip);

              }}

              title="Ver detalles en Vista Lista"

            >

              {device.total_vulnerabilidades} CVE ↗

            </div>

          )}

          {device.es_nuevo && (

            <div className="nt-badge" style={{ background: "rgba(239,68,68,0.15)", color: "#f87171", border: "1px solid rgba(239,68,68,0.3)" }}>

              NUEVO

            </div>

          )}

          {hasPorts && (

            <div className="nt-badge" style={{ background: "#334155", color: "#94a3b8" }}>

              {device.puertos_abiertos.length} puertos {open ? "▾" : "▸"}

            </div>

          )}

        </div>

      </div>



      {open && hasPorts && (

        <div className="nt-ports-popup">

          {device.puertos_abiertos.map((p, i) => {

            const pHasVulns = p.vulnerabilidades?.length > 0;

            const pColor = pHasVulns ? getScoreColor(Math.max(...p.vulnerabilidades.map(v => v.score || 0))) : "#4a5568";

            return (

              <div 

                key={i} 

                className="nt-port-row" 

                style={{ "--pc": pColor, cursor: pHasVulns ? "pointer" : "default" }}

                onClick={(e) => {

                  e.stopPropagation();

                  if (pHasVulns && onVulnClick) onVulnClick(device.ip);

                }}

                title={pHasVulns ? "Ver detalles en Vista Lista" : ""}

              >

                <span className="nt-port-dot" style={{ background: pColor }} />

                <span className="nt-port-num">:{p.puerto}</span>

                <span className="nt-port-svc">{p.servicio}</span>

                {p.version && <span className="nt-port-ver">{p.version}</span>}

                {pHasVulns && (

                  <span style={{ marginLeft: "auto", color: pColor, fontSize: 11, fontWeight: 700 }}>

                    ⚠ {p.vulnerabilidades.length} CVE ↗

                  </span>

                )}

              </div>

            );

          })}

        </div>

      )}

    </div>

  );

}



/* ─── CARD: NODO EN PLANO FÍSICO (REDIMENSIONABLE Y ADAPTATIVO) ─── */

function FloorPlanNodeCard({ node, isEditing, onStartDrag, onStartResize, onUnplace, routerIp, localIp, onFocus }) {

  const [isFocused, setIsFocused] = useState(false);

  const cardRef = useRef(null);



  const isGw = node.es_gateway || (routerIp && node.ip === routerIp);

  const isScanner = isScannerHost(node, localIp);

  const color = isGw ? "#38bdf8" : getScoreColor(node.max_score);



  // Tamaño personalizado o predeterminado

  const currentW = node.pos?.w || 115;

  const isSmall = currentW < 75;

  const currentH = isSmall ? currentW : (node.pos?.h || 44);



  const displayName = isGw
    ? (node.ssid ? node.ssid.replace(/^Red\s+/i, '') : (node.hostname && !node.hostname.includes("Router Principal (C)") ? node.hostname : (node.fabricante && node.fabricante !== "Desconocido" && !node.fabricante.includes("Gateway") ? `Router (${node.fabricante})` : "Router Principal")))

    : (node.hostname && node.hostname !== "Caché Local ARP" 

        ? node.hostname 

        : (node.fabricante && node.fabricante !== "Desconocido" ? node.fabricante : "Dispositivo"));



  const tooltipText = isGw

    ? `Router Principal${node.fabricante && node.fabricante !== "Desconocido" && !node.fabricante.includes("Gateway") ? ` (${node.fabricante})` : ""} — ${node.ip}`

    : `${displayName} — ${node.ip}`;



  const handleClick = (e) => {

    if (isEditing) return;

    if (onFocus && cardRef.current) {

      onFocus(cardRef.current, false);

      setIsFocused(true);

      setTimeout(() => setIsFocused(false), 2000);

    }

  };



  const handleMouseDown = (e) => {

    if (e.target.closest('.nt-floorplan-resize-handle') || e.target.closest('.nt-floorplan-remove-btn')) {

      return;

    }

    if (isEditing) {

      onStartDrag(node, e);

    }

  };



  // 1. MODO PEQUEÑO (Icono solo - cuando el usuario reduce el tamaño con la esquina)

  if (isSmall) {

    const iconSize = Math.max(16, Math.min(28, Math.round(currentW * 0.55)));

    return (

      <div

        ref={cardRef}

        className={`nt-floorplan-card nt-floorplan-card--small ${isScanner ? 'nt-card--scanner' : ''} ${isGw ? 'nt-card--gateway' : ''} ${isEditing ? 'nt-card--editing' : ''} ${isFocused ? 'nt-card--focused' : ''}`}

        style={{

          position: "absolute",

          left: `${node.pos.x}px`,

          top: `${node.pos.y}px`,

          width: `${currentW}px`,

          height: `${currentH}px`,

          minWidth: 0,

          maxWidth: "none",

          boxSizing: "border-box",

          display: "flex",

          alignItems: "center",

          justifyContent: "center",

          padding: 0,

          borderRadius: "6px",

          background: "#1e293b",

          border: isFocused 

            ? "1.5px solid #38bdf8"

            : isScanner 

              ? "1.5px solid #ffd700" 

              : `1px solid ${isGw ? "#38bdf8" : color}88`,

          zIndex: isEditing ? 20 : 5,

          cursor: isEditing ? "grab" : "pointer",

          userSelect: "none"

        }}

        title={tooltipText}

        onMouseDown={handleMouseDown}

        onClick={handleClick}

      >

        {isEditing && (

          <button

            type="button"

            className="nt-floorplan-remove-btn"

            title="Devolver a la bandeja sin ubicar"

            onClick={(e) => onUnplace(node.ip, e)}

            style={{ top: -5, right: -5, width: 14, height: 14, fontSize: 8 }}

          >

            ✕

          </button>

        )}



        <div style={{ position: "relative", fontSize: iconSize, lineHeight: 1 }}>

          {isGw ? "📡" : getDeviceIcon(node, routerIp)}

          {isScanner && (

            <span 

              title="Equipo Principal (Escáner)" 

              style={{

                position: "absolute",

                top: -Math.round(iconSize * 0.45),

                left: "50%",

                transform: "translateX(-50%)",

                fontSize: Math.max(9, Math.round(iconSize * 0.55)),

                lineHeight: 1,

                pointerEvents: "none"

              }}

            >

              👑

            </span>

          )}

        </div>



        {isEditing && (

          <div

            className="nt-floorplan-resize-handle"

            onMouseDown={(e) => {

              e.stopPropagation();

              e.preventDefault();

              onStartResize(node, e);

            }}

            title="Arrastra esta esquina para agrandar o achicar"

          />

        )}

      </div>

    );

  }



  // 2. MODO NORMAL (Icono + Nombre + IP)

  const iconSize = Math.max(18, Math.min(26, Math.round(currentH * 0.45)));

  const nameFontSize = Math.max(9, Math.min(12, Math.round(currentW * 0.085)));

  const ipFontSize = Math.max(9, Math.min(11, Math.round(currentW * 0.08)));



  return (

    <div

      ref={cardRef}

      className={`nt-floorplan-card ${isScanner ? 'nt-card--scanner' : ''} ${isGw ? 'nt-card--gateway' : ''} ${isEditing ? 'nt-card--editing' : ''} ${isFocused ? 'nt-card--focused' : ''}`}

      style={{

        position: "absolute",

        left: `${node.pos.x}px`,

        top: `${node.pos.y}px`,

        width: `${currentW}px`,

        height: `${currentH}px`,

        boxSizing: "border-box",

        padding: "5px 8px",

        borderRadius: "8px",

        background: "#1e293b",

        border: isFocused 

          ? "2px solid #38bdf8"

          : isScanner 

            ? "1.5px solid #ffd700" 

            : `1px solid ${isGw ? "#38bdf8" : color}66`,

        borderTop: isScanner 

          ? "2px solid #ffd700" 

          : `2px solid ${isGw ? "#38bdf8" : color}`,

        zIndex: isEditing ? 20 : 5,

        cursor: isEditing ? "grab" : "pointer",

        display: "flex",

        alignItems: "center",

        gap: 6,

        overflow: "hidden",

        userSelect: "none"

      }}

      title={tooltipText}

      onMouseDown={handleMouseDown}

      onClick={handleClick}

    >

      {isEditing && (

        <button

          type="button"

          className="nt-floorplan-remove-btn"

          title="Devolver a la bandeja sin ubicar"

          onClick={(e) => onUnplace(node.ip, e)}

          style={{ top: 2, right: 2, width: 16, height: 16 }}

        >

          ✕

        </button>

      )}



      {isEditing && (

        <div className="nt-floorplan-drag-indicator" style={{ top: 2, left: 3, fontSize: 9, color: "#38bdf8", opacity: 0.6, pointerEvents: "none" }}>

          ✥

        </div>

      )}



      <div style={{ position: "relative", fontSize: iconSize, lineHeight: 1, flexShrink: 0 }}>

        {isGw ? "📡" : getDeviceIcon(node, routerIp)}

        {isScanner && (

          <span 

            title="Equipo Principal (Escáner)" 

            style={{

              position: "absolute",

              top: -Math.round(iconSize * 0.45),

              left: "50%",

              transform: "translateX(-50%)",

              fontSize: Math.max(9, Math.round(iconSize * 0.55)),

              lineHeight: 1,

              pointerEvents: "none"

            }}

          >

            👑

          </span>

        )}

      </div>



      <div style={{ flex: 1, minWidth: 0, textAlign: "left" }}>

        <div 

          style={{ 

            fontSize: nameFontSize, 

            fontWeight: 600, 

            color: isScanner ? "#ffd700" : (isGw ? "#38bdf8" : "#f1f5f9"), 

            overflow: "hidden", 

            textOverflow: "ellipsis", 

            whiteSpace: "nowrap" 

          }}

        >

          {displayName}

        </div>

        <div 

          style={{ 

            fontSize: ipFontSize, 

            fontFamily: "'Fira Code', monospace", 

            color: "#38bdf8", 

            fontWeight: 500,

            lineHeight: 1.2

          }}

        >

          {node.ip}

        </div>

        {node.telemetria && (
          <div 
            style={{ 
              fontSize: Math.max(8, ipFontSize - 1), 
              color: (node.telemetria.packet_loss || 0) >= 100 
                ? "#f87171" 
                : (node.telemetria.packet_loss || 0) > 0 
                  ? "#fbbf24" 
                  : "#64ffda", 
              fontWeight: 700, 
              display: "flex", 
              alignItems: "center", 
              gap: 3, 
              lineHeight: 1.1,
              marginTop: 1 
            }}
            title={`Telemetría: ${node.telemetria.packets_recv || 0}/${node.telemetria.packets_sent || 4} pkts (${node.telemetria.packet_loss || 0}% pérdida)`}
          >
            <span style={{ width: 4, height: 4, borderRadius: "50%", background: (node.telemetria.packet_loss || 0) >= 100 ? "#f87171" : ((node.telemetria.packet_loss || 0) > 0 ? "#fbbf24" : "#10b981") }} />
            {(node.telemetria.packet_loss || 0) >= 100 
              ? `0/${node.telemetria.packets_sent || 4}` 
              : (node.telemetria.packet_loss || 0) > 0 
                ? `${node.telemetria.packet_loss}% loss` 
                : `${node.telemetria.latency_ms !== null && node.telemetria.latency_ms !== undefined ? `${node.telemetria.latency_ms}ms` : "<1ms"}`}
          </div>
        )}

      </div>



      {isEditing && (

        <div

          className="nt-floorplan-resize-handle"

          onMouseDown={(e) => {

            e.stopPropagation();

            e.preventDefault();

            onStartResize(node, e);

          }}

          title="Arrastra esta esquina para agrandar o achicar"

        />

      )}

    </div>

  );

}



/* ─── RAMA DEL ÁRBOL (nodo + hijos) ─────────────────────────── */

function OrgBranch({ card, children }) {

  return (

    <li className="nt-branch">

      {card}

      {children && (

        <ul className="nt-children">

          {children}

        </ul>

      )}

    </li>

  );

}



/* ─── COMPONENTE PRINCIPAL ──────────────────────────────────── */

export default function NetworkTree({ devices, topology, onVulnClick, localIp, isProcessing, scanMsg }) {

  const tree = useMemo(() => buildTree(devices, topology), [devices, topology]);

  const viewportRef = useRef(null);

  const internetCardRef = useRef(null);

  const fileInputRef = useRef(null);

  

  const [zoom, setZoom] = useState(1);

  const [showWarnings, setShowWarnings] = useState(false);

  const [showIspDrawer, setShowIspDrawer] = useState(false);

  const [isAnimatingZoom, setIsAnimatingZoom] = useState(false);

  const animTimeoutRef = useRef(null);

  const dragging = useRef(false);

  const lastPos = useRef({ x: 0, y: 0 });



  /* Estado del Modo Dual: Árbol vs Plano Físico */

  const [viewMode, setViewMode] = useState("tree");

  const [isEditing, setIsEditing] = useState(false);

  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);

  const [showLinks, setShowLinks] = useState(true);

  const [confirmModal, setConfirmModal] = useState(null);



  const { isp, cgnatGroup, main, extensors } = tree || {};



  /* Clave de almacenamiento por subred local */

  const subnetKey = useMemo(() => {

    return main?.prefix || (topology?.router_principal_ip ? getSubnetPrefix(topology.router_principal_ip) : "default");

  }, [main, topology]);

  const storageKey = `secscan_floorplan_${subnetKey}`;



  /* Datos del plano físico y sistema multi-plantas (pisos) */
  const defaultFloors = useMemo(() => [
    {
      id: "floor_1",
      name: "Planta Baja / Piso 1",
      image: null,
      canvasSize: { width: 1500, height: 950 },
      positions: {}
    }
  ], []);

  const [floors, setFloors] = useState(defaultFloors);
  const [activeFloorId, setActiveFloorId] = useState("floor_1");
  const [editingFloorId, setEditingFloorId] = useState(null);
  const [floorNameInput, setFloorNameInput] = useState("");
  const [isDrawerOpen, setIsDrawerOpen] = useState(true);
  const [drawerSearch, setDrawerSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedIps, setSelectedIps] = useState(new Set());



  /* Planta activa en el visor */
  const activeFloor = useMemo(() => {
    return floors.find(f => f.id === activeFloorId) || floors[0] || defaultFloors[0];
  }, [floors, activeFloorId, defaultFloors]);

  const floorplanImage = activeFloor.image || null;
  const positions = activeFloor.positions || {};
  const canvasSize = activeFloor.canvasSize || { width: 1500, height: 950 };

  /* Actualizador reactivo de la planta activa */
  const updateActiveFloor = useCallback((updater) => {
    setFloors(prevFloors => {
      return prevFloors.map(f => {
        if (f.id === activeFloorId) {
          return typeof updater === "function" ? updater(f) : { ...f, ...updater };
        }
        return f;
      });
    });
    setHasUnsavedChanges(true);
  }, [activeFloorId]);

  const setPositions = useCallback((updater) => {
    updateActiveFloor(currentFloor => {
      const nextPositions = typeof updater === "function" ? updater(currentFloor.positions || {}) : updater;
      return {
        ...currentFloor,
        positions: nextPositions
      };
    });
  }, [updateActiveFloor]);

  const setFloorplanImage = useCallback((newImage) => {
    updateActiveFloor(currentFloor => ({
      ...currentFloor,
      image: newImage
    }));
  }, [updateActiveFloor]);

  const setCanvasSize = useCallback((newSize) => {
    updateActiveFloor(currentFloor => ({
      ...currentFloor,
      canvasSize: typeof newSize === "function" ? newSize(currentFloor.canvasSize || { width: 1500, height: 950 }) : newSize
    }));
  }, [updateActiveFloor]);

  /* Cargar datos del plano y plantas guardadas en localStorage */
  useEffect(() => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed.floors && Array.isArray(parsed.floors) && parsed.floors.length > 0) {
          const loadedFloors = parsed.floors.map(f => ({
            ...f,
            canvasSize: f.canvasSize ? {
              width: Math.max(1400, f.canvasSize.width),
              height: Math.max(850, f.canvasSize.height)
            } : { width: 1500, height: 950 }
          }));
          setFloors(loadedFloors);
          if (parsed.activeFloorId && loadedFloors.some(f => f.id === parsed.activeFloorId)) {
            setActiveFloorId(parsed.activeFloorId);
          } else {
            setActiveFloorId(loadedFloors[0].id);
          }
        } else {
          // Migración transparente de plano único legado
          let initialW = Math.max(1400, parsed.canvasSize?.width || 1500);
          let initialH = Math.max(850, parsed.canvasSize?.height || 950);
          setFloors([
            {
              id: "floor_1",
              name: "Planta Baja / Piso 1",
              image: parsed.image || null,
              canvasSize: { width: initialW, height: initialH },
              positions: parsed.positions || {}
            }
          ]);
          setActiveFloorId("floor_1");
        }

        if (typeof parsed.showLinks === "boolean") setShowLinks(parsed.showLinks);
      }
    } catch (err) {
      console.error("Error cargando plano de localStorage:", err);
    }
  }, [storageKey]);

  /* Ajustar zoom automáticamente al entrar o cambiar de planta */
  useEffect(() => {
    if (viewMode === "floorplan" && viewportRef.current) {
      const vp = viewportRef.current;
      const vpW = vp.clientWidth - 40;
      const vpH = vp.clientHeight - 40;
      if (vpW > 0 && vpH > 0) {
        const scaleX = vpW / canvasSize.width;
        const scaleY = vpH / canvasSize.height;
        const fitZoom = Math.min(scaleX, scaleY);
        setZoom(Math.max(0.25, Math.min(1.0, Number(fitZoom.toFixed(2)))));
      }
    }
  }, [viewMode, activeFloorId, canvasSize.width, canvasSize.height]);

  /* Acciones de gestión de plantas / pisos */
  const handleAddFloor = useCallback(() => {
    const newIndex = floors.length + 1;
    const newFloor = {
      id: `floor_${Date.now()}`,
      name: `Piso ${newIndex}`,
      image: null,
      canvasSize: { width: 1500, height: 950 },
      positions: {}
    };
    setFloors(prev => [...prev, newFloor]);
    setActiveFloorId(newFloor.id);
    setHasUnsavedChanges(true);
  }, [floors.length]);

  const startRenameFloor = (floor) => {
    setEditingFloorId(floor.id);
    setFloorNameInput(floor.name);
  };

  const saveRenameFloor = () => {
    if (floorNameInput.trim() && editingFloorId) {
      setFloors(prev => prev.map(f => f.id === editingFloorId ? { ...f, name: floorNameInput.trim() } : f));
      setHasUnsavedChanges(true);
    }
    setEditingFloorId(null);
  };

  const handleRemoveFloor = useCallback((floorToRemove) => {
    if (floors.length <= 1) return;
    const count = Object.keys(floorToRemove.positions || {}).length;
    setConfirmModal({
      title: `¿Eliminar "${floorToRemove.name}"?`,
      message: count > 0 
        ? `Se eliminará esta planta y los ${count} dispositivo(s) ubicados en ella volverán a la lista de pendientes.` 
        : `Se eliminará esta planta del edificio.`,
      confirmText: "Sí, eliminar planta",
      confirmType: "danger",
      onConfirm: () => {
        setFloors(prev => {
          const filtered = prev.filter(f => f.id !== floorToRemove.id);
          if (activeFloorId === floorToRemove.id) {
            setActiveFloorId(filtered[0]?.id || "floor_1");
          }
          return filtered;
        });
        setHasUnsavedChanges(true);
        setConfirmModal(null);
      }
    });
  }, [floors.length, activeFloorId]);

  /* IP resuelta del Router/Gateway principal */

  const resolvedRouterIp = useMemo(() => {

    return topology?.router_principal_ip || main?.gateway?.ip || (main?.prefix ? `${main.prefix}.1` : null);

  }, [topology, main]);



  /* Todos los nodos disponibles para el plano físico */

  const allFloorplanNodes = useMemo(() => {

    const list = [...(devices || [])];

    const gwIp = resolvedRouterIp;

    if (gwIp) {

      const existingIdx = list.findIndex(d => d.ip === gwIp);

      if (existingIdx >= 0) {

        list[existingIdx] = {

          ...list[existingIdx],

          es_gateway: true,

          icono: "📡",

          hostname: "Router Principal"

        };

      } else {

        list.unshift({

          ip: gwIp,

          hostname: "Router Principal",

          fabricante: main?.gateway?.fabricante || "Gateway",

          es_gateway: true,

          icono: "📡",

          max_score: 0,

          puertos_abiertos: []

        });

      }

    }

    return list;

  }, [devices, resolvedRouterIp, main]);



  /* Dispositivos ubicados en la planta activa vs pendientes de ubicar */
  const { placedNodes, unplacedNodes, otherFloorNodes } = useMemo(() => {
    const placed = [];
    const unplaced = [];
    const otherFloor = [];

    // Mapeo de dispositivos ubicados en otras plantas
    const otherFloorMap = {};
    floors.forEach(f => {
      if (f.id !== activeFloorId && f.positions) {
        Object.keys(f.positions).forEach(ip => {
          otherFloorMap[ip] = f.name;
        });
      }
    });

    allFloorplanNodes.forEach(node => {
      if (positions[node.ip] && typeof positions[node.ip].x === "number") {
        placed.push({ ...node, pos: positions[node.ip] });
      } else if (otherFloorMap[node.ip]) {
        otherFloor.push({ ...node, locatedFloorName: otherFloorMap[node.ip] });
      } else {
        unplaced.push(node);
      }
    });

    return { placedNodes: placed, unplacedNodes: unplaced, otherFloorNodes: otherFloor };
  }, [allFloorplanNodes, positions, floors, activeFloorId]);

  const getDeviceCat = useCallback((node) => {
    if (node.es_gateway || node.ip === resolvedRouterIp) return "network";
    const icon = getDeviceIcon(node, resolvedRouterIp);
    if (icon === "💻") return "pc";
    if (icon === "📱" || icon === "🍎" || icon === "📞") return "mobile";
    if (icon === "📷") return "camera";
    if (icon === "🖨️") return "printer";
    if (icon === "📡") return "network";
    if (icon === "🖥️" || icon === "🗄️") return "server";
    if (icon === "📺" || icon === "🎮") return "iot";
    return "other";
  }, [resolvedRouterIp]);

  const categoriesList = useMemo(() => {
    let pcCount = 0, mobileCount = 0, camCount = 0, printerCount = 0, netCount = 0, serverCount = 0, vulnCount = 0;
    unplacedNodes.forEach(n => {
      const cat = getDeviceCat(n);
      if (cat === "pc") pcCount++;
      else if (cat === "server") serverCount++;
      else if (cat === "mobile") mobileCount++;
      else if (cat === "camera") camCount++;
      else if (cat === "printer") printerCount++;
      else if (cat === "network") netCount++;
      if ((n.vulnerabilidades && n.vulnerabilidades.length > 0) || (n.max_score && n.max_score > 0)) {
        vulnCount++;
      }
    });

    const list = [
      { id: "all", label: "Todos", icon: "📋", count: unplacedNodes.length }
    ];
    if (pcCount > 0) list.push({ id: "pc", label: "PCs", icon: "💻", count: pcCount });
    if (serverCount > 0) list.push({ id: "server", label: "Servidores", icon: "🗄️", count: serverCount });
    if (mobileCount > 0) list.push({ id: "mobile", label: "Móviles", icon: "📱", count: mobileCount });
    if (camCount > 0) list.push({ id: "camera", label: "Cámaras", icon: "📷", count: camCount });
    if (printerCount > 0) list.push({ id: "printer", label: "Impresoras", icon: "🖨️", count: printerCount });
    if (netCount > 0) list.push({ id: "network", label: "Red", icon: "📡", count: netCount });
    if (vulnCount > 0) list.push({ id: "vuln", label: "Con CVEs", icon: "🚨", count: vulnCount });
    return list;
  }, [unplacedNodes, getDeviceCat]);

  const filteredList = useMemo(() => {
    return unplacedNodes.filter(n => {
      if (selectedCategory !== "all") {
        if (selectedCategory === "vuln") {
          const hasV = (n.vulnerabilidades && n.vulnerabilidades.length > 0) || (n.max_score && n.max_score > 0);
          if (!hasV) return false;
        } else {
          if (getDeviceCat(n) !== selectedCategory) return false;
        }
      }
      if (drawerSearch.trim()) {
        const q = drawerSearch.toLowerCase();
        const matchesIp = n.ip && n.ip.toLowerCase().includes(q);
        const matchesHost = n.hostname && n.hostname.toLowerCase().includes(q);
        const matchesFab = (n.fabricante || n.vendor || "").toLowerCase().includes(q);
        if (!matchesIp && !matchesHost && !matchesFab) return false;
      }
      return true;
    });
  }, [unplacedNodes, selectedCategory, drawerSearch, getDeviceCat]);

  const toggleSelectIp = useCallback((ip) => {
    setSelectedIps(prev => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }, []);

  const placeSelectedNodes = useCallback((ipsToPlace) => {
    const ips = Array.from(ipsToPlace);
    if (ips.length === 0) return;
    setPositions(prev => {
      const next = { ...prev };
      const cols = Math.min(5, Math.ceil(Math.sqrt(ips.length * 1.5)));
      const startX = Math.round(canvasSize.width / 2 - (cols * 130) / 2);
      const startY = Math.round(canvasSize.height / 2 - (Math.ceil(ips.length / cols) * 60) / 2);

      ips.forEach((ip, index) => {
        const col = index % cols;
        const row = Math.floor(index / cols);
        const x = Math.max(20, Math.min(canvasSize.width - 130, startX + col * 135));
        const y = Math.max(20, Math.min(canvasSize.height - 60, startY + row * 60));
        next[ip] = { x, y, w: 115, h: 44 };
      });

      return next;
    });
    setSelectedIps(new Set());
    setHasUnsavedChanges(true);
  }, [canvasSize, setPositions]);


  /* Coordenadas del Router/Gateway en el plano calculadas al centro exacto de su recuadro */

  const gatewayPos = useMemo(() => {

    const gwNode = placedNodes.find(n => n.es_gateway || n.ip === resolvedRouterIp);

    if (gwNode) {

      const w = gwNode.pos?.w || 115;

      const isSmall = w < 75;

      const h = isSmall ? w : (gwNode.pos?.h || 44);

      return {

        x: gwNode.pos.x + Math.round(w / 2),

        y: gwNode.pos.y + Math.round(h / 2)

      };

    }

    return null;

  }, [placedNodes, topology, main]);



  /* Enfocar y hacer zoom suave en un dispositivo o elemento del árbol / plano */

  const focusOnElement = useCallback((element, hasPorts = false) => {

    if (!element || !viewportRef.current) return;

    const vp = viewportRef.current;

    const canvas = vp.querySelector('.nt-canvas');

    if (!canvas) return;



    const cardRect = element.getBoundingClientRect();

    const canvasRect = canvas.getBoundingClientRect();

    const vpRect = vp.getBoundingClientRect();



    const currentZ = zoom;

    const targetZ = currentZ < 1.3 ? 1.3 : currentZ;

    const ratio = targetZ / currentZ;



    const cardCenterX = cardRect.left + cardRect.width / 2;

    const cardCenterY = cardRect.top + (hasPorts ? cardRect.height * 0.35 : cardRect.height / 2);



    const originScreenX = canvasRect.left + canvasRect.width / 2;

    const originScreenY = canvasRect.top;



    const targetCardCenterX = originScreenX + (cardCenterX - originScreenX) * ratio;

    const targetCardCenterY = originScreenY + (cardCenterY - originScreenY) * ratio;



    const vpCenterX = vpRect.left + vpRect.width / 2;

    const vpCenterY = vpRect.top + vpRect.height / 2;



    const deltaX = targetCardCenterX - vpCenterX;

    const deltaY = targetCardCenterY - vpCenterY;



    const targetScrollLeft = Math.max(0, vp.scrollLeft + deltaX);

    const targetScrollTop = Math.max(0, vp.scrollTop + deltaY);



    setIsAnimatingZoom(true);

    setZoom(targetZ);



    vp.scrollTo({

      left: targetScrollLeft,

      top: targetScrollTop,

      behavior: "smooth"

    });



    if (animTimeoutRef.current) clearTimeout(animTimeoutRef.current);

    animTimeoutRef.current = setTimeout(() => {

      setIsAnimatingZoom(false);

    }, 450);

  }, [zoom]);



  const handleResetZoom = useCallback(() => {

    setIsAnimatingZoom(true);

    if (viewMode === "floorplan" && viewportRef.current) {

      const vp = viewportRef.current;

      const vpW = vp.clientWidth - 40;

      const vpH = vp.clientHeight - 40;

      const scaleX = vpW / canvasSize.width;

      const scaleY = vpH / canvasSize.height;

      const fitZoom = Math.max(0.6, Math.min(scaleX, scaleY, 1.0));

      setZoom(Number(fitZoom.toFixed(2)));

      vp.scrollTo({ left: 0, top: 0, behavior: 'smooth' });

    } else {

      setZoom(1);

      if (viewportRef.current) {

        const vp = viewportRef.current;

        const canvas = vp.querySelector('.nt-canvas');

        if (canvas) {

          const targetLeft = Math.max(0, (canvas.offsetWidth - vp.clientWidth) / 2);

          vp.scrollTo({ left: targetLeft, top: 0, behavior: 'smooth' });

        }

      }

    }

    if (animTimeoutRef.current) clearTimeout(animTimeoutRef.current);

    animTimeoutRef.current = setTimeout(() => {

      setIsAnimatingZoom(false);

    }, 450);

  }, [viewMode, canvasSize]);



  /* Pan con drag en el fondo del lienzo */

  const onMouseDown = useCallback((e) => {

    if (e.target.closest(".nt-card") || e.target.closest(".nt-ports-popup") || e.target.closest(".nt-floorplan-card")) return;

    dragging.current = true;

    lastPos.current = { x: e.clientX, y: e.clientY };

    e.currentTarget.style.cursor = "grabbing";

  }, []);

  const onMouseMove = useCallback((e) => {

    if (!dragging.current) return;

    const vp = viewportRef.current;

    vp.scrollLeft -= e.clientX - lastPos.current.x;

    vp.scrollTop  -= e.clientY - lastPos.current.y;

    lastPos.current = { x: e.clientX, y: e.clientY };

  }, []);

  const onMouseUp = useCallback((e) => {

    dragging.current = false;

    e.currentTarget.style.cursor = "grab";

  }, []);



  /* Zoom con rueda nativo no pasivo */

  useEffect(() => {

    const vp = viewportRef.current;

    if (!vp) return;



    const handleWheel = (e) => {

      e.preventDefault();

      setZoom(z => Math.min(Math.max(z * (e.deltaY > 0 ? 0.92 : 1.08), 0.3), 2.5));

    };



    vp.addEventListener("wheel", handleWheel, { passive: false });

    return () => {

      vp.removeEventListener("wheel", handleWheel);

    };

  }, [tree]);



  /* Subir y optimizar plano arquitectónico en alta resolución */
  const handleImageSelect = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const rawDataUrl = event.target?.result;
      if (!rawDataUrl) return;

      const img = new Image();
      img.onload = () => {
        let origW = img.naturalWidth || 1600;
        let origH = img.naturalHeight || 1000;

        // Mantener alta resolución arquitectónica hasta 2800px para que las habitaciones y textos se lean con total nitidez al hacer zoom
        const maxDim = 2800;
        let w = origW;
        let h = origH;
        if (w > maxDim || h > maxDim) {
          if (w > h) {
            h = Math.round((h * maxDim) / w);
            w = maxDim;
          } else {
            w = Math.round((w * maxDim) / h);
            h = maxDim;
          }
        }

        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext("2d");
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = "high";
        ctx.drawImage(img, 0, 0, w, h);
        const compressedDataUrl = canvas.toDataURL("image/jpeg", 0.88);

        setFloorplanImage(compressedDataUrl);

        // Lienzo en proporción real con amplitud suficiente para posicionamiento fluido
        let canvasW = Math.max(1500, Math.min(origW, 2600));
        let canvasH = Math.round(canvasW * (origH / origW));
        if (canvasH < 800) canvasH = 800;

        setCanvasSize({ width: canvasW, height: canvasH });
        setHasUnsavedChanges(true);

        // Auto-fit suave al viewport
        if (viewportRef.current) {
          const vpW = viewportRef.current.clientWidth - 40;
          const vpH = viewportRef.current.clientHeight - 40;
          const fitZoom = Math.min(vpW / canvasW, vpH / canvasH);
          setZoom(Math.max(0.25, Math.min(1.0, Number(fitZoom.toFixed(2)))));
        }
      };

      img.src = rawDataUrl;
    };

    reader.readAsDataURL(file);
    e.target.value = "";
  };

  const handleRemoveImage = () => {
    setFloorplanImage(null);
    setHasUnsavedChanges(true);
  };

  /* Arrastre para mover dispositivos en modo edición */

  const handleStartNodeDrag = useCallback((node, e) => {

    if (!isEditing) return;

    e.preventDefault();

    e.stopPropagation();



    const startClientX = e.clientX;

    const startClientY = e.clientY;

    const currentPos = positions[node.ip] || { x: 100, y: 100 };

    const startX = currentPos.x;

    const startY = currentPos.y;



    const w = currentPos.w || 115;

    const h = (w < 75) ? w : (currentPos.h || 44);



    const onMove = (moveEvent) => {

      moveEvent.preventDefault();

      const currentZ = zoom || 1;

      const dx = (moveEvent.clientX - startClientX) / currentZ;

      const dy = (moveEvent.clientY - startClientY) / currentZ;



      const newX = Math.round(Math.max(5, Math.min(canvasSize.width - w, startX + dx)));

      const newY = Math.round(Math.max(5, Math.min(canvasSize.height - h, startY + dy)));



      setPositions(prev => ({

        ...prev,

        [node.ip]: {

          ...(prev[node.ip] || {}),

          x: newX,

          y: newY

        }

      }));

      setHasUnsavedChanges(true);

    };



    const onUp = () => {

      window.removeEventListener("mousemove", onMove);

      window.removeEventListener("mouseup", onUp);

    };



    window.addEventListener("mousemove", onMove);

    window.addEventListener("mouseup", onUp);

  }, [isEditing, positions, zoom, canvasSize]);



  /* Redimensionamiento interactivo por esquina (adaptativo: agranda o achica a icono) */

  const handleStartNodeResize = useCallback((node, e) => {

    if (!isEditing) return;

    e.preventDefault();

    e.stopPropagation();



    const startClientX = e.clientX;

    const startClientY = e.clientY;

    const currentPos = positions[node.ip] || { x: 100, y: 100, w: 115, h: 44 };

    const startW = currentPos.w || 115;

    const startH = currentPos.h || 44;



    const onMove = (moveEvent) => {

      moveEvent.preventDefault();

      const currentZ = zoom || 1;

      const dx = (moveEvent.clientX - startClientX) / currentZ;

      const dy = (moveEvent.clientY - startClientY) / currentZ;



      let newW = Math.round(startW + dx);

      let newH = Math.round(startH + dy);



      // Limitar ancho entre 34px y 220px

      newW = Math.max(30, Math.min(220, newW));



      // Si se encoge por debajo de 75px, se adapta a cuadrado perfecto con sólo el icono

      if (newW < 75) {

        newH = newW;

      } else {

        newH = Math.max(38, Math.min(85, newH));

      }



      setPositions(prev => ({

        ...prev,

        [node.ip]: {

          ...(prev[node.ip] || { x: 100, y: 100 }),

          w: newW,

          h: newH

        }

      }));

      setHasUnsavedChanges(true);

    };



    const onUp = () => {

      window.removeEventListener("mousemove", onMove);

      window.removeEventListener("mouseup", onUp);

    };



    window.addEventListener("mousemove", onMove);

    window.addEventListener("mouseup", onUp);

  }, [isEditing, positions, zoom]);



  /* Devolver nodo a la bandeja de pendientes */

  const handleUnplaceNode = useCallback((ip, e) => {

    if (e) e.stopPropagation();

    setPositions(prev => {

      const next = { ...prev };

      delete next[ip];

      return next;

    });

    setHasUnsavedChanges(true);

  }, []);



  /* Ubicar nodo pendiente cerca del centro */

  const placeNodeAtCenter = useCallback((ip) => {

    const jitterX = (Math.random() - 0.5) * 60;

    const jitterY = (Math.random() - 0.5) * 60;

    const centerX = Math.round(canvasSize.width / 2 - 58 + jitterX);

    const centerY = Math.round(canvasSize.height / 2 - 22 + jitterY);

    

    setPositions(prev => ({

      ...prev,

      [ip]: { x: Math.max(10, centerX), y: Math.max(10, centerY), w: 115, h: 44 }

    }));

    setHasUnsavedChanges(true);

  }, [canvasSize]);



  /* Distribuir en cuadrícula los dispositivos pendientes */

  const placeAllUnplaced = useCallback(() => {

    setPositions(prev => {

      const next = { ...prev };

      let row = 0;

      let col = 0;

      unplacedNodes.forEach(node => {

        const x = 30 + col * 135;

        const y = 30 + row * 60;

        next[node.ip] = { x, y, w: 115, h: 44 };

        col++;

        if (col >= 6) {

          col = 0;

          row++;

        }

      });

      return next;

    });

    setHasUnsavedChanges(true);

  }, [unplacedNodes]);



  /* Acciones rápidas de tamaño para todos los nodos */

  const applySizeToAll = useCallback((targetW, targetH) => {

    setPositions(prev => {

      const next = { ...prev };

      Object.keys(next).forEach(ip => {

        next[ip] = {

          ...next[ip],

          w: targetW,

          h: targetH

        };

      });

      return next;

    });

    setHasUnsavedChanges(true);

  }, []);



  /* Guardar distribución física y plantas en localStorage */
  const handleSave = useCallback(() => {
    try {
      const dataToSave = {
        activeFloorId,
        floors,
        showLinks
      };
      localStorage.setItem(storageKey, JSON.stringify(dataToSave));
      setHasUnsavedChanges(false);
      setIsEditing(false);
    } catch (err) {
      console.error("Error guardando plano:", err);
      setConfirmModal({
        title: "No se pudo guardar",
        message: "Las imágenes de los planos ocupan demasiado espacio en el almacenamiento del navegador. Intenta optimizar o subir imágenes más livianas.",
        confirmText: "Entendido",
        confirmType: "primary",
        singleButton: true,
        onConfirm: () => setConfirmModal(null)
      });
    }
  }, [floors, activeFloorId, showLinks, storageKey]);

  /* Cancelar edición y revertir a los datos guardados */
  const handleCancelEdit = useCallback(() => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed.floors && Array.isArray(parsed.floors)) {
          setFloors(parsed.floors);
          if (parsed.activeFloorId) setActiveFloorId(parsed.activeFloorId);
        } else {
          setFloors([
            {
              id: "floor_1",
              name: "Planta Baja / Piso 1",
              image: parsed.image || null,
              canvasSize: parsed.canvasSize || { width: 1500, height: 950 },
              positions: parsed.positions || {}
            }
          ]);
        }
        if (typeof parsed.showLinks === "boolean") setShowLinks(parsed.showLinks);
      } else {
        setFloors(defaultFloors);
        setActiveFloorId("floor_1");
      }
    } catch (err) {
      console.error(err);
    }
    setHasUnsavedChanges(false);
    setIsEditing(false);
    setEditingFloorId(null);
  }, [storageKey, defaultFloors]);

  /* Reiniciar y borrar todas las plantas del plano físico */
  const handleResetAll = useCallback(() => {
    setConfirmModal({
      title: "¿Reiniciar distribución completa?",
      message: "Se borrarán todas las plantas, imágenes de fondo y ubicaciones guardadas en esta red.",
      confirmText: "Sí, reiniciar todo",
      confirmType: "danger",
      onConfirm: () => {
        try {
          localStorage.removeItem(storageKey);
        } catch (err) {
          console.error(err);
        }
        setFloors([
          {
            id: "floor_1",
            name: "Planta Baja / Piso 1",
            image: null,
            canvasSize: { width: 1500, height: 950 },
            positions: {}
          }
        ]);
        setActiveFloorId("floor_1");
        setHasUnsavedChanges(false);
        setIsEditing(false);
        setEditingFloorId(null);
        setConfirmModal(null);
      }
    });
  }, [storageKey]);

  if (!tree || !tree.main) {

    if (isProcessing) {

      return (

        <div className="nt-empty" style={{ padding: "80px 20px", textAlign: "center" }}>

          <div className="scanning-spinner" style={{ margin: "0 auto 24px", width: "52px", height: "52px" }} />

          <h3 style={{ color: "var(--cyan-400)", marginBottom: "10px", fontSize: "18px" }}>

            📡 Sintonizando Burbujas en Vivo...

          </h3>

          <p style={{ color: "var(--text-secondary)", fontSize: "13px", maxWidth: "480px", margin: "0 auto", lineHeight: "1.6" }}>

            {scanMsg || "El motor de auditoría está descubriendo y analizando los nodos en tu red local. Las burbujas se conectarán en pantalla en cuanto se detecten."}

          </p>

        </div>

      );

    }

    return (

      <div className="nt-empty">

        <div style={{ fontSize: 48 }}>🌐</div>

        <p>No hay datos para construir el árbol.</p>

      </div>

    );

  }



  const hasExtensors = extensors && extensors.length > 0;

  const warnings = topology?.advertencias || [];



  const gatewayBranch = (

    <OrgBranch

      card={

        <GatewayCard

          ip={main?.gateway?.ip || (main?.prefix ? `${main.prefix}.1` : "192.168.1.1")}

          hostname={main?.gateway?.hostname || "Router Principal"}

          fabricante={main?.gateway?.fabricante}

          mac={main?.gateway?.mac}

          ssid={main?.gateway?.ssid || topology?.network_name}

          onFocus={focusOnElement}

        />

      }

    >

      {(main?.devices || []).length > 0 && (
        <OrgBranch
          key="main-devices-group"
          card={
            <div className="nt-device-group">
              {(main?.devices || []).map(d => (
                <DeviceCard
                  key={d.ip}
                  device={d}
                  onVulnClick={onVulnClick}
                  routerIp={resolvedRouterIp}
                  localIp={localIp}
                  onFocus={focusOnElement}
                />
              ))}
            </div>
          }
        />
      )}



      {hasExtensors && extensors.map((ext, i) => (

        <OrgBranch

          key={ext.prefix || `ext-${i}`}

          card={

            ext.isGroup ? (

              <InvisibleGroupCard count={ext.count} />

            ) : ext.gateway?.tipo === "invisible" ? (

              <InvisibleCard />

            ) : (

              <ExtensorCard

                ip={ext.gateway?.ip || (ext.prefix ? `${ext.prefix}.1` : "Extensor")}

                hostname={ext.gateway?.hostname}

                fabricante={ext.gateway?.fabricante || ext.gateway?.mac}

                deviceCount={ext.devices?.length || 0}

                nat_habilitado={ext.gateway?.nat_habilitado}

                onFocus={focusOnElement}

              />

            )

          }

        >

          {(ext.devices || []).length > 0 && (
            <OrgBranch
              key={`ext-devices-group-${i}`}
              card={
                <div className="nt-device-group">
                  {(ext.devices || []).map(d => (
                    <DeviceCard
                      key={d.ip}
                      device={d}
                      onVulnClick={onVulnClick}
                      routerIp={resolvedRouterIp}
                      localIp={localIp}
                      onFocus={focusOnElement}
                    />
                  ))}
                </div>
              }
            />
          )}

        </OrgBranch>

      ))}

    </OrgBranch>

  );



  return (

    <div className="nt-root">

      

      {/* Barra de herramientas superior */}

      <div className="nt-toolbar">

        <div className="nt-toolbar-group">

          <button

            type="button"

            className={`nt-mode-tab ${viewMode === "tree" ? "nt-mode-tab--active" : ""}`}

            onClick={() => {

              if (isEditing && hasUnsavedChanges) {

                setConfirmModal({

                  title: "¿Salir sin guardar?",

                  message: "Tienes cambios sin guardar en el plano físico. Si sales a la vista jerárquica, se descartarán los cambios no guardados.",

                  confirmText: "Descartar y salir",

                  confirmType: "danger",

                  onConfirm: () => {

                    handleCancelEdit();

                    setViewMode("tree");

                    setConfirmModal(null);

                  }

                });

                return;

              }

              setViewMode("tree");

            }}

          >

            Vista Jerárquica

          </button>

          <button

            type="button"

            className={`nt-mode-tab ${viewMode === "floorplan" ? "nt-mode-tab--active" : ""}`}

            onClick={() => setViewMode("floorplan")}

          >

            Modo Plano Físico

            {placedNodes.length > 0 && (

              <span className="nt-mode-counter">{placedNodes.length}</span>

            )}

          </button>



          {/* Opciones de tamaño rápido para todos los nodos en Plano Físico */}

          {viewMode === "floorplan" && isEditing && placedNodes.length > 0 && (

            <div className="nt-size-switcher">

              <span className="nt-size-label">Tamaño:</span>

              <button

                type="button"

                className="nt-size-btn"

                onClick={() => applySizeToAll(36, 36)}

                title="Convertir todos los dispositivos en iconos pequeños (ideal para habitaciones pequeñas)"

              >

                Todos Icono

              </button>

              <button

                type="button"

                className="nt-size-btn"

                onClick={() => applySizeToAll(115, 44)}

                title="Restablecer todos los dispositivos a tamaño normal (icono, nombre e IP)"

              >

                Todos Normal

              </button>

            </div>

          )}



          {/* Botón de Alertas de Topología integrado directamente en la barra */}

          {warnings.length > 0 && (

            <div style={{ position: "relative", marginLeft: 6 }}>

              <button 

                type="button"

                onClick={() => setShowWarnings(!showWarnings)}

                style={{

                  background: "#b45309",

                  color: "#fef3c7",

                  border: "1px solid #d97706",

                  padding: "5px 11px",

                  borderRadius: 6,

                  fontWeight: 600,

                  cursor: "pointer",

                  display: "inline-flex",

                  alignItems: "center",

                  gap: 6,

                  fontSize: 12

                }}

              >

                <span>⚠️ {warnings.length} Alertas {showWarnings ? "▲" : "▼"}</span>

              </button>

              {showWarnings && (

                <div style={{

                  position: "absolute",

                  top: "calc(100% + 6px)",

                  left: 0,

                  background: "#0f172a",

                  border: "1px solid rgba(245, 158, 11, 0.4)",

                  borderRadius: 8,

                  padding: 14,

                  width: 320,

                  boxShadow: "0 10px 25px rgba(0,0,0,0.6)",

                  zIndex: 9999

                }}>

                  <h4 style={{ margin: "0 0 8px 0", color: "#f59e0b", fontSize: 13, fontWeight: 700 }}>

                    Advertencias de Escaneo

                  </h4>

                  <ul style={{ margin: 0, paddingLeft: 18, color: "#cbd5e1", fontSize: 12, display: "flex", flexDirection: "column", gap: 6 }}>

                    {warnings.map((w, i) => (

                      <li key={i}>{w}</li>

                    ))}

                  </ul>

                </div>

              )}

            </div>

          )}

        </div>



        {viewMode === "floorplan" ? (

          <div className="nt-toolbar-group" style={{ marginLeft: "auto" }}>

            <input

              ref={fileInputRef}

              type="file"

              accept="image/*"

              style={{ display: "none" }}

              onChange={handleImageSelect}

            />



            {isEditing ? (

              <>

                <button

                  type="button"

                  className="nt-toolbar-btn"

                  onClick={() => fileInputRef.current?.click()}

                  title="Subir o cambiar imagen de fondo del plano"

                >

                  {floorplanImage ? "Cambiar Plano" : "Subir Plano"}

                </button>

                

                {floorplanImage && (

                  <button

                    type="button"

                    className="nt-toolbar-btn"

                    onClick={handleRemoveImage}

                    title="Quitar plano de fondo"

                  >

                    Quitar Fondo

                  </button>

                )}



                <button

                  type="button"

                  className={`nt-toolbar-btn ${showLinks ? "nt-toolbar-btn--active" : ""}`}

                  onClick={() => setShowLinks(s => !s)}

                  title="Mostrar u ocultar líneas hacia el router"

                >

                  Enlaces: {showLinks ? "ON" : "OFF"}

                </button>



                <button

                  type="button"

                  className="nt-toolbar-btn nt-toolbar-btn--success"

                  onClick={handleSave}

                  title="Guardar distribución e imagen en tu navegador"

                >

                  Guardar y Salir

                </button>



                <button

                  type="button"

                  className="nt-toolbar-btn"

                  onClick={handleCancelEdit}

                  title="Descartar cambios no guardados"

                >

                  Cancelar

                </button>



                <button

                  type="button"

                  className="nt-toolbar-btn nt-toolbar-btn--danger"

                  onClick={handleResetAll}

                  title="Reiniciar y borrar plano físico"

                >

                  Reiniciar

                </button>

              </>

            ) : (

              <>

                <button

                  type="button"

                  className={`nt-toolbar-btn ${showLinks ? "nt-toolbar-btn--active" : ""}`}

                  onClick={() => setShowLinks(s => !s)}

                  title="Mostrar u ocultar líneas hacia el router"

                >

                  Enlaces: {showLinks ? "ON" : "OFF"}

                </button>



                <button

                  type="button"

                  className="nt-toolbar-btn nt-toolbar-btn--primary"

                  onClick={() => setIsEditing(true)}

                  title="Entrar al modo edición para mover o redimensionar dispositivos"

                >

                  Editar Distribución

                </button>



                {(floorplanImage || placedNodes.length > 0) && (

                  <button

                    type="button"

                    className="nt-toolbar-btn nt-toolbar-btn--danger"

                    onClick={handleResetAll}

                    title="Borrar plano y posiciones guardadas"

                  >

                    Reiniciar

                  </button>

                )}

              </>

            )}

            {/* Botón cajón de dispositivos integrado directamente en la barra */}
            <button
              type="button"
              className={`nt-drawer-toggle-btn ${isDrawerOpen ? 'nt-drawer-toggle-btn--active' : ''}`}
              onClick={() => setIsDrawerOpen(prev => !prev)}
              title={isDrawerOpen ? "Ocultar panel lateral de dispositivos" : "Mostrar panel lateral de dispositivos"}
            >
              <span>📦</span>
              <span>Dispositivos ({unplacedNodes.length})</span>
              <span style={{ fontSize: 10 }}>{isDrawerOpen ? "▶" : "◀"}</span>
            </button>

          </div>

        ) : (

          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>

            <span style={{ color: "#64748b", fontSize: 11 }}>

              Arrastrar fondo para mover · Rueda para zoom

            </span>

          </div>

        )}

      </div>



      {/* Leyenda explicativa contextual */}

      <div className="nt-legend">

        {[

          { color: "#ffd700", label: "👑 Escáner (Este PC)" },

          { color: "#38bdf8", label: viewMode === "floorplan" ? "📡 Gateway / Router" : "Internet" },

          ...(viewMode === "tree" ? [

            { color: "#93c5fd", label: "Gateway" },

            { color: "#fbbf24", label: "Extensor / AP" }

          ] : []),

          { color: "#10b981", label: "Seguro" },

          { color: "#eab308", label: "Riesgo Medio" },

          { color: "#f43f5e", label: "Riesgo Crítico" },

        ].map(({ color, label }) => (

          <span key={label} className="nt-legend-item">

            <span style={{ width: 9, height: 9, borderRadius: "50%", background: color, display: "inline-block", flexShrink: 0 }} />

            {label}

          </span>

        ))}

        <span className="nt-legend-item" style={{ marginLeft: "auto", color: isEditing ? "#38bdf8" : "#64748b", fontSize: 11, fontWeight: isEditing ? 600 : 500 }}>

          {viewMode === "floorplan" 

            ? (isEditing ? "MODO EDICIÓN: Arrastra el dispositivo para moverlo · Arrastra la esquina inferior derecha ⤡ para agrandar o achicar a icono" : "Clic en un dispositivo para enfocarlo · Presiona 'Editar Distribución' para moverlos o redimensionarlos")

            : "Arrastrar para mover · Rueda para zoom · Clic para enfocar"}

        </span>

      </div>



      {/* Barra de Gestión de Plantas / Pisos (Multi-Piso) */}
      {viewMode === "floorplan" && (
        <div className="nt-floors-bar">
          <div className="nt-floors-tabs">
            <span className="nt-floors-label">🏢 Plantas / Pisos:</span>
            {floors.map((floor) => {
              const isCurrent = floor.id === activeFloorId;
              const count = Object.keys(floor.positions || {}).length;
              const isEditingThis = editingFloorId === floor.id;

              return (
                <div
                  key={floor.id}
                  className={`nt-floor-tab ${isCurrent ? 'nt-floor-tab--active' : ''}`}
                  onClick={() => !isEditingThis && setActiveFloorId(floor.id)}
                >
                  {isEditingThis ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} onClick={e => e.stopPropagation()}>
                      <input
                        type="text"
                        value={floorNameInput}
                        onChange={e => setFloorNameInput(e.target.value)}
                        onKeyDown={e => {
                          if (e.key === 'Enter') saveRenameFloor();
                          if (e.key === 'Escape') setEditingFloorId(null);
                        }}
                        autoFocus
                        className="nt-floor-rename-input"
                      />
                      <button type="button" onClick={saveRenameFloor} className="nt-floor-icon-btn" title="Guardar">✓</button>
                      <button type="button" onClick={() => setEditingFloorId(null)} className="nt-floor-icon-btn" title="Cancelar">✕</button>
                    </div>
                  ) : (
                    <>
                      <span className="nt-floor-name" onDoubleClick={() => isEditing && startRenameFloor(floor)}>
                        {floor.name}
                      </span>
                      <span className="nt-floor-count" title={`${count} dispositivos ubicados en esta planta`}>
                        {count}
                      </span>
                      {isEditing && (
                        <div className="nt-floor-actions" onClick={e => e.stopPropagation()}>
                          <button
                            type="button"
                            onClick={() => startRenameFloor(floor)}
                            className="nt-floor-action-btn"
                            title="Renombrar planta"
                          >
                            ✏️
                          </button>
                          {floors.length > 1 && (
                            <button
                              type="button"
                              onClick={() => handleRemoveFloor(floor)}
                              className="nt-floor-action-btn nt-floor-action-btn--delete"
                              title="Eliminar esta planta"
                            >
                              🗑️
                            </button>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </div>
              );
            })}

            {isEditing && (
              <button
                type="button"
                onClick={handleAddFloor}
                className="nt-add-floor-btn"
                title="Añadir una nueva planta o piso al edificio"
              >
                ＋ Añadir Piso
              </button>
            )}
          </div>

          <div className="nt-floors-info">
            <span>
              {activeFloor.image ? "🖼️ Plano asignado" : "⚠️ Sin plano cargado"} · {placedNodes.length} en {activeFloor.name}
            </span>
          </div>
        </div>
      )}

      {/* Cajón Lateral Inteligente (Smart Device Drawer para 100+ equipos) */}
      {viewMode === "floorplan" && (
        <aside className={`nt-device-drawer ${isDrawerOpen ? 'nt-device-drawer--open' : ''}`}>
          <div className="nt-drawer-header">
            <div className="nt-drawer-title">
              <span>📦</span>
              <span>Dispositivos por Ubicar ({unplacedNodes.length})</span>
            </div>
            <button
              type="button"
              className="nt-drawer-close-btn"
              onClick={() => setIsDrawerOpen(false)}
              title="Cerrar panel lateral"
            >
              ✕
            </button>
          </div>

          {/* Buscador predictivo en tiempo real */}
          <div className="nt-drawer-search-box">
            <input
              type="text"
              placeholder="🔍 Buscar por IP, nombre, marca..."
              value={drawerSearch}
              onChange={(e) => setDrawerSearch(e.target.value)}
              className="nt-drawer-search-input"
            />
          </div>

          {/* Píldoras de filtrado por categoría */}
          <div className="nt-drawer-categories">
            {categoriesList.map(cat => (
              <button
                key={cat.id}
                type="button"
                className={`nt-drawer-cat-pill ${selectedCategory === cat.id ? 'nt-drawer-cat-pill--active' : ''}`}
                onClick={() => setSelectedCategory(cat.id)}
              >
                <span>{cat.icon}</span>
                <span>{cat.label}</span>
                <span style={{ opacity: 0.65, fontSize: 10 }}>({cat.count})</span>
              </button>
            ))}
          </div>

          {/* Barra de acciones y ubicación en lote */}
          <div className="nt-drawer-actions-bar">
            {isEditing ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', gap: 6 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', userSelect: 'none' }}>
                  <input
                    type="checkbox"
                    checked={filteredList.length > 0 && filteredList.every(n => selectedIps.has(n.ip))}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedIps(new Set(filteredList.map(n => n.ip)));
                      } else {
                        setSelectedIps(new Set());
                      }
                    }}
                  />
                  <span>Todos ({filteredList.length})</span>
                </label>

                {selectedIps.size > 0 && (
                  <button
                    type="button"
                    onClick={() => placeSelectedNodes(selectedIps)}
                    className="nt-dock-btn-all"
                    style={{ background: '#0284c7', color: '#fff', border: 'none', padding: '4px 10px', borderRadius: 6, cursor: 'pointer', fontWeight: 700 }}
                    title="Ubicar dispositivos seleccionados agrupados en el centro del plano"
                  >
                    📍 Ubicar ({selectedIps.size})
                  </button>
                )}

                <button
                  type="button"
                  onClick={placeAllUnplaced}
                  className="nt-dock-btn-all"
                  style={{ background: '#1e293b', border: '1px solid #38bdf8', color: '#38bdf8', padding: '4px 10px', borderRadius: 6, cursor: 'pointer', fontWeight: 600 }}
                  title="Distribuir automáticamente todos los dispositivos pendientes en este plano"
                >
                  Ubicar Todos
                </button>
              </div>
            ) : (
              <span style={{ fontSize: 11, color: '#94a3b8' }}>
                Entra en 'Editar Distribución' para arrastrar al plano
              </span>
            )}
          </div>

          {/* Lista scrolleable de tarjetas compactas */}
          <div className="nt-drawer-list">
            {filteredList.length === 0 ? (
              <div style={{ padding: '36px 16px', textAlign: 'center', color: '#64748b', fontSize: 12 }}>
                {unplacedNodes.length === 0 ? (
                  <>
                    <div style={{ fontSize: 26, marginBottom: 8 }}>🎉</div>
                    <div style={{ color: '#38bdf8', fontWeight: 700, fontSize: 13 }}>¡Todos los dispositivos ubicados!</div>
                    <div style={{ marginTop: 4 }}>No quedan equipos pendientes de posicionar en este piso.</div>
                  </>
                ) : (
                  <>
                    <div style={{ fontSize: 26, marginBottom: 8 }}>🔍</div>
                    <div>No se encontraron equipos para el filtro actual.</div>
                  </>
                )}
              </div>
            ) : (
              filteredList.map(node => {
                const isSelected = selectedIps.has(node.ip);
                const hasVulns = (node.vulnerabilidades && node.vulnerabilidades.length > 0) || (node.max_score && node.max_score > 0);

                return (
                  <div
                    key={node.ip}
                    className={`nt-drawer-card ${isSelected ? 'nt-drawer-card--selected' : ''}`}
                    draggable={isEditing}
                    onDragStart={(e) => {
                      e.dataTransfer.setData('text/plain', node.ip);
                    }}
                    onClick={() => {
                      if (isEditing) {
                        toggleSelectIp(node.ip);
                      }
                    }}
                    onDoubleClick={() => isEditing && placeNodeAtCenter(node.ip)}
                    title={isEditing ? "Arrastra directamente hacia el plano, o haz doble clic para posicionar en el centro" : ""}
                    style={{ cursor: isEditing ? "grab" : "default" }}
                  >
                    <div className="nt-drawer-card-left">
                      {isEditing && (
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) => {
                            e.stopPropagation();
                            toggleSelectIp(node.ip);
                          }}
                          onClick={(e) => e.stopPropagation()}
                        />
                      )}
                      <span className="nt-drawer-card-icon">
                        {node.es_gateway || node.ip === resolvedRouterIp ? "📡" : getDeviceIcon(node, resolvedRouterIp)}
                      </span>
                      <div className="nt-drawer-card-info">
                        <span className="nt-drawer-card-ip">{node.ip}</span>
                        <span className="nt-drawer-card-host">
                          {node.es_gateway || node.ip === resolvedRouterIp
                            ? (node.ssid ? node.ssid.replace(/^Red\s+/i, '') : (node.hostname && !node.hostname.includes("Router Principal (C)") ? node.hostname : (node.fabricante ? `Router (${node.fabricante})` : "Router Principal")))
                            : node.hostname && node.hostname !== "Caché Local ARP"
                              ? node.hostname
                              : node.fabricante || "Dispositivo de Red"}
                        </span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      {(() => {
                        const med = getDeviceConnectionMedium(node, resolvedRouterIp);
                        if (!med) return null;
                        return (
                          <span 
                            style={{ 
                              fontSize: 10, 
                              background: med.medio === 'wifi' ? 'rgba(14, 165, 233, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                              color: med.medio === 'wifi' ? '#38bdf8' : '#c084fc',
                              border: med.medio === 'wifi' ? '1px solid rgba(14, 165, 233, 0.3)' : '1px solid rgba(168, 85, 247, 0.3)',
                              padding: '2px 6px',
                              borderRadius: 4,
                              fontWeight: 700,
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '3px'
                            }}
                            title={med.detalle || `Conexión ${med.label}`}
                          >
                            <span>{med.icono}</span>
                            <span>{med.label}</span>
                          </span>
                        );
                      })()}
                      {node.telemetria && (
                        <span 
                          style={{ 
                            fontSize: 10, 
                            background: (node.telemetria.packet_loss || 0) >= 100 
                              ? 'rgba(239, 68, 68, 0.2)' 
                              : (node.telemetria.packet_loss || 0) > 0 
                                ? 'rgba(245, 158, 11, 0.2)' 
                                : 'rgba(255, 255, 255, 0.05)', 
                            color: (node.telemetria.packet_loss || 0) >= 100 
                              ? '#f87171' 
                              : (node.telemetria.packet_loss || 0) > 0 
                                ? '#fbbf24' 
                                : '#64ffda', 
                            border: (node.telemetria.packet_loss || 0) >= 100 
                              ? '1px solid rgba(239, 68, 68, 0.4)' 
                              : (node.telemetria.packet_loss || 0) > 0 
                                ? '1px solid rgba(245, 158, 11, 0.4)' 
                                : '1px solid rgba(255, 255, 255, 0.1)', 
                            borderRadius: 6, 
                            padding: '1px 6px', 
                            fontWeight: 700 
                          }}
                          title={`Telemetría: ${node.telemetria.packets_recv || 0}/${node.telemetria.packets_sent || 4} pkts (${node.telemetria.packet_loss || 0}% pérdida)`}
                        >
                          {(node.telemetria.packet_loss || 0) >= 100 
                            ? `🔴 0/${node.telemetria.packets_sent || 4}` 
                            : (node.telemetria.packet_loss || 0) > 0 
                              ? `⚠️ ${node.telemetria.packet_loss}%` 
                              : `${node.telemetria.latency_ms !== null && node.telemetria.latency_ms !== undefined ? `${node.telemetria.latency_ms}ms` : '<1ms'}`}
                        </span>
                      )}
                      {hasVulns && (
                        <span style={{ fontSize: 10, background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: 10, padding: '1px 6px', fontWeight: 700 }}>
                          🚨 {node.max_score ? node.max_score.toFixed(1) : '!'}
                        </span>
                      )}
                      {isEditing && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            placeNodeAtCenter(node.ip);
                          }}
                          style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.35)', color: '#34d399', borderRadius: 4, padding: '2px 6px', fontSize: 11, cursor: 'pointer', fontWeight: 700 }}
                          title="Ubicar en el centro del plano"
                        >
                          ＋
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}

            {/* Equipos ya ubicados en otras plantas */}
            {otherFloorNodes.length > 0 && (
              <div style={{ marginTop: 12, padding: '10px 12px', background: 'rgba(56, 189, 248, 0.05)', border: '1px dashed rgba(56, 189, 248, 0.25)', borderRadius: 8, fontSize: 11 }}>
                <div style={{ color: '#38bdf8', fontWeight: 700, marginBottom: 4 }}>
                  🏢 En otras plantas ({otherFloorNodes.length}):
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 110, overflowY: 'auto' }}>
                  {otherFloorNodes.map(on => (
                    <div key={on.ip} style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8' }}>
                      <span style={{ fontFamily: 'monospace' }}>{on.ip}</span>
                      <span style={{ color: '#cbd5e1' }}>{on.locatedFloorName}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </aside>
      )}

      {/* Viewport Principal (Zoom + Pan) */}

      <div

        className="nt-viewport"

        ref={viewportRef}

        onMouseDown={onMouseDown}

        onMouseMove={onMouseMove}

        onMouseUp={onMouseUp}

        onMouseLeave={onMouseUp}

        style={{ cursor: "grab" }}

      >

        {viewMode === "tree" ? (

          /* VISTA JERÁRQUICA ORIGINAL (100% INTACTA) */

          <div className={`nt-canvas ${isAnimatingZoom ? 'nt-canvas--animating' : ''}`} style={{ transform: `scale(${zoom})`, transformOrigin: "top center" }}>

            <ul className="nt-children nt-children--root">



              <OrgBranch

                card={

                  <div ref={internetCardRef} className="nt-card nt-card--internet" onClick={() => focusOnElement(internetCardRef.current)} style={{ cursor: "pointer" }}>

                    <div className="nt-card-icon">🌐</div>

                    <div className="nt-card-label">Internet</div>

                    {isp && <div className="nt-card-ip">{isp.ip}</div>}

                    <div className="nt-badge" style={{ background: "rgba(56,189,248,0.12)", color: "#38bdf8", border: "1px solid rgba(56,189,248,0.25)" }}>

                      ISP PÚBLICO

                    </div>

                  </div>

                }

              >

                {cgnatGroup ? (

                  <OrgBranch card={<CgnatGroupCard count={cgnatGroup.count} hops={cgnatGroup.hops} onClick={() => setShowIspDrawer(true)} />}>

                    {gatewayBranch}

                  </OrgBranch>

                ) : (

                  gatewayBranch

                )}

              </OrgBranch>



            </ul>

          </div>

        ) : (

          /* MODO PLANO FÍSICO INTERACTIVO */
          <div className={`nt-canvas ${isAnimatingZoom ? 'nt-canvas--animating' : ''}`} style={{ transform: `scale(${zoom})`, transformOrigin: "top center" }}>
            <div 
              className={`nt-floorplan-canvas ${isEditing ? "nt-floorplan-canvas--editing" : ""}`}
              style={{
                width: `${canvasSize.width}px`,
                height: `${canvasSize.height}px`,
                backgroundImage: floorplanImage ? `url(${floorplanImage})` : undefined,
                backgroundSize: "100% 100%",
                backgroundRepeat: "no-repeat",
                backgroundPosition: "center",
                imageRendering: "high-quality",
                position: "relative"
              }}
              onDragOver={(e) => {
                if (isEditing) {
                  e.preventDefault();
                  e.dataTransfer.dropEffect = 'copy';
                }
              }}
              onDrop={(e) => {
                if (!isEditing) return;
                e.preventDefault();
                const ip = e.dataTransfer.getData('text/plain');
                if (!ip) return;
                const rect = e.currentTarget.getBoundingClientRect();
                const rawX = (e.clientX - rect.left) / zoom;
                const rawY = (e.clientY - rect.top) / zoom;
                const x = Math.max(10, Math.min(canvasSize.width - 120, Math.round(rawX - 58)));
                const y = Math.max(10, Math.min(canvasSize.height - 50, Math.round(rawY - 22)));
                setPositions(prev => ({
                  ...prev,
                  [ip]: { x, y, w: 115, h: 44 }
                }));
                setHasUnsavedChanges(true);
              }}
            >
              {/* Líneas de enlace SVG conectadas exactamente al centro dinámico de cada tarjeta */}

              <svg 

                className="nt-floorplan-svg" 

                width={canvasSize.width} 

                height={canvasSize.height}

                style={{ position: "absolute", top: 0, left: 0, pointerEvents: "none", zIndex: 1 }}

              >

                {showLinks && gatewayPos && placedNodes.map(node => {

                  if (node.es_gateway || node.ip === resolvedRouterIp) return null;

                  const w = node.pos?.w || 115;

                  const isSmall = w < 75;

                  const h = isSmall ? w : (node.pos?.h || 44);

                  const nodeCenterX = node.pos.x + Math.round(w / 2);

                  const nodeCenterY = node.pos.y + Math.round(h / 2);

                  return (

                    <line

                      key={`link-${node.ip}`}

                      x1={gatewayPos.x}

                      y1={gatewayPos.y}

                      x2={nodeCenterX}

                      y2={nodeCenterY}

                      stroke="#38bdf8"

                      strokeWidth="2"

                      strokeDasharray="6 4"

                      strokeOpacity="0.85"

                    />

                  );

                })}

              </svg>



              {/* Banner de inicio si no hay plano ni dispositivos colocados */}

              {!floorplanImage && placedNodes.length === 0 && (

                <div className="nt-floorplan-empty-banner">

                  <h3 style={{ margin: "0 0 6px 0", color: "#f8fafc", fontSize: 16, fontWeight: 700 }}>

                    Modo Plano Físico

                  </h3>

                  <p style={{ margin: "0 0 16px 0", color: "#94a3b8", fontSize: 13, maxWidth: 420, lineHeight: 1.5 }}>

                    Sube una imagen del plano de tu casa u oficina y posiciona tus dispositivos (routers, PCs, teléfonos, cámaras) en sus ubicaciones reales.

                  </p>

                  <div style={{ display: "flex", gap: 10 }}>

                    {!isEditing ? (

                      <button

                        type="button"

                        className="nt-toolbar-btn nt-toolbar-btn--primary"

                        onClick={() => {

                          setIsEditing(true);

                          setTimeout(() => fileInputRef.current?.click(), 100);

                        }}

                      >

                        Comenzar y Subir Plano

                      </button>

                    ) : (

                      <button

                        type="button"

                        className="nt-toolbar-btn nt-toolbar-btn--primary"

                        onClick={() => fileInputRef.current?.click()}

                      >

                        Seleccionar Imagen de Plano

                      </button>

                    )}

                  </div>

                </div>

              )}



              {/* Dispositivos ubicados en el plano con soporte de redimensionamiento adaptativo */}

              {placedNodes.map(node => (

                <FloorPlanNodeCard

                  key={node.ip}

                  node={node}

                  isEditing={isEditing}

                  onStartDrag={handleStartNodeDrag}

                  onStartResize={handleStartNodeResize}

                  onUnplace={handleUnplaceNode}

                  routerIp={resolvedRouterIp}

                  localIp={localIp}

                  onFocus={focusOnElement}

                />

              ))}

            </div>

          </div>

        )}

      </div>



      {showIspDrawer && cgnatGroup && (

        <div style={{

          position: "fixed",

          top: 0,

          right: 0,

          width: "360px",

          height: "100vh",

          background: "rgba(15, 23, 42, 0.98)",

          backdropFilter: "blur(12px)",

          borderLeft: "1px solid #334155",

          boxShadow: "-8px 0 32px rgba(0, 0, 0, 0.6)",

          zIndex: 9999,

          display: "flex",

          flexDirection: "column",

          padding: "24px",

          boxSizing: "border-box",

          color: "#e2e8f0"

        }}>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #334155", paddingBottom: 14, marginBottom: 16 }}>

            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>

              <span style={{ fontSize: 22 }}>📶</span>

              <div>

                <h3 style={{ margin: 0, fontSize: 16, color: "#38bdf8", fontWeight: "bold" }}>Nodos ISP / CGNAT</h3>

                <span style={{ fontSize: 12, color: "#94a3b8" }}>{cgnatGroup.count} Saltos de Enrutamiento</span>

              </div>

            </div>

            <button 

              onClick={() => setShowIspDrawer(false)} 

              style={{ background: "transparent", border: "none", color: "#94a3b8", fontSize: 20, cursor: "pointer", fontWeight: "bold" }}

              title="Cerrar Panel"

            >

              ✕

            </button>

          </div>



          <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 10, paddingRight: 4 }}>

            {cgnatGroup.hops && cgnatGroup.hops.map((hop, i) => (

              <div key={i} style={{

                background: "#1e293b",

                border: "1px solid #334155",

                borderRadius: 6,

                padding: 12,

                display: "flex",

                justifyContent: "space-between",

                alignItems: "center"

              }}>

                <div>

                  <div style={{ fontSize: 11, color: "#38bdf8", fontWeight: 700 }}>SALTO {i + 1}</div>

                  <div style={{ fontSize: 13, color: "#f8fafc", fontWeight: "bold", marginTop: 2 }}>

                    {hop.ip && hop.ip !== "unknown" ? hop.ip : "ICMP Bloqueado / Timeout"}

                  </div>

                  {hop.hostname && hop.hostname !== "Nodo ISP / CGNAT Intermedio" && (

                    <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>{hop.hostname}</div>

                  )}

                </div>

                <span className="nt-badge" style={{ 

                  background: hop.tipo === "invisible" ? "rgba(245, 158, 11, 0.15)" : "rgba(56, 189, 248, 0.15)", 

                  color: hop.tipo === "invisible" ? "#fbbf24" : "#38bdf8",

                  border: `1px solid ${hop.tipo === "invisible" ? "rgba(245, 158, 11, 0.3)" : "rgba(56, 189, 248, 0.3)"}`,

                  fontSize: 10,

                  fontWeight: "bold"

                }}>

                  {hop.tipo === "invisible" ? "INVISIBLE" : "NODO PROVEEDOR"}

                </span>

              </div>

            ))}

          </div>



          <button 

            onClick={() => setShowIspDrawer(false)}

            style={{

              marginTop: 16,

              background: "#1e293b",

              color: "#38bdf8",

              border: "1px solid #334155",

              borderRadius: 6,

              padding: "10px",

              fontWeight: 600,

              fontSize: 13,

              cursor: "pointer"

            }}

          >

            Cerrar Panel

          </button>

        </div>

      )}



      {/* Modal de confirmación personalizado (sin alertas nativas de localhost) */}

      {confirmModal && (

        <div 

          className="secscan-confirm-overlay" 

          onClick={() => !confirmModal.singleButton && setConfirmModal(null)}

        >

          <div 

            className={`secscan-confirm-box ${confirmModal.confirmType === "danger" ? "secscan-confirm-box--danger" : "secscan-confirm-box--primary"}`}

            onClick={(e) => e.stopPropagation()}

          >

            <div className="secscan-confirm-header">

              <div className={`secscan-confirm-icon ${confirmModal.confirmType === "danger" ? "secscan-confirm-icon--danger" : "secscan-confirm-icon--primary"}`}>

                {confirmModal.confirmType === "danger" ? "⚠️" : "ℹ️"}

              </div>

              <h3 className="secscan-confirm-title">

                {confirmModal.title || "¿Estás seguro?"}

              </h3>

            </div>



            <p className="secscan-confirm-message">

              {confirmModal.message}

            </p>



            <div className="secscan-confirm-actions">

              {!confirmModal.singleButton && (

                <button

                  type="button"

                  className="secscan-confirm-btn-cancel"

                  onClick={() => setConfirmModal(null)}

                >

                  Cancelar

                </button>

              )}

              <button

                type="button"

                className={confirmModal.confirmType === "danger" ? "secscan-confirm-btn-danger" : "secscan-confirm-btn-primary"}

                onClick={() => {

                  if (confirmModal.onConfirm) confirmModal.onConfirm();

                }}

              >

                {confirmModal.confirmText || "Aceptar"}

              </button>

            </div>

          </div>

        </div>

      )}



      {/* Controles de Zoom y Pantalla Completa con rango extendido (20% - 400%) */}
      <div className="nt-controls" style={{ left: 20, right: 'auto', bottom: 20, zIndex: 25 }}>
        <button className="nt-ctrl-btn" onClick={() => setZoom(z => Math.min(z * 1.18, 4.0))} title="Zoom + (Acercar)">＋</button>
        <span className="nt-zoom-label">{Math.round(zoom * 100)}%</span>
        <button className="nt-ctrl-btn" onClick={() => setZoom(z => Math.max(z * 0.82, 0.2))} title="Zoom − (Alejar)">－</button>
        <button className="nt-ctrl-btn" onClick={handleResetZoom} title="Restablecer vista completa">⊡</button>
        <button 
          className="nt-ctrl-btn" 
          onClick={() => {
            const root = document.querySelector('.nt-root');
            if (!document.fullscreenElement) {
              root.requestFullscreen().catch(err => console.log(err));
            } else {
              document.exitFullscreen();
            }
          }} 
          title="Pantalla Completa"
          style={{ marginLeft: 8 }}
        >
          ⛶
        </button>
      </div>
    </div>

  );

}

