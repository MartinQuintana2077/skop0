import { Home as HomeIcon, BarChart, LogOut, Shield, Crosshair, Flame, Radio, Globe, Monitor, Plug, Folder, Clock, AlertTriangle, Activity, Rocket, EyeOff, Zap, Maximize2, Minimize2, Power, HardDrive , ChevronDown, ChevronUp, Layers, ExternalLink, Crown, Network, RefreshCw } from "lucide-react";



import React, { Component, useState, useEffect, useCallback, useMemo } from "react";



import {



  BrowserRouter as Router,



  Routes,



  Route,



  useNavigate,



  useParams,



  useLocation,



  Link



} from "react-router-dom";



import { triggerN8nScan, cancelScan, deepScan, getDeviceTelemetry, getDevices, getVulnerabilities, checkHealth, installNmap, getScanDevices, getScanDetails, getScanHistory, deleteScan, deleteBatchScans, getWifiNetworks, connectWifi, sendHeartbeat, sendShutdown, getSubnetBridgeStatus, bindSubnetBridge, unbindSubnetBridge, getNetworkInterfaces, checkAppUpdate } from "./services/api";



import "./index.css";



import { AuthProvider, useAuth } from "./context/AuthContext";



import LoginPage from "./pages/LoginPage";



import ScanHistoryPage from "./pages/ScanHistoryPage";



import NetworkTree, { getDeviceIcon, getDeviceConnectionMedium, isScannerHost } from "./components/NetworkTree";



import { translateToSpanish } from "./utils/translator";



import BackupModal from "./components/BackupModal";
import SubscriptionModal from "./components/SubscriptionModal";
import UpdateModal from "./components/UpdateModal";
import Skop0Logo from "./components/Skop0Logo";
import OnboardingTour from "./components/OnboardingTour";
import AppearanceModal, { applySavedAppearance } from "./components/AppearanceModal";

applySavedAppearance();



function TranslatedText({ text }) {



  const [translated, setTranslated] = useState(text);



  useEffect(() => {



    let isMounted = true;



    if (!text || text === "Sin descripción" || text === "Sin descripción disponible.") {



      setTranslated(text || "Sin descripción disponible.");



      return;



    }



    translateToSpanish(text).then((res) => {



      if (isMounted && res) {



        setTranslated(res);



      }



    });



    return () => {



      isMounted = false;



    };



  }, [text]);



  return <>{translated}</>;



}




/* ========== RENDERIZADOR DE LINEAS DE CONSOLA (ESTRUCTURADO Y LIMPIO) ========== */
function renderTerminalLine(rawLog, i) {
  if (!rawLog) return null;
  let log = String(rawLog).trim();

  // 1. Extraer timestamp si existe: [HH:MM:SS]
  let timeStr = "";
  const timeMatch = log.match(/^\[(\d{2}:\d{2}:\d{2})\]\s*/);
  if (timeMatch) {
    timeStr = timeMatch[1];
    log = log.substring(timeMatch[0].length);
  }

  // 2. Detectar si es cabecera de Fase Principal
  const isMajorPhase = /\[FASE\s*\d\]|Iniciando auditoria|Fase de descubrimiento completada/i.test(log);

  // 3. Parsear badges semanticos segun el proceso o resultado
  let badgeType = null;
  let badgeText = "";
  let remainder = log;

  const phaseMatch = log.match(/^(\[FASE\s*\d[^\]]*\])/i);
  if (phaseMatch) {
    badgeType = "phase";
    badgeText = phaseMatch[1];
    remainder = log.substring(phaseMatch[0].length).trim();
  } else if (/^(\[(?:L2 Confirmado|Nmap Confirmado|Verificacion Activa|OK|ABIERTO|Activo)\])/i.test(log) || log.startsWith("✓")) {
    const m = log.match(/^(\[[^\]]+\])/);
    badgeType = "ok";
    badgeText = m ? m[1] : "✓";
    remainder = log.substring((m ? m[0].length : 0)).trim();
  } else if (/^(\[(?:ERROR|BLOQUEADO|CRITICO)\])/i.test(log) || /Error critico|Error crítico/i.test(log)) {
    const m = log.match(/^(\[[^\]]+\])/);
    badgeType = "err";
    badgeText = m ? m[1] : "✕ ERROR";
    remainder = log.substring((m ? m[0].length : 0)).trim();
  } else if (/^(\[(?:ALERTA|AVISO|WARNING)\])/i.test(log) || /Timeout|sin respuesta/i.test(log)) {
    const m = log.match(/^(\[[^\]]+\])/);
    badgeType = "warn";
    badgeText = m ? m[1] : "⚠️ AVISO";
    remainder = log.substring((m ? m[0].length : 0)).trim();
  } else if (/^(\[(?:SNMP|DHCP|Traceroute|Fallback|DAEMON|SYS|Barrido Activo|L2 ARP Sweep|Nmap|HOST|DEEP-SCAN|Fase \d - Intento \d)\])/i.test(log)) {
    const m = log.match(/^(\[[^\]]+\])/);
    badgeType = "proc";
    badgeText = m ? m[1] : "";
    remainder = log.substring((m ? m[0].length : 0)).trim();
  }

  // 4. Separar fabricante / vendor si viene con tuberia
  let mainText = remainder;
  let vendorText = "";
  if (remainder.includes(" | ")) {
    const parts = remainder.split(" | ");
    mainText = parts[0];
    vendorText = parts.slice(1).join(" | ");
  }

  // 5. Destacar IP y MAC
  let formattedContent = null;
  const ipMacMatch = mainText.match(/^(.*?)(?:(?:Activo en tiempo real|Host activo|Confirmado encendido|Analizando|para):?\s*)?(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)(.*)$/i);
  if (ipMacMatch && !mainText.toLowerCase().includes("traceroute") && !mainText.includes("Red:")) {
    const prefixText = ipMacMatch[1] || "";
    const ipStr = ipMacMatch[2];
    const suffixText = ipMacMatch[3] || "";
    formattedContent = (
      <>
        {prefixText && <span className="terminal-text">{prefixText}</span>}
        <span className="terminal-ip">{ipStr}</span>
        {suffixText && <span className="terminal-mac">{suffixText}</span>}
      </>
    );
  }

  return (
    <div key={i} className={`terminal-line ${isMajorPhase ? "terminal-line--phase" : ""}`}>
      <span className="terminal-prompt">$</span>
      {timeStr && <span className="terminal-time">{timeStr}</span>}
      <div className="terminal-content">
        {badgeText && (
          <span className={`terminal-badge terminal-badge-${badgeType}`}>
            {badgeType === "ok" ? "✓ " : badgeType === "err" ? "✕ " : ""}{badgeText}
          </span>
        )}
        {formattedContent ? formattedContent : <span className="terminal-text">{mainText}</span>}
        {vendorText && (
          <span className="terminal-vendor">
            <span style={{ color: "#475569", margin: "0 4px" }}>|</span>
            {vendorText}
          </span>
        )}
      </div>
    </div>
  );
}


/* ========== PROTECTED ROUTE ========== */



const ProtectedRoute = ({ children }) => {



  const { user, loading } = useAuth();



  if (loading) return <div className="loading-screen">Cargando sesión...</div>;



  if (!user) return <LoginPage />;



  return children;



};



/* ========== SCAN ENGINE PERSISTENT STATE ========== */



const scanEngineState = {



  scanning: false,



  scanId: null,



  target: "auto",



  scanMsg: "",



  devicesFound: 0,



  totalTargets: 0,



  pollInterval: null,



  consoleLogs: [



    "[SYS] Skop0 CLI v1.3 - Motor de Auditoría y Redes Activo.",



    "[SYS] Elige un método de escaneo en los paneles interactivos del Bento Grid para inicializar...",



    "[SEC] Listo para monitoreo continuo en subredes locales."



  ],



  activeListeners: new Set()



};



function notifyScanListeners() {



  scanEngineState.activeListeners.forEach(listener => {



    try {



      listener({ ...scanEngineState });



    } catch (e) {}



  });



}



function useScanEngine() {



  const [state, setState] = useState({ ...scanEngineState });



  useEffect(() => {



    const listener = (s) => setState({ ...s });



    scanEngineState.activeListeners.add(listener);



    return () => {



      scanEngineState.activeListeners.delete(listener);



    };



  }, []);



  return state;



}



function resumeScan(scanId, target = "auto", getToken = null) {



  if (scanEngineState.scanning && scanEngineState.scanId === scanId) return;



  if (scanEngineState.pollInterval) {



    clearInterval(scanEngineState.pollInterval);



  }



  scanEngineState.scanning = true;



  scanEngineState.scanId = scanId;



  scanEngineState.target = target;



  scanEngineState.scanMsg = "Auditando dispositivos en segundo plano...";



  notifyScanListeners();



  let polls = 0;



  const maxPolls = 150;



  scanEngineState.pollInterval = setInterval(async () => {



    polls++;



    try {



      let token = "";



      if (typeof getToken === "function") {



        try { token = await getToken(); } catch (_) {}



      }



      const res = await getScanDetails(scanId, token);



      if (res && res.status === "ok" && res.details) {



        const { devices_found = 0, total_targets = 1, status, logs = [] } = res.details;



        if (logs && logs.length > 0) {



          scanEngineState.consoleLogs = logs;



        }



        scanEngineState.devicesFound = devices_found;



        scanEngineState.totalTargets = total_targets;



        if (status !== "completed" && status !== "cancelled" && status !== "error") {

          scanEngineState.scanMsg = `Auditando puertos... (${devices_found} / ${total_targets || '?'}) dispositivos listos`;

        }

        notifyScanListeners();

        if (status === "completed" || status === "cancelled" || status === "error" || polls >= maxPolls) {

          clearInterval(scanEngineState.pollInterval);

          scanEngineState.pollInterval = null;

          scanEngineState.scanning = false;

          if (status === "cancelled") {
            scanEngineState.scanMsg = "Auditoría detenida por el usuario.";
          }

          notifyScanListeners();

        }



      }



    } catch (e) {



      console.error("Error polling resumeScan", e);



    }



  }, 1500);



}



/* ========== NAVBAR ========== */



function Navbar() {

  const { user, logout, getToken, subscription, refreshSubscription } = useAuth();

  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [backupModalOpen, setBackupModalOpen] = useState(false);

  const [subModalOpen, setSubModalOpen] = useState(false);
  const [updateModalOpen, setUpdateModalOpen] = useState(false);
  const [appearanceModalOpen, setAppearanceModalOpen] = useState(false);
  const [appearanceFirstRun, setAppearanceFirstRun] = useState(false);
  const [currentTheme, setCurrentTheme] = useState(() => {
    try { return localStorage.getItem("secscan_theme") || "original"; } catch (e) { return "original"; }
  });
  const [currentLayout, setCurrentLayout] = useState(() => {
    try { return localStorage.getItem("secscan_layout") || "original"; } catch (e) { return "original"; }
  });

  const handleCloseAppearance = useCallback(() => {
    setAppearanceModalOpen(false);
    try {
      localStorage.setItem("secscan_appearance_configured_v1", "true");
    } catch (e) {}
    if (appearanceFirstRun) {
      setAppearanceFirstRun(false);
      try {
        const tourSeen = localStorage.getItem("secscan_tour_completed_v1");
        if (!tourSeen) {
          setTimeout(() => {
            window.dispatchEvent(new CustomEvent("secscan:start-tour"));
          }, 300);
        }
      } catch (e) {}
    }
  }, [appearanceFirstRun]);

  const handleSelectTheme = useCallback((themeId) => {
    setCurrentTheme(themeId);
    try {
      localStorage.setItem("secscan_theme", themeId);
    } catch (e) {}
    if (themeId === "original") {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", themeId);
    }
  }, []);

  const handleSelectLayout = useCallback((layoutId) => {
    setCurrentLayout(layoutId);
    try {
      localStorage.setItem("secscan_layout", layoutId);
    } catch (e) {}
    window.dispatchEvent(new CustomEvent("secscan:layout-changed", { detail: layoutId }));
  }, []);
  const [updateInfo, setUpdateInfo] = useState({ current_version: "1.3.0", latest_version: "1.3.0", update_available: false });
  const [checkingUpdate, setCheckingUpdate] = useState(false);

  const [authToken, setAuthToken] = useState("");

  const handleCheckUpdate = useCallback(async (autoOpen = false) => {
    setCheckingUpdate(true);
    try {
      const tk = getToken ? await getToken() : authToken;
      const info = await checkAppUpdate(tk);
      if (info && info.status === "ok") {
        setUpdateInfo(info);
        if (autoOpen && info.update_available) {
          setUpdateModalOpen(true);
        }
      }
    } catch (e) {
      console.warn("Update check warn:", e);
    } finally {
      setCheckingUpdate(false);
    }
  }, [getToken, authToken]);

  useEffect(() => {
    if (user) {
      handleCheckUpdate(true);
      try {
        const configured = localStorage.getItem("secscan_appearance_configured_v1");
        if (!configured) {
          const t = setTimeout(() => {
            setAppearanceFirstRun(true);
            setAppearanceModalOpen(true);
          }, 350);
          return () => clearTimeout(t);
        }
      } catch (e) {}
    }
  }, [user]);

  const scanEngine = useScanEngine();

  const navigate = useNavigate();

  useEffect(() => {

    if (getToken) {

      getToken().then(setAuthToken).catch(() => {});

    }

  }, [getToken]);

  useEffect(() => {
    const handleOpenSubModal = () => {
      setSubModalOpen(true);
      if (refreshSubscription) refreshSubscription();
    };
    window.addEventListener("secscan:open-subscription-modal", handleOpenSubModal);
    return () => window.removeEventListener("secscan:open-subscription-modal", handleOpenSubModal);
  }, [refreshSubscription]);

  if (!user) return null;



  return (



    <>



      <nav className="navbar">



        <div className="navbar-left" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>



          {user && (



            <button 



              className="navbar-hamburger" 



              onClick={() => setSidebarOpen(true)}



              aria-label="Abrir menú"



              style={{



                background: 'transparent',



                border: 'none',



                cursor: 'pointer',



                display: 'flex',



                flexDirection: 'column',



                gap: '5px',



                padding: '8px',



                zIndex: 110,



                transition: 'all 0.3s ease'



              }}



            >



              <span className="hamburger-line" style={{ display: 'block', width: '20px', height: '2px', background: 'var(--text-primary)', borderRadius: '2px', transition: 'all 0.3s ease' }}></span>



              <span className="hamburger-line" style={{ display: 'block', width: '20px', height: '2px', background: 'var(--text-primary)', borderRadius: '2px', transition: 'all 0.3s ease' }}></span>



              <span className="hamburger-line" style={{ display: 'block', width: '20px', height: '2px', background: 'var(--text-primary)', borderRadius: '2px', transition: 'all 0.3s ease' }}></span>



            </button>



          )}



          



          <Link to="/" className="navbar-logo">



            <div className="navbar-logo-icon">
              <Skop0Logo size={32} />
            </div>



            <div className="navbar-logo-text">



              Skop<span>0</span>



            </div>



          </Link>
        </div>



        



        <div className="navbar-right">

          {user && updateInfo?.update_available && (
            <button
              onClick={() => setUpdateModalOpen(true)}
              style={{
                background: 'linear-gradient(135deg, rgba(45, 212, 191, 0.2), rgba(14, 165, 233, 0.2))',
                border: '1px solid rgba(45, 212, 191, 0.6)',
                color: '#2dd4bf',
                padding: '5px 12px',
                borderRadius: '20px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                boxShadow: '0 0 12px rgba(45, 212, 191, 0.25)'
              }}
              title="Hay una nueva versión de Skop0 lista para instalar"
            >
              <Rocket size={14} color="#2dd4bf" />
              <span>Actualizar a v{updateInfo.latest_version}</span>
            </button>
          )}

          {user && (
            <button
              onClick={() => {
                navigate("/");
                setTimeout(() => {
                  window.dispatchEvent(new CustomEvent("secscan:start-tour"));
                }, 120);
              }}
              style={{
                background: 'rgba(14, 165, 233, 0.1)',
                border: '1px solid rgba(14, 165, 233, 0.35)',
                color: '#38bdf8',
                padding: '5px 11px',
                borderRadius: '20px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                transition: 'all 0.15s ease'
              }}
              title="Iniciar recorrido guiado por los apartados de Skop0"
            >
              <span>❓</span>
              <span>Tutorial</span>
            </button>
          )}

          {user && (
            <button
              onClick={() => setSubModalOpen(true)}
              style={{
                background: 'rgba(234, 179, 8, 0.12)',
                border: '1px solid rgba(234, 179, 8, 0.4)',
                color: '#facc15',
                padding: '5px 12px',
                borderRadius: '20px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                transition: 'transform 0.15s ease, background 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease',
                boxShadow: '0 1px 3px rgba(0, 0, 0, 0.25)'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(234, 179, 8, 0.2)';
                e.currentTarget.style.borderColor = 'rgba(234, 179, 8, 0.6)';
                e.currentTarget.style.transform = 'translateY(-1.5px)';
                e.currentTarget.style.boxShadow = '0 3px 8px rgba(0, 0, 0, 0.35)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(234, 179, 8, 0.12)';
                e.currentTarget.style.borderColor = 'rgba(234, 179, 8, 0.4)';
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.25)';
              }}
              onMouseDown={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = '0 1px 2px rgba(0, 0, 0, 0.2)';
              }}
              title="Estado de cuenta y suscripción (Clic para ver detalles)"
            >
              {subscription?.status === 'expired' ? (
                <AlertTriangle size={14} color="#facc15" />
              ) : (
                <Crown size={14} color="#facc15" />
              )}
              <span>
                {subscription?.status === 'expired'
                  ? 'Licencia Vencida'
                  : subscription?.status === 'inactive'
                    ? 'Licencia Inactiva'
                    : `${(subscription?.plan || 'PRO').toUpperCase()} (${subscription?.days_remaining ?? 0}d)`}
              </span>
            </button>
          )}



          {scanEngine.scanning && (

            <div 

              className="navbar-status scanning"

              title="Auditoría activa en segundo plano. Haz clic para ver el árbol / burbujas"

              style={{ cursor: scanEngine.scanId ? 'pointer' : 'default' }}

              onClick={() => {

                if (scanEngine.scanId) {

                  navigate(`/history/${scanEngine.scanId}`, { state: { defaultView: 'arbol' } });

                }

              }}

            >

              <div className="navbar-status-dot pulse-green" />

              Auditando ({scanEngine.devicesFound || 0} disp.)

            </div>

          )}



        </div>



      </nav>



      {user && (



        <>



          <div 



            className={`sidebar-overlay ${sidebarOpen ? 'active' : ''}`} 



            onClick={() => setSidebarOpen(false)}



          />



          



          <div className={`sidebar-panel ${sidebarOpen ? 'active' : ''}`}>



            <div className="sidebar-header">



              <div className="sidebar-logo">



                <div className="sidebar-logo-icon">
                  <Skop0Logo size={30} />
                </div>



                <div className="sidebar-logo-text">Skop<span>0</span></div>



              </div>



              <button 



                className="sidebar-close-btn" 



                onClick={() => setSidebarOpen(false)}



                aria-label="Cerrar menú"



              >



                &times;



              </button>



            </div>



            <div className="sidebar-profile-card">



              <div className="sidebar-avatar-wrapper">



                <img 



                  src={user.photoURL || "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y"} 



                  alt={user.displayName} 



                  className="sidebar-avatar" 



                  referrerPolicy="no-referrer"



                />



                <span className="sidebar-status-badge"></span>



              </div>



              



              <div className="sidebar-user-details">



                <h3 className="sidebar-user-name">{user.displayName}</h3>



                <span className="sidebar-user-email">{user.email || "Usuario Invitado"}</span>



                <span className="sidebar-user-role"><Shield size={16} className="inline-icon" />  Auditor de Redes</span>



              </div>



            </div>

            {/* Tarjeta de Estado de Cuenta en la Barra Lateral */}
            <div 
              className="sidebar-subscription-card"
              onClick={() => {
                setSidebarOpen(false);
                setSubModalOpen(true);
              }}
              style={{
                margin: '12px 16px',
                padding: '12px 14px',
                borderRadius: '12px',
                background: subscription?.status === 'expired' 
                  ? 'rgba(239, 68, 68, 0.08)' 
                  : subscription?.status === 'inactive'
                    ? 'rgba(245, 158, 11, 0.08)'
                    : 'rgba(0, 242, 254, 0.06)',
                border: `1px solid ${
                  subscription?.status === 'expired' 
                    ? 'rgba(239, 68, 68, 0.3)' 
                    : subscription?.status === 'inactive'
                      ? 'rgba(245, 158, 11, 0.3)'
                      : 'rgba(0, 242, 254, 0.25)'
                }`,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                transition: 'all 0.2s ease'
              }}
              title="Haz clic para ver o gestionar tu estado de cuenta"
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {subscription?.status === 'expired' ? (
                    <AlertTriangle size={15} color="#f87171" />
                  ) : (
                    <Crown size={15} color={subscription?.plan === 'enterprise' ? '#c084fc' : '#38bdf8'} />
                  )}
                  <span style={{ 
                    fontSize: '12px', 
                    fontWeight: 700, 
                    color: subscription?.status === 'expired' 
                      ? '#f87171' 
                      : subscription?.status === 'inactive'
                        ? '#fbbf24'
                        : '#38bdf8' 
                  }}>
                    {subscription?.status === 'expired' 
                      ? 'Licencia Vencida' 
                      : subscription?.status === 'inactive'
                        ? 'Sin Licencia Activa'
                        : `Licencia ${(subscription?.plan || 'PRO').toUpperCase()}`}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '3px' }}>
                  {subscription?.status === 'expired' 
                    ? 'Haz clic para renovar' 
                    : subscription?.status === 'inactive'
                      ? 'Pendiente de activación'
                      : `${subscription?.days_remaining ?? 0} días restantes (${subscription?.formatted_date || 'Activo'})`}
                </div>
              </div>
              <span style={{ fontSize: '11px', color: '#38bdf8', fontWeight: 600, padding: '2px 8px', background: 'rgba(0, 242, 254, 0.1)', borderRadius: '6px' }}>
                Ver
              </span>
            </div>




            <div className="sidebar-menu">



              <div className="sidebar-menu-section-title">Navegación</div>



              <Link to="/" className="sidebar-menu-item" onClick={() => setSidebarOpen(false)}>



                <HomeIcon size={18} className="inline-icon" />  Inicio Dashboard



              </Link>



              <Link to="/history" className="sidebar-menu-item" onClick={() => setSidebarOpen(false)}>



                <BarChart size={18} className="inline-icon" />  Historial de Auditorías



              </Link>



              <div className="sidebar-menu-section-title" style={{ marginTop: '12px' }}>Datos & Sistema</div>

              <button 
                className="sidebar-menu-item" 
                onClick={() => {
                  setSidebarOpen(false);
                  setSubModalOpen(true);
                }}
                style={{ background: 'transparent', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit', font: 'inherit', display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <Crown size={18} className="inline-icon" /> Estado de Cuenta / Licencia
              </button>




              <button 



                className="sidebar-menu-item" 



                onClick={() => {



                  setSidebarOpen(false);



                  setBackupModalOpen(true);



                }}



                style={{ background: 'transparent', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit', font: 'inherit', display: 'flex', alignItems: 'center', gap: '8px' }}



              >



                <HardDrive size={18} className="inline-icon" /> Copia de Seguridad



              </button>

              <button 
                className="sidebar-menu-item" 
                onClick={() => {
                  setSidebarOpen(false);
                  setUpdateModalOpen(true);
                  handleCheckUpdate(false);
                }}
                style={{ background: 'transparent', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit', font: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <RefreshCw size={18} className="inline-icon" /> Buscar Actualizaciones
                </span>
                {updateInfo?.update_available ? (
                  <span style={{ background: '#2dd4bf', color: '#06080f', fontSize: '10px', fontWeight: 800, padding: '2px 6px', borderRadius: '99px' }}>
                    v{updateInfo.latest_version}
                  </span>
                ) : (
                  <span style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>
                    v{updateInfo?.current_version || "1.3.0"}
                  </span>
                )}
              </button>

              <button 
                className="sidebar-menu-item" 
                onClick={() => {
                  setSidebarOpen(false);
                  navigate("/");
                  setTimeout(() => {
                    window.dispatchEvent(new CustomEvent("secscan:start-tour"));
                  }, 150);
                }}
                style={{ background: 'transparent', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit', font: 'inherit', display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <span style={{ fontSize: '16px', width: '18px', textAlign: 'center' }}>❓</span> Tutorial Interactivo
              </button>

              <button 
                className="sidebar-menu-item" 
                onClick={() => {
                  setSidebarOpen(false);
                  setAppearanceModalOpen(true);
                }}
                style={{ background: 'transparent', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'inherit', font: 'inherit', display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <span style={{ fontSize: '16px', width: '18px', textAlign: 'center' }}>🎨</span> Apariencia y Diseño
              </button>



            </div>



            <div className="sidebar-footer">



              <button 



                className="sidebar-logout-btn" 



                onClick={() => {



                  setSidebarOpen(false);



                  logout();



                }}



              >



                <LogOut size={18} className="inline-icon" />  Cerrar Sesión



              </button>



              



            </div>



          </div>



        </>



      )}



      {/* Bottom-left permanent branding */}



      <div 



        style={{



          position: 'fixed',



          bottom: '12px',



          left: '16px',



          zIndex: 90,



          fontSize: '11px',



          fontWeight: '600',



          color: '#94a3b8',



          background: 'rgba(15, 23, 42, 0.85)',



          backdropFilter: 'blur(6px)',



          padding: '4px 10px',



          borderRadius: '16px',



          border: '1px solid rgba(56, 189, 248, 0.25)',



          boxShadow: '0 2px 8px rgba(0,0,0,0.4)',



          pointerEvents: 'none',



          display: 'flex',



          alignItems: 'center',



          gap: '5px',



          userSelect: 'none'



        }}



      >



        <span style={{ opacity: 0.7 }}>by</span>



        <span style={{ color: '#38bdf8', fontWeight: '700', letterSpacing: '0.4px' }}>NoneIT</span> <span style={{ opacity: 0.6, fontSize: '10px', color: '#94a3b8' }}>v{updateInfo?.current_version || '1.3.0'}</span>



      </div>



      <BackupModal



        isOpen={backupModalOpen}



        onClose={() => setBackupModalOpen(false)}



        token={authToken}



        onRestoreSuccess={() => {



          window.location.reload();



        }}



      />

      <SubscriptionModal
        isOpen={subModalOpen}
        onClose={() => setSubModalOpen(false)}
        subscription={subscription}
        token={authToken}
        onRefreshed={() => {
          if (refreshSubscription) refreshSubscription();
        }}
      />

      <UpdateModal
        isOpen={updateModalOpen}
        onClose={() => setUpdateModalOpen(false)}
        updateInfo={updateInfo}
        onRefreshCheck={() => handleCheckUpdate(false)}
        checkingUpdate={checkingUpdate}
        token={authToken}
      />

      <AppearanceModal
        isOpen={appearanceModalOpen && !updateModalOpen}
        onClose={handleCloseAppearance}
        currentTheme={currentTheme}
        onSelectTheme={handleSelectTheme}
        currentLayout={currentLayout}
        onSelectLayout={handleSelectLayout}
        isFirstRun={appearanceFirstRun}
      />




    </>



  );



}



/* ========== GLOBAL LIVE SCAN BANNER (VISUAL EN TODAS LAS PÁGINAS) ========== */



function GlobalScanBanner() {

  const { scanning, scanId, scanMsg, devicesFound, totalTargets, target } = useScanEngine();
  const { getToken } = useAuth();
  const [cancelling, setCancelling] = useState(false);

  const navigate = useNavigate();

  const location = useLocation();

  useEffect(() => {
    if (!scanning) setCancelling(false);
  }, [scanning]);

  if (!scanning) return null;

  const isAlreadyOnTree = location.pathname === `/history/${scanId}`;

  const isAlreadyOnHome = location.pathname === "/";

  const handleStopScan = async () => {
    if (cancelling) return;
    setCancelling(true);
    try {
      const token = await getToken();
      await cancelScan(scanId || "current", token);
      scanEngineState.scanMsg = "Deteniendo auditoría...";
      notifyScanListeners();
    } catch (err) {
      console.error("Error cancelando auditoría:", err);
      setCancelling(false);
    }
  };



  return (



    <div className="global-scan-banner slide-up">



      <div className="global-scan-banner-left">



        <div className="global-scan-pulse" />



        <div className="global-scan-info">



          <span className="global-scan-title">



            ⚡ Auditoría en Curso {target && target !== "auto" ? `(${target})` : ""}:



          </span>



          <span className="global-scan-status">



            {scanMsg || "Procesando red..."}



          </span>



          {devicesFound > 0 && (



            <span className="global-scan-counter">



              🟢 <strong>{devicesFound}</strong> {totalTargets > 0 ? `/ ${totalTargets}` : ""} dispositivos detectados



            </span>



          )}



        </div>



      </div>



      <div className="global-scan-banner-actions">

        <button
          type="button"
          className="global-scan-btn"
          disabled={cancelling}
          onClick={handleStopScan}
          style={{
            background: "rgba(239, 68, 68, 0.14)",
            border: "1px solid rgba(239, 68, 68, 0.45)",
            color: "#fca5a5",
            cursor: cancelling ? "wait" : "pointer",
          }}
          title="Detener la auditoría en curso de forma inmediata"
        >
          {cancelling ? "Deteniendo..." : "Detener"}
        </button>

        {!isAlreadyOnTree && scanId && (



          <button



            className="global-scan-btn tree-btn"



            onClick={() => navigate(`/history/${scanId}`, { state: { defaultView: "arbol" } })}



          >



            🌳 Ver Burbujas en Vivo



          </button>



        )}



        {!isAlreadyOnHome && (



          <button



            className="global-scan-btn home-btn"



            onClick={() => navigate("/")}



          >



            🏠 Volver al Inicio



          </button>



        )}



      </div>



    </div>



  );



}




function validateTarget(target) {
  if (!target || target.toLowerCase() === "auto") {
    return { valid: true, normalized: "auto", isSubnet: true };
  }
  
  const clean = target.trim();
  
  if (clean.includes("/")) {
    const parts = clean.split("/");
    if (parts.length !== 2) {
      return { valid: false, error: "Formato CIDR inválido. Usa formato IP/máscara (ej: 192.168.1.0/24)." };
    }
    const ipPart = parts[0].trim();
    const mask = parseInt(parts[1].trim(), 10);
    
    if (isNaN(mask) || mask < 20 || mask > 32) {
      return { valid: false, error: `La máscara /${parts[1].trim()} no está permitida. El rango debe estar entre /20 y /32 (ej: /24 para 254 hosts). Un prefijo menor a /20 contiene demasiadas direcciones (ej: /15 tiene más de 131.000 IPs).` };
      return { valid: false, error: `La máscara de subred /${parts[1].trim()} no es válida. En redes IPv4 el prefijo debe estar entre /8 y /32 (ej: /24 para 254 hosts).` };
    }
    
    const octets = ipPart.split(".");
    if (octets.length !== 4) {
      return { valid: false, error: "La dirección IP debe tener 4 octetos numéricos (ej: 192.168.1.0)." };
    }
    for (const oct of octets) {
      const num = parseInt(oct, 10);
      if (isNaN(num) || num < 0 || num > 255 || oct !== num.toString()) {
        return { valid: false, error: `Octeto inválido '${oct}'. Debe ser un número entero entre 0 y 255.` };
      }
    }
    
    return { valid: true, normalized: `${ipPart}/${mask}`, isSubnet: mask < 32 };
  }
  
  const octets = clean.split(".");
  if (octets.length !== 4) {
    return { valid: false, error: "La dirección IP debe tener 4 octetos separados por puntos (ej: 192.168.1.50)." };
  }
  for (const oct of octets) {
    const num = parseInt(oct, 10);
    if (isNaN(num) || num < 0 || num > 255 || oct !== num.toString()) {
      return { valid: false, error: `Octeto inválido '${oct}'. Debe ser un número entero entre 0 y 255.` };
    }
  }
  
  if (clean.endsWith(".0")) {
    return { valid: true, normalized: `${clean}/24`, isSubnet: true };
  }
  
  return { valid: true, normalized: clean, isSubnet: false };
}


/* ========== HOME (BENTO GRID DESIGN) ========== */



function Home() {



  const navigate = useNavigate();
  const { getToken } = useAuth();



  const scanEngine = useScanEngine();



  const scanning = scanEngine.scanning;



  const bgTaskActive = scanEngine.scanning;



  const scanMsg = scanEngine.scanMsg;



  const devicesFound = scanEngine.devicesFound;



  const consoleLogs = scanEngine.consoleLogs;



  const [showRangeModal, setShowRangeModal] = useState(false);



  const [rangeIp, setRangeIp] = useState("");
  const [bridgeInfo, setBridgeInfo] = useState(null);
  const [activeBridge, setActiveBridge] = useState(null);
  const [bridgeLoading, setBridgeLoading] = useState(false);



  const [nmapMissing, setNmapMissing] = useState(false);



  const [installingNmap, setInstallingNmap] = useState(false);



  const [isPassive, setIsPassive] = useState(false);



  const [terminalExpanded, setTerminalExpanded] = useState(false);



  const [targetType, setTargetType] = useState("auto"); // "auto" | "custom"



  const [customTarget, setCustomTarget] = useState("");
  const [networkInterfaces, setNetworkInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("all");
  const [loadingIfaces, setLoadingIfaces] = useState(false);
  const [tourOpen, setTourOpen] = useState(false);
  const [homeLayout, setHomeLayout] = useState(() => {
    try { return localStorage.getItem("secscan_layout") || "original"; } catch (e) { return "original"; }
  });
  const [ccTab, setCcTab] = useState("auto"); // "auto" | "target"

  useEffect(() => {
    const onLayoutChange = (e) => {
      if (e && e.detail) setHomeLayout(e.detail);
    };
    window.addEventListener("secscan:layout-changed", onLayoutChange);
    return () => window.removeEventListener("secscan:layout-changed", onLayoutChange);
  }, []);

  const handleCloseTour = useCallback(() => {
    setTourOpen(false);
    try {
      localStorage.setItem("secscan_tour_completed_v1", "true");
    } catch (e) {}
  }, []);

  useEffect(() => {
    try {
      const configured = localStorage.getItem("secscan_appearance_configured_v1");
      const seen = localStorage.getItem("secscan_tour_completed_v1");
      if (configured && !seen) {
        const t = setTimeout(() => setTourOpen(true), 600);
        return () => clearTimeout(t);
      }
    } catch (e) {}
  }, []);

  useEffect(() => {
    const onStartTour = () => setTourOpen(true);
    window.addEventListener("secscan:start-tour", onStartTour);
    return () => window.removeEventListener("secscan:start-tour", onStartTour);
  }, []);

  const loadInterfaces = useCallback(async () => {
    setLoadingIfaces(true);
    try {
      const token = getToken ? await getToken() : null;
      const res = await getNetworkInterfaces(token);
      if (res && Array.isArray(res.interfaces)) {
        setNetworkInterfaces(res.interfaces);
      }
    } catch (err) {
      console.warn("Error cargando interfaces de red:", err);
    } finally {
      setLoadingIfaces(false);
    }
  }, [getToken]);

  useEffect(() => {
    loadInterfaces();
  }, [loadInterfaces]);



  const [switcherTab, setSwitcherTab] = useState("history"); // "history" | "wifi"



  const [wifiNetworks, setWifiNetworks] = useState([]);



  const [scanningWifi, setScanningWifi] = useState(false);



  const [selectedWifi, setSelectedWifi] = useState(null);



  const [wifiPassword, setWifiPassword] = useState("");



  const [connectingWifi, setConnectingWifi] = useState(false);



  const [historyList, setHistoryList] = useState([]);



  const [selectedNetwork, setSelectedNetwork] = useState(null);



  const [deleteTarget, setDeleteTarget] = useState(null);



  const [deletingTarget, setDeletingTarget] = useState(false);



  useEffect(() => {



    const el = document.getElementById("console-logs-container");



    if (el) {
      requestAnimationFrame(() => {
        el.scrollTop = el.scrollHeight;
      });
    }



  }, [consoleLogs.length]);



  useEffect(() => {



    const checkEngine = async () => {



      try {



        const token = await getToken();



        if (token) {



          const h = await checkHealth(token);



          if (h && h.nmap_installed === false) {



            setNmapMissing(true);



          }



        }



      } catch (err) {



        console.warn("Nmap engine check warn:", err);



      }



    };



    checkEngine();



  }, [getToken]);



  
  useEffect(() => {
    const fetchInitialBridge = async () => {
      try {
        const token = await getToken();
        const res = await getSubnetBridgeStatus("", token);
        if (res && res.active_bridge) {
          setActiveBridge(res.active_bridge);
        }
      } catch (e) {}
    };
    fetchInitialBridge();
  }, [getToken]);

  useEffect(() => {
    const clean = rangeIp.trim();
    if (!clean || clean.length < 7 || !clean.includes(".")) {
      setBridgeInfo(null);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const token = await getToken();
        const res = await getSubnetBridgeStatus(clean, token, selectedInterface);
        if (res && res.requires_bridge) {
          setBridgeInfo(res);
        } else {
          setBridgeInfo(null);
        }
        if (res && res.active_bridge) {
          setActiveBridge(res.active_bridge);
        }
      } catch (e) {}
    }, 350);
    return () => clearTimeout(timer);
  }, [rangeIp, getToken, selectedInterface]);


  const handleScanWifi = async () => {



    setScanningWifi(true);



    try {



      const token = await getToken();



      const res = await getWifiNetworks(token);



      if (res.status === "ok") {



        setWifiNetworks(res.networks);



      } else {



        console.error("Error al escanear WiFi:", res.detail);



      }



    } catch (e) {



      console.error("Error cargando WiFi", e);



    }



    setScanningWifi(false);



  };



  const handleConnectWifi = async () => {



    if (!selectedWifi) return;



    setConnectingWifi(true);



    try {



      const token = await getToken();



      const res = await connectWifi(selectedWifi.ssid, wifiPassword, token);



      if (res.status === "ok") {



        const newLog = `[OK] Conectando a '${selectedWifi.ssid}'... La red cambiará en unos segundos.`;



        scanEngineState.consoleLogs.push(newLog);



        notifyScanListeners();



        setSelectedWifi(null);



        setWifiPassword("");



      } else {



        const errLog = `[ERR] Error al conectar: ${res.detail}`;



        scanEngineState.consoleLogs.push(errLog);



        notifyScanListeners();



      }



    } catch (e) {



      const critLog = "[ERR] Error crítico conectando a la red WiFi.";



      scanEngineState.consoleLogs.push(critLog);



      notifyScanListeners();



    }



    setConnectingWifi(false);



  };



  useEffect(() => {



    if (switcherTab === "wifi") {



      handleScanWifi();



    }



  }, [switcherTab]);



  useEffect(() => {



    const fetchHistory = async () => {



      try {



        const token = await getToken();



        const data = await getScanHistory(token);



        if (data.status === "ok" && data.scans) {



          const sorted = [...data.scans].sort((a, b) => new Date(b.timestamp || b.created_at) - new Date(a.timestamp || a.created_at));



          setHistoryList(sorted);



          if (sorted.length > 0 && sorted[0].status === "processing" && !scanEngineState.scanning) {



            resumeScan(sorted[0].scan_id || sorted[0].id, sorted[0].target_ip || "auto", getToken);



          }



        }



      } catch (e) {



        console.error("Error al cargar historial", e);



      }



    };



    fetchHistory();



  }, [getToken]);



  const [customNetNames, setCustomNetNames] = useState(() => {



    try {



      return JSON.parse(localStorage.getItem("secscan_network_names") || "{}");



    } catch {



      return {};



    }



  });



  const handleRenameNetwork = (originalKey, currentDisplayName) => {



    const newName = prompt("Ingresa el nombre para esta red (ej: Red Martín, Red Luis, Red Oficina):", currentDisplayName);



    if (newName && newName.trim()) {



      const updated = { ...customNetNames, [originalKey]: newName.trim() };



      setCustomNetNames(updated);



      localStorage.setItem("secscan_network_names", JSON.stringify(updated));



    }



  };



  const handleConfirmDeleteTarget = async () => {



    if (!deleteTarget) return;



    setDeletingTarget(true);



    try {



      const token = await getToken();



      if (deleteTarget.type === 'single') {



        const res = await deleteScan(deleteTarget.scanId, token);



        if (res.status === "ok") {



          setHistoryList((prev) => prev.filter((s) => (s.scan_id || s.id) !== deleteTarget.scanId));



          setDeleteTarget(null);



        } else {



          alert("Error al eliminar auditoría: " + (res.detail || res.message || "Error desconocido"));



        }



      } else if (deleteTarget.type === 'network') {



        const res = await deleteBatchScans(deleteTarget.scanIds, token);



        if (res.status === "ok") {



          const idSet = new Set(deleteTarget.scanIds);



          setHistoryList((prev) => prev.filter((s) => !idSet.has(s.scan_id || s.id)));



          setSelectedNetwork(null);



          setDeleteTarget(null);



        } else {



          alert("Error al eliminar auditorías: " + (res.detail || res.message || "Error desconocido"));



        }



      }



    } catch (e) {



      console.error(e);



      alert("Error de conexión al eliminar auditorías.");



    } finally {



      setDeletingTarget(false);



    }



  };



  const groupedNetworks = useMemo(() => {



    const groups = {};



    (historyList || []).forEach(scan => {



      let rawKey = scan.network_name || scan.target_ip || scan.ip || "";



      if (!rawKey || rawKey.toLowerCase() === "auto") {



        rawKey = "Red Local";



      }



      



      let displayName = customNetNames[rawKey] || customNetNames[scan.target_ip] || scan.network_name;



      if (!displayName || displayName.toLowerCase() === "auto") {



        if (rawKey.startsWith("192.") || rawKey.startsWith("10.") || rawKey.startsWith("172.")) {



          displayName = `Red ${rawKey}`;



        } else {



          displayName = rawKey.startsWith("Red") ? rawKey : `Red ${rawKey}`;



        }



      }



      if (!groups[rawKey]) {



        groups[rawKey] = {



          key: rawKey,



          name: displayName,



          scans: []



        };



      }



      groups[rawKey].scans.push(scan);



    });



    return Object.values(groups);



  }, [historyList, customNetNames]);



  const handleFullScan = async (passiveScan = false, targetOverride = null) => {



    if (scanEngineState.scanning) {



      alert("Ya hay un escaneo en progreso. Por favor, espera a que termine.");



      return;



    }



    const targetRaw = targetOverride ? targetOverride.trim() : (targetType === "auto" ? "auto" : customTarget.trim());
    let target = targetRaw;
    if (target !== "auto") {
      const val = validateTarget(target);
      if (!val.valid) {
        alert(`⚠️ ${val.error}`);
        return;
      }
      target = val.normalized;
    }



    if (!targetOverride && targetType === "custom" && !target) {



      alert("Por favor, ingresa un rango de red o dirección IP válida.");



      return;



    }



    if (!passiveScan) {



      try {



        const token = await getToken();



        const health = await checkHealth(token);



        if (health && health.nmap_installed === false) {



          setNmapMissing(true);



          return;



        }



      } catch (e) {



        console.warn("Health check error:", e);



      }



    }



    const scanId = (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") ? crypto.randomUUID() : (`${Date.now()}-${Math.random().toString(36).substring(2, 9)}`);



    scanEngineState.scanning = true;



    scanEngineState.scanId = scanId;



    scanEngineState.target = target;



    scanEngineState.devicesFound = 0;



    scanEngineState.totalTargets = 0;



    scanEngineState.scanMsg = passiveScan ? "Inicializando escaneo pasivo indetectable..." : `Conectando con el motor de escaneo activo en ${target}...`;



    scanEngineState.consoleLogs = [`[SYS] Skop0 Daemon - Conectando con el motor backend para auditar ${target}...`];



    notifyScanListeners();



    try {



      const token = await getToken();



      const scanResult = await triggerN8nScan(target, token, scanId, passiveScan, selectedInterface);



      



      if (!passiveScan) {
        scanEngineState.consoleLogs = [
          "[SYS] Motor Nativo Skop0 conectado exitosamente.",
          `Iniciando auditoría de red (Pasivo: ${passiveScan}) en ${target}...`
        ];
      }
      if (passiveScan) {
        scanEngineState.scanMsg = "[SEC] Modo Pasivo (ARP Caché) — Leyendo memoria local...";
      } else {
        scanEngineState.scanMsg = `Escaneando red en ${target}. Esperando resultados...`;
      }



      notifyScanListeners();



      if (scanEngineState.pollInterval) {



        clearInterval(scanEngineState.pollInterval);



      }



      let polls = 0;



      const maxPolls = 150;



      scanEngineState.pollInterval = setInterval(async () => {



        polls++;



        try {



          const currentToken = await getToken();



          const res = await getScanDetails(scanId, currentToken);



          if (res.status === "ok" && res.details) {



            const { devices_found = 0, total_targets = 1, status, logs = [] } = res.details;



            



            if (logs.length > 0) {



              scanEngineState.consoleLogs = logs;



            }



            



            scanEngineState.devicesFound = devices_found;



            scanEngineState.totalTargets = total_targets;



            



            if (!passiveScan && status !== "completed" && status !== "cancelled" && status !== "error") {

              scanEngineState.scanMsg = `Auditando puertos... (${devices_found} / ${total_targets || '?'}) dispositivos listos`;

            }

            notifyScanListeners();

            if (status === "completed" || status === "cancelled" || status === "error") {

              clearInterval(scanEngineState.pollInterval);

              scanEngineState.pollInterval = null;

              scanEngineState.scanning = false;

              if (status === "cancelled") {
                scanEngineState.scanMsg = "Auditoría detenida por el usuario.";
              }

              notifyScanListeners();

              if (status === "completed" && window.location.pathname === "/") {

                setTimeout(() => {

                  navigate(`/history/${scanId}`, { state: { defaultView: "arbol" } });

                }, 1000); // Pequeño delay para ver el último log de éxito



              }



            }



          }



          if (polls >= maxPolls) {



            clearInterval(scanEngineState.pollInterval);



            scanEngineState.pollInterval = null;



            scanEngineState.scanning = false;



            notifyScanListeners();



            if (window.location.pathname === "/") {



              navigate(`/history/${scanId}`, { state: { defaultView: "arbol" } });



            }



          }



        } catch (e) {



           console.error("Error polling", e);



        }



      }, 1500); // Polling más rápido (1.5s) para sensación de tiempo real



    } catch (err) {



      scanEngineState.scanning = false;



      if (scanEngineState.pollInterval) {



        clearInterval(scanEngineState.pollInterval);



        scanEngineState.pollInterval = null;



      }



      notifyScanListeners();



      if (err.code === "SIN_INTERNET") {



        alert("⚠️ Sin conexión a internet. El escaneo requiere conexión activa para registrar los resultados en la nube. Por favor, verifica tu red e inténtalo de nuevo.");



      } else {



        if (err.code === "LICENCIA_EXPIRADA" || err.message?.includes("licencia") || err.message?.includes("suscripción")) {
        alert(`⚠️ ${err.message || "Tu suscripción ha vencido. Por favor, solicita la activación o renovación con el administrador."}`);
      } else if (err.message && err.message !== "Failed to fetch") {
        alert(`⚠️ ${err.message}`);
      } else {
        alert("Error de conexión. ¿El backend está encendido?");
      }



      }



    }



  };



  
  const handleBindAndScan = async () => {
    const rawTarget = rangeIp.trim();
    if (!rawTarget) return;
    const val = validateTarget(rawTarget);
    if (!val.valid) {
      alert(`⚠️ ${val.error}`);
      return;
    }
    setBridgeLoading(true);
    try {
      const token = await getToken();
      const res = await bindSubnetBridge(val.normalized, token, selectedInterface);
      if (res && res.status === "ok") {
        setActiveBridge({
          bound_ip: res.bound_ip,
          interface: res.interface,
          subnet: res.subnet
        });
        setBridgeInfo(null);
      }
    } catch (e) {
      console.warn("Error al vincular puente:", e);
    } finally {
      setBridgeLoading(false);
    }
    await handleRangeScan();
  };


  const handleRangeScan = async () => {
    const rawTarget = rangeIp.trim();
    if (!rawTarget) {
      alert("Por favor, ingresa una IP o rango de subred para auditar (ej: 192.168.1.0/24 o 192.168.1.50).");
      return;
    }

    const val = validateTarget(rawTarget);
    if (!val.valid) {
      alert(`⚠️ ${val.error}`);
      return;
    }

    const normalizedTarget = val.normalized;

    if (scanEngineState.scanning) {
      alert("Ya hay un escaneo en progreso. Por favor, espera a que termine.");
      return;
    }

    try {
      const token = await getToken();
      const health = await checkHealth(token);
      if (health && health.nmap_installed === false) {
        setShowRangeModal(false);
        setNmapMissing(true);
        return;
      }
    } catch (e) {
      console.warn("Health check error:", e);
    }

    setShowRangeModal(false);

    try {
      const token = await getToken();
      const st = await getSubnetBridgeStatus(normalizedTarget, token, selectedInterface);
      if (st && st.requires_bridge) {
        setBridgeLoading(true);
        const bRes = await bindSubnetBridge(normalizedTarget, token, selectedInterface);
        if (bRes && bRes.status === "ok") {
          setActiveBridge({
            bound_ip: bRes.bound_ip,
            interface: bRes.interface,
            subnet: bRes.subnet
          });
          setBridgeInfo(null);
        }
      }
    } catch (e) {
      console.warn("Auto bridge error:", e);
    } finally {
      setBridgeLoading(false);
    }

    if (val.isSubnet) {
      // Auditoría multi-dispositivo completa para la subred especificada
      await handleFullScan(false, normalizedTarget);
      return;
    }

    // Si es una IP individual específica, ejecutar auditoría profunda directa
    scanEngineState.scanning = true;
    scanEngineState.target = normalizedTarget;
    scanEngineState.scanMsg = `Escaneando objetivo específico: ${normalizedTarget}...`;
    scanEngineState.consoleLogs = [
      `⚙️ Skop0 Engine - Auditoría directa de host único: ${normalizedTarget}`,
      `[i] Analizando puertos y vulnerabilidades en paralelo...`
    ];
    notifyScanListeners();

    try {
      const token = await getToken();
      const data = await deepScan(normalizedTarget, token);
      scanEngineState.scanning = false;
      scanEngineState.scanMsg = "Auditoría de objetivo individual finalizada.";
      scanEngineState.consoleLogs.push(`✅ Análisis completado para ${normalizedTarget}.`);
      notifyScanListeners();

      navigate("/results", {
        state: {
          data: {
            status: "ok",
            total_dispositivos: 1,
            resultados: [data],
          },
          tipo: `IP Específica: ${normalizedTarget}`,
        },
      });
    } catch (err) {
      scanEngineState.scanning = false;
      scanEngineState.scanMsg = "Error en auditoría individual.";
      scanEngineState.consoleLogs.push(`❌ Error al escanear ${normalizedTarget}: ${err.message}`);
      notifyScanListeners();
      alert(`Error al escanear ${normalizedTarget}: ${err.message}`);
    }
  };



  const handleInstallNmap = async () => {



    setInstallingNmap(true);



    try {



      const token = await getToken();



      const resp = await installNmap(token);



      if (resp.status === "ok") {



        setNmapMissing(false);



        alert("¡Motor Nmap inyectado y habilitado correctamente!");



      } else {



        alert("Error de instalación: " + resp.mensaje);



      }



    } catch (e) {



      alert("Error crítico ejecutando el instalador.");



    }



    setInstallingNmap(false);



  };



  const renderInterfaceOptions = () => (
    <>
      <option value="all">🌐 Todas las interfaces (Automático)</option>
      {Array.isArray(networkInterfaces) && networkInterfaces.map((iface) => {
        const ipStr = iface.primary_ip || (Array.isArray(iface.ipv4) && iface.ipv4.length > 0 ? (iface.ipv4[0]?.ip || iface.ipv4[0]) : "Sin IP");
        const icon = iface.icono || (iface.tipo === "wifi" || iface.type === "wifi" ? "📶 " : "🔌 ");
        return (
          <option key={iface.name || iface.id} value={iface.name || iface.id}>
            {icon} {iface.name} — {ipStr}
          </option>
        );
      })}
    </>
  );

  const renderCommandCenter = () => (
    <div className="cc-wrapper fade-in">
      {/* Cabecera de Comando Unificada */}
      <div className="cc-hero-card" data-tour="tour-main-scan">
        <div className="cc-hero-top">
          <div>
            <div className="bento-badge main" style={{ marginBottom: "8px" }}>🛰️ CENTRO DE AUDITORÍA</div>
            <h1 className="home-title" style={{ fontSize: "28px", textAlign: "left", margin: 0 }}>
              Monitoreo de <span>Vulnerabilidades</span>
            </h1>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "4px" }}>
              Configura tu tarjeta física y elige entre escaneo automático de red o auditoría de IP/subred aislada.
            </p>
          </div>

          <div className="cc-tabs">
            <button
              type="button"
              className={`cc-tab-btn ${ccTab === "auto" ? "active" : ""}`}
              onClick={() => setCcTab("auto")}
            >
              ⚡ Red Automática
            </button>
            <button
              type="button"
              className={`cc-tab-btn ${ccTab === "target" ? "active" : ""}`}
              onClick={() => setCcTab("target")}
            >
              🎯 IP / Subred (Cámaras)
            </button>
          </div>
        </div>

        <div className="cc-action-bar">
          <div data-tour="tour-interface-selector">
            <div className="cc-field-label">
              <span><Network size={12} className="inline-icon" /> Tarjeta de Red</span>
              <button
                type="button"
                className="network-interface-refresh-btn"
                onClick={loadInterfaces}
                disabled={loadingIfaces || scanning}
              >
                <RefreshCw size={11} className={loadingIfaces ? "spin" : ""} />
                <span>{loadingIfaces ? "..." : "Refrescar"}</span>
              </button>
            </div>
            <select
              className="network-interface-select"
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={scanning || bgTaskActive}
            >
              {renderInterfaceOptions()}
            </select>
          </div>

          <div data-tour="tour-target-scan">
            <div className="cc-field-label">
              <span>{ccTab === "auto" ? "Alcance de Auditoría" : "IP Única o Rango CIDR"}</span>
            </div>
            {ccTab === "auto" ? (
              <div
                style={{
                  padding: "10px 14px",
                  borderRadius: "8px",
                  background: "var(--bg-base)",
                  border: "1px solid var(--border-base)",
                  fontSize: "13px",
                  fontFamily: "'Fira Code', monospace",
                  color: "var(--cyan-400)",
                }}
              >
                Subred local completa + Topología L2/L3 + CVEs
              </div>
            ) : (
              <input
                type="text"
                placeholder="Ej: 192.168.20.0/24 o 192.168.18.33"
                className="quick-input"
                style={{ width: "100%", padding: "9px 14px", fontSize: "13px" }}
                value={rangeIp}
                onChange={(e) => setRangeIp(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleRangeScan()}
              />
            )}
          </div>

          <div>
            <button
              className="bento-btn bento-btn-primary"
              style={{ padding: "10px 18px" }}
              onClick={() => (ccTab === "auto" ? handleFullScan(false) : handleRangeScan())}
              disabled={scanning || bgTaskActive || bridgeLoading}
            >
              {(scanning || bgTaskActive) ? (
                <>
                  <div className="bento-spinner-sm" style={{ width: "15px", height: "15px" }} />
                  Auditando...
                </>
              ) : bridgeLoading ? (
                "Vinculando..."
              ) : ccTab === "auto" ? (
                <><Rocket size={16} /> Iniciar Auditoría</>
              ) : (
                <><Crosshair size={16} /> Auditar Objetivo</>
              )}
            </button>
          </div>
        </div>

        {ccTab === "target" && bridgeInfo && bridgeInfo.requires_bridge && (
          <div style={{ padding: "10px 14px", background: "var(--purple-dim)", border: "1px solid var(--purple-border)", borderRadius: "10px", fontSize: "12px", color: "var(--text-secondary)" }}>
            <strong style={{ color: "var(--purple-400)" }}>🔌 Subred Aislada Detectada ({rangeIp}):</strong> Se enlazará automáticamente una IP secundaria en <strong>{bridgeInfo.active_interface || "tu tarjeta"}</strong> sin perder tu conexión a Internet.
          </div>
        )}

        {activeBridge && (
          <div style={{ padding: "8px 12px", background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)", borderRadius: "8px", fontSize: "12px", color: "#34d399" }}>
            🟢 Puente Activo: IP <strong>{activeBridge.bound_ip}</strong> en {activeBridge.interface} ({activeBridge.subnet})
          </div>
        )}

        {scanning && (
          <div className="scan-inline-progress fade-in">
            <div className="scan-inline-progress-left">
              <div className="bento-spinner-sm" />
              <span className="scan-inline-progress-text">{scanMsg || "Iniciando auditoría de red..."}</span>
            </div>
            {devicesFound > 0 && (
              <span className="scan-inline-progress-count">
                {devicesFound} {devicesFound === 1 ? "dispositivo" : "dispositivos"}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Grilla Inferior: Consola Grande + Wi-Fi e Historial */}
      <div className="cc-lower-grid">
        <div
          className={`bento-card bento-terminal slide-up ${terminalExpanded ? "bento-terminal-expanded" : ""}`}
          style={{ height: terminalExpanded ? undefined : "420px" }}
          data-tour="tour-terminal"
        >
          <div className="terminal-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
            <div className="bento-badge terminal-badge" style={{ marginBottom: 0 }}>⌨️ CONSOLA DE AUDITORÍA</div>
            <button
              className="terminal-expand-toggle"
              onClick={() => setTerminalExpanded(!terminalExpanded)}
              title={terminalExpanded ? "Minimizar consola" : "Expandir consola"}
              type="button"
            >
              {terminalExpanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
            </button>
          </div>
          <div className="terminal-body" id="console-logs-container">
            {consoleLogs.map((log, i) => renderTerminalLine(log, i))}
          </div>
        </div>

        <div className="cc-side-stack">
          <div className="bento-card bento-switcher slide-up" style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }} data-tour="tour-wifi">
            <div className="bento-badge switcher-badge">📡 REDES WI-FI</div>
            <h3 className="bento-card-title-sm">Redes Wi-Fi Disponibles</h3>
            <div className="network-switcher-list" style={{ overflowY: "auto", flex: 1, marginTop: "10px", display: "flex", flexDirection: "column", gap: "6px" }}>
              {scanningWifi ? (
                <div style={{ padding: "24px 10px", textAlign: "center" }}>
                  <div className="bento-spinner-sm" style={{ margin: "0 auto 10px" }} />
                  <p style={{ color: "var(--cyan-400)", fontSize: "12px" }}>Buscando redes inalámbricas...</p>
                </div>
              ) : (
                <>
                  {wifiNetworks.map((net, i) => (
                    <div key={i} className="network-switcher-item" onClick={() => setSelectedWifi(net)} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <span>📶</span>
                        <span className="network-item-name">{net.ssid}</span>
                      </div>
                      <span style={{ fontSize: "11px", color: "var(--cyan-400)", fontWeight: 700 }}>{net.signal || 0}%</span>
                    </div>
                  ))}
                  {wifiNetworks.length === 0 && (
                    <div className="network-switcher-placeholder">No se encontraron redes Wi-Fi visibles.</div>
                  )}
                  <button type="button" className="bento-btn bento-btn-secondary" style={{ padding: "8px", fontSize: "12px", marginTop: "8px" }} onClick={handleScanWifi}>
                    🔄 Escanear Redes de Nuevo
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="history-quicklink slide-up" data-tour="tour-history" onClick={() => navigate("/history")}>
            <div className="history-quicklink-text">
              <div className="history-quicklink-title"><BarChart size={18} className="inline-icon" /> Ver Auditorías Históricas</div>
              <div className="history-quicklink-desc">Mapas de red interactivos y vulnerabilidades guardadas.</div>
            </div>
            <div className="history-quicklink-arrow">→</div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderMinimalistFocus = () => (
    <div className="mf-wrapper fade-in">
      <div className="home-hero" style={{ marginBottom: "8px" }}>
        <div className="bento-badge main" style={{ margin: "0 auto 12px" }}>🛰️ SKOP0 ENGINE</div>
        <h1 className="home-title">
          ¿Qué red deseas <span>auditar hoy</span>?
        </h1>
        <p className="home-subtitle">
          Déjalo vacío para escanear tu red local completa o escribe una IP / subred CIDR (ej: 192.168.20.0/24).
        </p>
      </div>

      {/* Barra Central Estilo Spotlight */}
      <div className="mf-search-bar" data-tour="tour-main-scan">
        <select
          className="mf-iface-pill"
          data-tour="tour-interface-selector"
          value={selectedInterface}
          onChange={(e) => setSelectedInterface(e.target.value)}
          disabled={scanning || bgTaskActive}
        >
          {renderInterfaceOptions()}
        </select>

        <button
          type="button"
          className="network-interface-refresh-btn"
          style={{ padding: "10px" }}
          onClick={loadInterfaces}
          disabled={loadingIfaces || scanning}
          title="Refrescar tarjetas de red"
        >
          <RefreshCw size={14} className={loadingIfaces ? "spin" : ""} />
        </button>

        <input
          type="text"
          className="mf-target-input"
          data-tour="tour-target-scan"
          placeholder="Automático (o escribe IP / subred como 192.168.20.0/24)..."
          value={rangeIp}
          onChange={(e) => setRangeIp(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              rangeIp.trim() ? handleRangeScan() : handleFullScan(false);
            }
          }}
        />

        <button
          className="bento-btn bento-btn-primary"
          style={{ width: "auto", padding: "12px 24px", whiteSpace: "nowrap" }}
          onClick={() => (rangeIp.trim() ? handleRangeScan() : handleFullScan(false))}
          disabled={scanning || bgTaskActive || bridgeLoading}
        >
          {(scanning || bgTaskActive) ? (
            <>
              <div className="bento-spinner-sm" style={{ width: "15px", height: "15px" }} />
              Auditando...
            </>
          ) : (
            <><Rocket size={16} /> {rangeIp.trim() ? "Auditar Objetivo" : "Iniciar Auditoría"}</>
          )}
        </button>
      </div>

      {bridgeInfo && bridgeInfo.requires_bridge && (
        <div style={{ padding: "10px 16px", background: "var(--purple-dim)", border: "1px solid var(--purple-border)", borderRadius: "12px", fontSize: "12.5px", color: "var(--text-secondary)", textAlign: "center" }}>
          🔌 <strong style={{ color: "var(--purple-400)" }}>Subred Aislada ({rangeIp}):</strong> Se creará un puente automático sin desconectarte de Internet.
        </div>
      )}

      {scanning && (
        <div className="scan-inline-progress fade-in">
          <div className="scan-inline-progress-left">
            <div className="bento-spinner-sm" />
            <span className="scan-inline-progress-text">{scanMsg || "Iniciando auditoría de red..."}</span>
          </div>
          {devicesFound > 0 && (
            <span className="scan-inline-progress-count">
              {devicesFound} {devicesFound === 1 ? "dispositivo" : "dispositivos"}
            </span>
          )}
        </div>
      )}

      {/* 3 Módulos Compactos Debajo */}
      <div className="mf-cards-grid">
        <div
          className={`bento-card bento-terminal slide-up ${terminalExpanded ? "bento-terminal-expanded" : ""}`}
          style={{ height: terminalExpanded ? undefined : "300px" }}
          data-tour="tour-terminal"
        >
          <div className="terminal-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
            <div className="bento-badge terminal-badge" style={{ marginBottom: 0 }}>⌨️ CONSOLA DE AUDITORÍA</div>
            <button
              className="terminal-expand-toggle"
              onClick={() => setTerminalExpanded(!terminalExpanded)}
              type="button"
            >
              {terminalExpanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
            </button>
          </div>
          <div className="terminal-body" id="console-logs-container">
            {consoleLogs.map((log, i) => renderTerminalLine(log, i))}
          </div>
        </div>

        <div className="bento-card bento-switcher slide-up" style={{ height: "300px", overflow: "hidden", display: "flex", flexDirection: "column" }} data-tour="tour-wifi">
          <div className="bento-badge switcher-badge">📡 WI-FI</div>
          <div className="network-switcher-list" style={{ overflowY: "auto", flex: 1, marginTop: "6px", display: "flex", flexDirection: "column", gap: "6px" }}>
            {scanningWifi ? (
              <div style={{ padding: "20px", textAlign: "center", fontSize: "12px", color: "var(--cyan-400)" }}>Buscando...</div>
            ) : (
              <>
                {wifiNetworks.map((net, i) => (
                  <div key={i} className="network-switcher-item" onClick={() => setSelectedWifi(net)} style={{ display: "flex", justifyContent: "space-between", cursor: "pointer" }}>
                    <span className="network-item-name">📶 {net.ssid}</span>
                    <span style={{ fontSize: "11px", color: "var(--cyan-400)" }}>{net.signal || 0}%</span>
                  </div>
                ))}
                {wifiNetworks.length === 0 && (
                  <div className="network-switcher-placeholder">Sin redes Wi-Fi visibles.</div>
                )}
                <button type="button" className="bento-btn bento-btn-secondary" style={{ padding: "7px", fontSize: "11.5px", marginTop: "auto" }} onClick={handleScanWifi}>
                  🔄 Escanear Wi-Fi
                </button>
              </>
            )}
          </div>
        </div>

        <div
          className="bento-card slide-up"
          data-tour="tour-history"
          onClick={() => navigate("/history")}
          style={{ height: "300px", cursor: "pointer", display: "flex", flexDirection: "column", justifyContent: "space-between", borderStyle: "dashed", borderColor: "var(--purple-border)" }}
        >
          <div>
            <div className="bento-badge target-badge"><BarChart size={14} className="inline-icon" /> HISTORIAL</div>
            <h3 className="bento-card-title-sm" style={{ marginTop: "12px" }}>Mapas y Reportes</h3>
            <p className="bento-card-desc-sm" style={{ marginTop: "8px" }}>
              Explora todas tus auditorías guardadas, árboles de red interactivos y vulnerabilidades CVE detectadas.
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "13px", fontWeight: 700, color: "var(--cyan-400)", paddingTop: "12px", borderTop: "1px solid var(--border-subtle)" }}>
            <span>Abrir Historial</span>
            <span>→</span>
          </div>
        </div>
      </div>
    </div>
  );

  return (



    <div className="page-container fade-in">

      {homeLayout === "command" ? renderCommandCenter() : homeLayout === "minimal" ? renderMinimalistFocus() : (
        <>

      <div className="home-hero">



        <h1 className="home-title">



          Monitoreo de <span>Vulnerabilidades</span>



        </h1>



        <p className="home-subtitle">



          Plataforma de ciberseguridad industrial y comercial. Auditoría activa y pasiva integrada para PYMEs e IoT.



        </p>



      </div>



      <div className="bento-grid">



        



        <div className="bento-card bento-large-scan slide-up" data-tour="tour-main-scan">



          <div className="bento-badge main">🛰️ AUDITORÍA DE RED</div>



          <h2 className="bento-card-title">Lanzar Auditoría Inteligente</h2>



          <p className="bento-card-desc">



            Escanea tu subred local completa, descubre la topología y extensores intermedios en cascada y detecta puertos vulnerables expuestos.



          </p>



          <div className="network-interface-box" data-tour="tour-interface-selector">
            <div className="network-interface-header">
              <label className="network-interface-label">
                <Network size={14} className="inline-icon" /> Interfaz de Red:
              </label>
              <button
                type="button"
                className="network-interface-refresh-btn"
                onClick={loadInterfaces}
                disabled={loadingIfaces || scanning}
                title="Detectar adaptadores de red conectados"
              >
                <RefreshCw size={12} className={loadingIfaces ? "spin" : ""} />
                <span>{loadingIfaces ? "Buscando..." : "Refrescar"}</span>
              </button>
            </div>
            <div className="network-interface-select-wrapper">
              <select
                className="network-interface-select"
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                disabled={scanning || bgTaskActive}
              >
                <option value="all">🌐 Todas las interfaces (Automático)</option>
                {Array.isArray(networkInterfaces) && networkInterfaces.map((iface) => {
                  const ipStr = iface.primary_ip || (Array.isArray(iface.ipv4) && iface.ipv4.length > 0 ? (iface.ipv4[0]?.ip || iface.ipv4[0]) : "Sin IP asignada");
                  const icon = iface.icono || (iface.tipo === "wifi" || iface.type === "wifi" ? "📶 " : "🔌 ");
                  return (
                    <option key={iface.name || iface.id} value={iface.name || iface.id}>
                      {icon} {iface.name} — {ipStr}
                    </option>
                  );
                })}
              </select>
            </div>
          </div>

          <div className="scanner-controls-box">



            <button 



              className="bento-btn bento-btn-primary" 



              onClick={() => handleFullScan(false)}



              disabled={scanning || bgTaskActive}



              style={(scanning || bgTaskActive) ? { opacity: 0.65, cursor: "not-allowed", filter: "saturate(0.7)" } : {}}



            >



              {(scanning || bgTaskActive) ? (



                <>



                  <div className="bento-spinner-sm" style={{ width: '16px', height: '16px', marginRight: '8px', display: 'inline-block' }} /> 



                  Auditoría en Curso...



                </>



              ) : (



                <>



                  <Rocket size={18} className="inline-icon" style={{marginRight: '8px'}} /> Iniciar Escaneo Activo



                </>



              )}



            </button>



          </div>



          {scanning && (



            <div className="bento-status-overlay">



              <div className="bento-status-spinner-row">



                <div className="bento-spinner-sm" />



                <div>



                  <div className="bento-status-text">



                    {scanMsg}



                  </div>



                  {devicesFound > 0 && (



                    <div style={{ fontSize: "12px", color: "var(--accent-green)", marginTop: "4px" }}>



                      🟢 {devicesFound} dispositivos detectados



                    </div>



                  )}



                </div>



              </div>



            </div>



          )}



        </div>



        <div className={`bento-card bento-terminal slide-up ${terminalExpanded ? "bento-terminal-expanded" : ""}`} style={{ animationDelay: "0.05s" }} data-tour="tour-terminal">



          <div className="terminal-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
            <div className="bento-badge terminal-badge" style={{ marginBottom: 0 }}>⌨️ CONSOLA DE AUDITORÍA</div>
            <button



              className="terminal-expand-toggle"



              onClick={() => setTerminalExpanded(!terminalExpanded)}



              title={terminalExpanded ? "Minimizar consola" : "Expandir consola a pantalla completa"}



              type="button"



            >



              {terminalExpanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}



            </button>
          </div>



          <div className="terminal-body" id="console-logs-container">



            {consoleLogs.map((log, i) => renderTerminalLine(log, i))}
          </div>



        </div>



        <div className="bento-card bento-switcher slide-up" style={{ animationDelay: "0.1s", overflow: "hidden", display: "flex", flexDirection: "column" }} data-tour="tour-wifi">
          <div className="bento-badge switcher-badge">📡 REDES WI-FI</div>
          <h3 className="bento-card-title-sm">Redes Wi-Fi Disponibles</h3>
          <p className="bento-card-desc-sm">
            Detecta y conéctate a las redes inalámbricas disponibles en el entorno de esta máquina auditora.
          </p>

          <div className="network-switcher-list" style={{ overflowY: "auto", flex: 1, marginTop: "12px", display: "flex", flexDirection: "column", gap: "6px" }}>
            {scanningWifi ? (
              <div style={{ padding: "30px 10px", textAlign: "center" }}>
                <div className="bento-spinner-sm" style={{ margin: "0 auto 12px" }} />
                <p style={{ color: "var(--cyan-400)", fontSize: "12px" }}>Buscando redes inalámbricas...</p>
              </div>
            ) : (
              <>
                {wifiNetworks.map((net, i) => {
                  const sig = net.signal || 0;
                  const bars = sig >= 80 ? 4 : sig >= 60 ? 3 : sig >= 40 ? 2 : sig >= 20 ? 1 : 0;
                  return (
                    <div 
                      key={i} 
                      className="network-switcher-item"
                      onClick={() => setSelectedWifi(net)}
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <span className="network-network-icon" style={{ fontSize: '20px' }}>📶</span>
                        <span className="network-item-name">{net.ssid}</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: '16px', marginRight: '4px' }}>
                        {[1,2,3,4].map(b => (
                          <div key={b} style={{
                            width: '4px',
                            height: `${4 + b * 3}px`,
                            borderRadius: '1px',
                            background: b <= bars
                              ? (bars >= 4 ? 'var(--green-400)' : bars >= 3 ? 'var(--cyan-400)' : bars >= 2 ? 'var(--yellow-400)' : 'var(--accent-red)')
                              : 'rgba(255,255,255,0.12)',
                            transition: 'background 0.3s'
                          }} />
                        ))}
                      </div>
                    </div>
                  );
                })}

                {wifiNetworks.length === 0 && (
                  <div className="network-switcher-placeholder">
                    No se encontraron redes Wi-Fi visibles.
                  </div>
                )}

                <button 
                  type="button"
                  className="bento-btn bento-btn-secondary" 
                  style={{ padding: "8px", fontSize: "12px", marginTop: "12px" }}
                  onClick={handleScanWifi}
                >
                  🔄 Escanear Redes de Nuevo
                </button>
              </>
            )}
          </div>
        </div>

        <div
          className="bento-card slide-up"
          data-tour="tour-history"
          style={{
            gridArea: "history",
            animationDelay: "0.15s",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            gap: "10px",
          }}
        >
          <div>
            <div className="bento-badge passive-badge" style={{ marginBottom: "8px" }}>
              <BarChart size={14} className="inline-icon" style={{ marginRight: "4px" }} /> HISTORIAL DE AUDITORÍAS
            </div>
            <h3 className="bento-card-title-sm" style={{ marginBottom: "6px" }}>Auditorías Recientes</h3>

            {Array.isArray(historyList) && historyList.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "8px" }}>
                {historyList.slice(0, 3).map((scan, idx) => {
                  const sid = scan.scan_id || scan.id;
                  const label = scan.network_name || scan.target_ip || "Red Local";
                  const devCount = scan.devices_found ?? scan.total_dispositivos ?? scan.device_count ?? 0;
                  let dateStr = "";
                  if (scan.timestamp) {
                    try {
                      const d = new Date(scan.timestamp);
                      if (!isNaN(d.getTime())) {
                        dateStr = d.toLocaleString("es-ES", {
                          day: "2-digit",
                          month: "short",
                          hour: "2-digit",
                          minute: "2-digit",
                        });
                      }
                    } catch (e) {}
                  }
                  return (
                    <div
                      key={sid || idx}
                      onClick={() => navigate(`/history/${sid}`)}
                      className="network-switcher-item"
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        cursor: "pointer",
                        padding: "8px 12px",
                        gap: "10px",
                      }}
                    >
                      <div style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
                        <span className="network-item-name" style={{ fontSize: "12.5px", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          🗺️ {label}
                        </span>
                        {dateStr && (
                          <span style={{ fontSize: "10.5px", color: "var(--text-muted)", marginTop: "2px" }}>
                            🕒 {dateStr}
                          </span>
                        )}
                      </div>
                      <span style={{ fontSize: "11.5px", color: "var(--cyan-400)", fontWeight: 700, flexShrink: 0, whiteSpace: "nowrap" }}>
                        {devCount} dispositivos →
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="bento-card-desc-sm" style={{ marginTop: "6px" }}>
                Accede a tus mapas de topología interactivos, dispositivos detectados y vulnerabilidades CVE guardadas.
              </p>
            )}
          </div>

          <button
            type="button"
            className="bento-btn bento-btn-secondary"
            style={{ padding: "9px 14px", fontSize: "12.5px", justifyContent: "space-between" }}
            onClick={() => navigate("/history")}
          >
            <span><BarChart size={15} className="inline-icon" style={{ marginRight: "6px" }} /> Ver Historial Completo</span>
            <span>→</span>
          </button>
        </div>



        <div className="bento-card bento-target slide-up" style={{ animationDelay: "0.2s" }} data-tour="tour-target-scan">



          <div className="bento-badge target-badge"><Crosshair size={18} className="inline-icon" />  OBJETIVO ESPECÍFICO</div>



          <h3 className="bento-card-title-sm">Escanear Objetivo</h3>



          <p className="bento-card-desc-sm" style={{ marginBottom: "14px" }}>



            Audita una IP única o un rango de subred CIDR (ej: 192.168.1.1 o 192.168.1.0/24).



          </p>



          



          <div className="network-interface-box target-card-interface">
            <div className="network-interface-header">
              <label className="network-interface-label">
                <Network size={13} className="inline-icon" /> Tarjeta para este objetivo:
              </label>
            </div>
            <select
              className="network-interface-select"
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={scanning || bgTaskActive || bridgeLoading}
            >
              <option value="all">🌐 Todas / Automático</option>
              {Array.isArray(networkInterfaces) && networkInterfaces.map((iface) => {
                const ipStr = iface.primary_ip || (Array.isArray(iface.ipv4) && iface.ipv4.length > 0 ? (iface.ipv4[0]?.ip || iface.ipv4[0]) : "");
                const icon = iface.icono || (iface.tipo === "wifi" || iface.type === "wifi" ? "📶 " : "🔌 ");
                return (
                  <option key={iface.name || iface.id} value={iface.name || iface.id}>
                    {icon} {iface.name} {ipStr ? `(${ipStr})` : ""}
                  </option>
                );
              })}
            </select>
          </div>

          <div className="quick-input-group" style={(bridgeInfo?.requires_bridge || activeBridge) ? { marginTop: "12px" } : {}}>



            <input 



              type="text" 



              placeholder="Ej: 192.168.18.33 o 192.168.1.0/24"



              className="quick-input"



              value={rangeIp}



              onChange={(e) => setRangeIp(e.target.value)}



              onKeyDown={(e) => e.key === "Enter" && handleRangeScan()}



            />



            <button 



              className="quick-input-btn"



              onClick={handleRangeScan}



              disabled={scanning || bgTaskActive || bridgeLoading}



              style={(scanning || bgTaskActive || bridgeLoading) ? { opacity: 0.5, cursor: "not-allowed" } : {}}



            >



              {(scanning || bgTaskActive) ? "Ocupado" : bridgeLoading ? "Vinculando..." : "Auditar"}



            </button>



          </div>
          {bridgeInfo && bridgeInfo.requires_bridge && (
            <div style={{
              marginTop: "12px",
              padding: "10px 14px",
              background: "rgba(14, 165, 233, 0.08)",
              border: "1px solid rgba(14, 165, 233, 0.35)",
              borderRadius: "8px",
              display: "flex",
              flexDirection: "column",
              gap: "6px"
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "0.85rem", color: "#38bdf8", fontWeight: 600 }}>
                <Plug size={15} />
                <span>Subred Aislada Detectada ({rangeIp})</span>
              </div>
              <p style={{ margin: 0, fontSize: "0.78rem", color: "#94a3b8", lineHeight: "1.4" }}>
                Tu tarjeta ({bridgeInfo.active_interface || "Red"}) no está en este segmento. Al presionar <strong style={{ color: "#38bdf8" }}>Auditar</strong> se enlazará automáticamente una IP secundaria: <span style={{ color: "#38bdf8" }}>no perderás tu conexión a Internet</span> y <span style={{ color: "#cbd5e1" }}>se desvinculará automáticamente al cerrar el programa (❌)</span>.
              </p>
            </div>
          )}

          {activeBridge && (
            <div style={{
              marginTop: "10px",
              padding: "8px 12px",
              background: "rgba(16, 185, 129, 0.08)",
              border: "1px solid rgba(16, 185, 129, 0.25)",
              borderRadius: "6px",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              fontSize: "0.8rem",
              color: "#34d399"
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "#10b981", boxShadow: "0 0 8px #10b981" }}></span>
                <span>Puente Activo: IP <strong>{activeBridge.bound_ip}</strong> en {activeBridge.interface} ({activeBridge.subnet})</span>
              </div>
              <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Se retira al presionar la ❌</span>
            </div>
          )}




        </div>



      </div>



        </>
      )}

      <OnboardingTour isOpen={tourOpen} onClose={handleCloseTour} />

      {nmapMissing && (



        <div className="modal-overlay">



          <div className="modal-content" style={{ textAlign: 'center' }}>



            <div style={{ fontSize: '48px', marginBottom: '16px' }}>⚙️</div>



            <h2 style={{ color: 'var(--accent-red)' }}>Motor Nmap Ausente</h2>



            <p style={{ margin: '12px 0 24px' }}>



              Skop0 detectó que esta máquina no tiene el motor forense Nmap. 



              El instalador autónomo puede solucionarlo en 5 segundos sin tu intervención.



            </p>



            



            {installingNmap ? (



              <div style={{ padding: '20px' }}>



                <div className="scanning-spinner" style={{ margin: '0 auto 20px', width: '40px', height: '40px' }}></div>



                <p style={{ color: 'var(--accent-cyan)' }}>Descargando e inyectando binarios nativos...</p>



              </div>



            ) : (



              <div className="modal-buttons" style={{ justifyContent: 'center' }}>



                <button className="btn btn-ghost" onClick={() => setNmapMissing(false)}>Cancelar</button>



                <button className="btn btn-primary" onClick={handleInstallNmap}>



                  📥 Instalar Motor Automáticamente



                </button>



              </div>



            )}



          </div>



        </div>



      )}



      {selectedWifi && (



        <div className="modal-overlay">



          <div className="modal-content" style={{ maxWidth: "400px" }}>



            <div style={{ fontSize: "36px", marginBottom: "12px", textAlign: "center" }}>📶</div>



            <h3 style={{ color: "var(--cyan-400)", marginBottom: "10px", textAlign: "center" }}>



              Conectar a {selectedWifi.ssid}



            </h3>



            <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "16px", textAlign: "center" }}>



              Seguridad: <strong>{selectedWifi.auth}</strong> | Señal: <strong>{selectedWifi.signal}%</strong>



            </p>



            



            {selectedWifi.auth.toLowerCase().includes("open") || selectedWifi.auth.toLowerCase().includes("abierta") || selectedWifi.auth.toLowerCase().includes("none") ? (



              <p style={{ fontSize: "13px", color: "var(--green-400)", marginBottom: "20px", textAlign: "center" }}>



                Esta es una red abierta. No se requiere contraseña para conectarse.



              </p>



            ) : (



              <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "20px" }}>



                <label style={{ fontSize: "12px", color: "var(--text-secondary)", fontWeight: "600" }}>



                  Contraseña de Red



                </label>



                <input



                  type="password"



                  placeholder="Ingresa la contraseña de la red..."



                  className="quick-input"



                  value={wifiPassword}



                  onChange={(e) => setWifiPassword(e.target.value)}



                  style={{



                    background: "var(--bg-surface)",



                    border: "1px solid var(--border-base)",



                    borderRadius: "8px",



                    padding: "10px 12px",



                    color: "var(--text-primary)",



                    outline: "none"



                  }}



                  onKeyDown={(e) => e.key === "Enter" && !connectingWifi && handleConnectWifi()}



                />



              </div>



            )}



            



            {connectingWifi ? (



              <div style={{ padding: "10px", textAlign: "center" }}>



                <div className="bento-spinner-sm" style={{ margin: "0 auto 10px" }} />



                <p style={{ color: "var(--cyan-400)", fontSize: "12px" }}>Enviando credenciales y conectando...</p>



              </div>



            ) : (



              <div className="modal-buttons" style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>



                <button className="btn btn-ghost" onClick={() => { setSelectedWifi(null); setWifiPassword(""); }}>



                  Cancelar



                </button>



                <button 



                  className="btn btn-primary" 



                  onClick={handleConnectWifi}



                  disabled={!(selectedWifi.auth.toLowerCase().includes("open") || selectedWifi.auth.toLowerCase().includes("abierta") || selectedWifi.auth.toLowerCase().includes("none")) && !wifiPassword.trim()}



                >



                  <Zap size={16} className="inline-icon" style={{marginRight: '6px'}} /> Conectar



                </button>



              </div>



            )}



          </div>



        </div>



      )}



      {deleteTarget && (



        <div className="modal-overlay">



          <div className="modal-content" style={{ maxWidth: "420px", textAlign: "center" }}>



            <div style={{ fontSize: "36px", marginBottom: "12px" }}>🗑️</div>



            <h3 style={{ color: "var(--red-400)", marginBottom: "10px" }}>



              {deleteTarget.type === 'single' ? "¿Eliminar auditoría?" : `¿Eliminar ${deleteTarget.scanIds.length} auditorías?`}



            </h3>



            <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "20px" }}>



              {deleteTarget.type === 'single'



                ? `Esta acción eliminará la auditoría del ${deleteTarget.dateStr} de forma permanente.`



                : `Esta acción eliminará las ${deleteTarget.scanIds.length} auditorías registradas en ${deleteTarget.name} de forma permanente.`}



            </p>



            <div className="modal-buttons" style={{ display: "flex", gap: "10px", justifyContent: "center" }}>



              <button 



                className="btn btn-ghost" 



                onClick={() => setDeleteTarget(null)}



                disabled={deletingTarget}



              >



                Cancelar



              </button>



              <button 



                className="btn btn-primary" 



                style={{ background: "var(--red-500)", borderColor: "var(--red-500)", color: "#fff" }}



                onClick={handleConfirmDeleteTarget}



                disabled={deletingTarget}



              >



                {deletingTarget ? "Eliminando..." : "Sí, eliminar"}



              </button>



            </div>



          </div>



        </div>



      )}



    </div>



  );



}



/* ========== RESULTS (Escaneo Específico) ========== */



function Results() {



  const navigate = useNavigate();



  const locationState = window.history.state?.usr;



  if (!locationState || !locationState.data) {



    navigate("/");



    return null;



  }



  const { data, tipo } = locationState;



  const resultados = data.resultados || [];



  const allVulns = [];



  resultados.forEach((r) => {



    const detalle = r.detalle || {};



    const puertos = detalle.puertos_abiertos || [];



    puertos.forEach((p) => {



      (p.vulnerabilidades || []).forEach((v) => {



        allVulns.push({



          ...v,



          puerto: p.puerto,



          servicio: p.servicio,



          version: p.version,



          ip: detalle.ip,



        });



      });



    });



  });



  allVulns.sort((a, b) => (b.score || 0) - (a.score || 0));



  const totalDevices = data.total_dispositivos || 0;



  const totalPorts = resultados.reduce((s, r) => s + (r.puertos_encontrados || 0), 0);



  const totalVulns = allVulns.length;



  const getSeverityClass = (sev) => {



    if (!sev || sev === "No disponible") return "severity-unknown";



    return `severity-${sev.toLowerCase()}`;



  };



  const getScoreColor = (score) => {



    if (score >= 9.0) return "#ff4757"; // Crítico



    if (score >= 7.0) return "#ffa502"; // Alto



    if (score >= 4.0) return "#eccc68"; // Medio



    return "#7bed9f"; // Bajo



  };



  return (



    <div className="page-container fade-in">



      <button className="btn btn-back" onClick={() => navigate("/")}>



        ← Volver al Inicio



      </button>



      <div className="results-header">



        <h1>Resultados del Escaneo</h1>



        <p>Tipo: {tipo}</p>



      </div>



      <div className="results-summary">



        <div className="summary-card slide-up">



          <div className="summary-card-label">Dispositivos</div>



          <div className="summary-card-value cyan">{totalDevices}</div>



        </div>



        <div className="summary-card slide-up" style={{ animationDelay: "0.1s" }}>



          <div className="summary-card-label">Puertos Abiertos</div>



          <div className="summary-card-value green">{totalPorts}</div>



        </div>



        <div className="summary-card slide-up" style={{ animationDelay: "0.2s" }}>



          <div className="summary-card-label">Vulnerabilidades</div>



          <div className="summary-card-value red">{totalVulns}</div>



        </div>



      </div>




      {resultados.map((r, idx) => {
        const d = r.detalle || {};
        const devIcon = getDeviceIcon(d);
        const ports = d.puertos_abiertos || [];
        const latency = d.telemetria?.status_label || (d.telemetria?.latency_ms ? `${d.telemetria.latency_ms.toFixed(1)} ms` : null);
        const ttlVal = d.telemetria?.ttl;

        return (
          <div 
            key={idx}
            className="slide-up"
            style={{
              marginTop: "20px",
              marginBottom: "24px",
              padding: "18px 22px",
              background: "rgba(15, 23, 42, 0.75)",
              border: "1px solid rgba(56, 189, 248, 0.25)",
              borderRadius: "12px",
              backdropFilter: "blur(12px)",
              display: "flex",
              flexDirection: "column",
              gap: "14px",
              boxShadow: "0 4px 20px rgba(0, 0, 0, 0.3)"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                <div style={{
                  width: "52px",
                  height: "52px",
                  borderRadius: "12px",
                  background: "radial-gradient(circle, rgba(56, 189, 248, 0.2) 0%, rgba(14, 165, 233, 0.05) 100%)",
                  border: "1px solid rgba(56, 189, 248, 0.4)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: "28px"
                }}>
                  {devIcon}
                </div>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <h2 style={{ margin: 0, fontSize: "1.25rem", color: "#f8fafc", fontWeight: 700 }}>{d.ip || r.ip_escaneada}</h2>
                    {d.hostname && d.hostname !== d.ip && (
                      <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>({d.hostname})</span>
                    )}
                  </div>
                  <div style={{ fontSize: "0.85rem", color: "#38bdf8", marginTop: "3px", fontWeight: 500 }}>
                    {d.categoria_nombre || d.dispositivo_tipo || "Dispositivo Conectado"}
                    {d.fabricante && d.fabricante !== "Desconocido" ? ` • ${d.fabricante}` : ""}
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
                {(() => {
                  const med = getDeviceConnectionMedium(d);
                  if (!med) return null;
                  const isWifi = med.medio === "wifi";
                  return (
                    <span 
                      title={med.detalle || `Conexión ${med.label}`}
                      style={{
                        padding: "4px 10px",
                        borderRadius: "6px",
                        background: isWifi ? "rgba(14, 165, 233, 0.15)" : "rgba(168, 85, 247, 0.15)",
                        border: isWifi ? "1px solid rgba(14, 165, 233, 0.35)" : "1px solid rgba(168, 85, 247, 0.35)",
                        color: isWifi ? "#38bdf8" : "#c084fc",
                        fontSize: "0.8rem",
                        fontWeight: 700,
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "4px"
                      }}
                    >
                      {med.icono} {med.label}
                    </span>
                  );
                })()}
                {latency && (
                  <span style={{
                    padding: "4px 10px",
                    borderRadius: "6px",
                    background: "rgba(16, 185, 129, 0.15)",
                    border: "1px solid rgba(16, 185, 129, 0.3)",
                    color: "#34d399",
                    fontSize: "0.8rem",
                    fontWeight: 600
                  }}>
                    ⚡ {latency} {ttlVal ? `(TTL ${ttlVal})` : ""}
                  </span>
                )}
                {d.mac && d.mac !== "Desconocida" && (
                  <span style={{
                    padding: "4px 10px",
                    borderRadius: "6px",
                    background: "rgba(255, 255, 255, 0.05)",
                    border: "1px solid rgba(255, 255, 255, 0.1)",
                    color: "#94a3b8",
                    fontSize: "0.78rem",
                    fontFamily: "monospace"
                  }}>
                    MAC: {d.mac}
                  </span>
                )}
              </div>
            </div>

            {ports.length > 0 && (
              <div style={{ borderTop: "1px solid rgba(255, 255, 255, 0.08)", paddingTop: "12px", display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                <span style={{ fontSize: "0.8rem", color: "#64748b", fontWeight: 600 }}>Puertos detectados:</span>
                {ports.map((p, pIdx) => {
                  const pNum = typeof p === "object" ? (p.puerto || p.port) : p;
                  const pServ = typeof p === "object" ? (p.servicio || p.service || "") : "";
                  return (
                    <span 
                      key={pIdx}
                      style={{
                        padding: "2px 8px",
                        borderRadius: "4px",
                        background: "rgba(56, 189, 248, 0.1)",
                        border: "1px solid rgba(56, 189, 248, 0.25)",
                        color: "#bae6fd",
                        fontSize: "0.78rem",
                        fontFamily: "monospace"
                      }}
                    >
                      {pNum} {pServ ? `(${pServ})` : ""}
                    </span>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}

      {allVulns.length > 0 ? (



        <div className="vuln-list">



          {allVulns.map((v, i) => (



            <div key={i} className={`vuln-card slide-up ${getSeverityClass(v.severidad)}`} style={{ animationDelay: `${i * 0.05}s` }}>



              <div className="vuln-score">



                <div className="vuln-score-number" style={{ color: getScoreColor(v.score || 0) }}>



                  {v.score ? v.score.toFixed(1) : "—"}



                </div>



                <span className="vuln-score-label" style={{ background: getScoreColor(v.score || 0), color: '#000' }}>



                  {v.severidad || "N/A"}



                </span>



              </div>



              <div className="vuln-port">



                <div className="vuln-port-number">:{v.puerto}</div>



                <div className="vuln-port-service">{v.servicio}</div>



                <div className="vuln-port-ip">{v.ip}</div>



              </div>



              <div className="vuln-info">



                <div className="vuln-cve-id">{v.cve_id}</div>



                <div className="vuln-description"><TranslatedText text={v.descripcion} /></div>



              </div>



            </div>



          ))}



        </div>



      ) : (



        <div className="empty-state">



          <div className="empty-state-icon"><Shield size={16} className="inline-icon" /> </div>



          <p>No se encontraron vulnerabilidades con versión detectable en este escaneo.</p>



        </div>



      )}



    </div>



  );



}



/* ========== ERROR BOUNDARY ========== */

class ErrorBoundary extends Component {

  constructor(props) {

    super(props);

    this.state = { hasError: false, error: null };

  }

  static getDerivedStateFromError(error) {

    return { hasError: true, error };

  }

  componentDidCatch(error, errorInfo) {

    console.error("[Skop0 ErrorBoundary] Error capturado:", error, errorInfo);

  }

  render() {

    if (this.state.hasError) {

      return (

        <div style={{ padding: "60px 20px", textAlign: "center", color: "var(--text-primary)" }}>

          <div style={{ fontSize: "42px", marginBottom: "16px" }}>⚠️</div>

          <h3 style={{ color: "var(--red-400)", marginBottom: "8px", fontSize: "18px" }}>

            Error al renderizar las burbujas

          </h3>

          <p style={{ color: "var(--text-secondary)", fontSize: "13px", maxWidth: "480px", margin: "0 auto 20px" }}>

            {this.state.error?.message || "Ocurrió un error inesperado al calcular la topología de la red."}

          </p>

          <div style={{ display: "flex", gap: "10px", justifyContent: "center" }}>

            <button 

              className="btn btn-primary"

              onClick={() => {

                this.setState({ hasError: false, error: null });

                if (this.props.onReset) this.props.onReset();

              }}

            >

              ↻ Reintentar vista

            </button>

          </div>

        </div>

      );

    }

    return this.props.children;

  }

}



/* ========== HISTORIAL ========== */



function Historial() {



  const navigate = useNavigate();



  const location = useLocation();



  const { scanId } = useParams();



  const { getToken } = useAuth();



  const scanEngine = useScanEngine();



  const [devices, setDevices] = useState([]);



  const [vulns, setVulns] = useState([]);



  const [topology, setTopology] = useState(null);



  const [loading, setLoading] = useState(true);



  const [isProcessing, setIsProcessing] = useState(false);



  const [vista, setVista] = useState(location.state?.defaultView || "lista");
  const [expandedDevices, setExpandedDevices] = useState(new Set());
  const [filterVulnOnly, setFilterVulnOnly] = useState(false);
  const [localIp, setLocalIp] = useState(null);
  const [pingLoading, setPingLoading] = useState({});

  const handleTestPing = async (ip, e) => {
    if (e) e.stopPropagation();
    setPingLoading(prev => ({ ...prev, [ip]: true }));
    try {
      const token = await getToken();
      const tele = await getDeviceTelemetry(ip, token);
      if (tele) {
        setDevices(prev => prev.map(d => d.ip === ip ? { ...d, telemetria: tele } : d));
      }
    } catch (err) {
      console.warn("Error probando ping en vivo:", err);
    } finally {
      setPingLoading(prev => ({ ...prev, [ip]: false }));
    }
  };

  useEffect(() => {
    checkHealth()
      .then(h => {
        if (h && (h.local_ip || h.ip)) {
          setLocalIp(h.local_ip || h.ip);
        }
      })
      .catch(() => {});
  }, []);

  const toggleDeviceVulns = (ip) => {
    setExpandedDevices(prev => {
      const next = new Set(prev);
      if (next.has(ip)) {
        next.delete(ip);
      } else {
        next.add(ip);
      }
      return next;
    });
  };

  const expandAllVulns = () => {
    const withVulns = (devices || []).filter(d => (d.total_vulnerabilidades || 0) > 0).map(d => d.ip);
    setExpandedDevices(new Set(withVulns.length > 0 ? withVulns : (devices || []).map(d => d.ip)));
  };

  const collapseAllVulns = () => {
    setExpandedDevices(new Set());
  };

  const scrollToVuln = (ip) => {
    setExpandedDevices(prev => new Set(prev).add(ip));
    setTimeout(() => {
      const el = document.getElementById(`device-row-${ip}`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 100);
  };

  const [scanLogs, setScanLogs] = useState([]);



  const [historialTerminalExpanded, setHistorialTerminalExpanded] = useState(false);



  const isCurrentScanActive = Boolean(scanEngine.scanning && scanEngine.scanId === scanId);



  const loadData = useCallback(async () => {



    try {



      const token = await getToken();



      let devs = [];



      let vuls = [];



      let topo = null;



      let status = "completed";



      



      if (scanId) {

        try {

          const [data, detailsData] = await Promise.all([

            getScanDevices(scanId, token),

            getScanDetails(scanId, token)

          ]);

          devs = (data && data.devices) || [];

          if (detailsData && detailsData.status === "ok" && detailsData.details) {

             topo = detailsData.details.topology || null;

             status = detailsData.details.status || "completed";

             if (detailsData.details.logs) {

               setScanLogs(detailsData.details.logs);

             }

          }

          // Si hay dispositivos descubiertos en la topología pero aún no terminaron el deep-scan, incluirlos para mantener la visual de burbujas

          if (topo && Array.isArray(topo.devices)) {

            const scannedIps = new Set(devs.map(d => d.ip));

            topo.devices.forEach(td => {

              const tip = typeof td === 'string' ? td : td.ip;

              if (tip && !scannedIps.has(tip)) {

                devs.push({
                  ip: tip,
                  mac: td.mac || "Sondeando...",
                  fabricante: td.fabricante || td.vendor || "Detectando...",
                  vendor: td.vendor || td.fabricante || "",
                  icono: td.icono || "",
                  dispositivo_tipo: td.dispositivo_tipo || "",
                  categoria_nombre: td.categoria_nombre || "",
                  hostname: td.hostname || tip,
                  puertos_abiertos: td.puertos_abiertos || [],
                  total_vulnerabilidades: td.total_vulnerabilidades || 0,
                  estado: td.estado || "Auditando..."
                });

              }

            });

          }

        } catch (fetchErr) {

          console.warn("[Historial] Esperando inicialización del escaneo...", fetchErr);

        }

      } else {

        const devData = await getDevices(token);

        devs = devData.dispositivos || [];

      }

      (devs || []).forEach(d => {
        if (!d) return;
        (d.puertos_abiertos || []).forEach(p => {
          if (!p) return;
          (p.vulnerabilidades || []).forEach(v => {
            if (!v) return;
            vuls.push({
              ...v,
              puerto: typeof p === 'object' ? (p.puerto || p.port) : p,
              servicio: typeof p === 'object' ? (p.servicio || p.service || '') : '',
              version: typeof p === 'object' ? (p.version || '') : '',
              ip: d.ip
            });
          });
        });
      });



      



      vuls.sort((a, b) => (b.score || 0) - (a.score || 0));



      setDevices(devs);



      setVulns(vuls);



      setTopology(topo);



      setIsProcessing(status === "processing" || isCurrentScanActive);



    } catch (e) {



      console.error(e);



    } finally {



      setLoading(false);



    }



  }, [scanId, getToken, isCurrentScanActive]);



  useEffect(() => {



    loadData();



    



    let intervalId;



    if (isProcessing || isCurrentScanActive) {



      intervalId = setInterval(() => {



        loadData();



      }, 1500); // Polling cada 1.5s para actualización fluida de burbujas en vivo



    }



    return () => {



      if (intervalId) clearInterval(intervalId);



    };



  }, [loadData, isProcessing, isCurrentScanActive]);



  useEffect(() => {



    if (!loading && location.state?.autoPrint) {



      setTimeout(() => {



        window.print();



        window.history.replaceState({}, '');



      }, 800);



    }



  }, [loading, location.state]);



  const getScoreColor = (score) => {



    if (score >= 9.0) return "#ff4757"; // Crítico



    if (score >= 7.0) return "#ffa502"; // Alto



    if (score >= 4.0) return "#eccc68"; // Medio



    return "#7bed9f"; // Bajo



  };
  if (loading && !isCurrentScanActive) {



    return (



      <div className="page-container fade-in">



        <button className="btn btn-back" onClick={() => navigate("/history")}>



          ← Volver



        </button>



        <div className="scanning-spinner" style={{ margin: "40px auto", width: "40px", height: "40px" }} />



      </div>



    );



  }



  return (
    <ErrorBoundary onReset={() => loadData()} title="Inconveniente al mostrar los detalles de la auditoría">
      <div className="page-container fade-in">



      <div className="historial-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>



        <div>



          <button className="btn btn-back" onClick={() => navigate("/history")}>



            ← Volver



          </button>



          <h1>Detalles del Escaneo</h1>



          <p>Datos almacenados en Firebase Firestore</p>



        </div>



        



      </div>



      {(isProcessing || isCurrentScanActive) && (



        <div className="historial-live-banner slide-up">



          <div className="bento-spinner-sm" style={{ width: '16px', height: '16px' }} />



          <span>



            <strong>Auditoría en curso:</strong> {scanEngine.scanMsg || "Procesando dispositivos de la red..."} (<strong>{devices.length || scanEngine.devicesFound || 0}</strong> dispositivos detectados en las burbujas)



          </span>



        </div>



      )}



      <div className="results-summary">



        <div className="summary-card">



          <div className="summary-card-label">Dispositivos {(isProcessing || isCurrentScanActive) ? "Detectados" : "Auditados"}</div>



          <div className="summary-card-value cyan">{devices?.length || scanEngine.devicesFound || 0}</div>



        </div>



        <div className="summary-card">



          <div className="summary-card-label">CVEs Detectados</div>



          <div className="summary-card-value red">{vulns?.length || 0}</div>



        </div>



      </div>



      <div className="view-toggle">



        <button



          className={`view-toggle-btn${vista === "lista" ? " active" : ""}`}



          onClick={() => setVista("lista")}



        >



          ☰ Vista Lista



        </button>



        <button



          className={`view-toggle-btn${vista === "arbol" ? " active" : ""}`}



          onClick={() => setVista("arbol")}



        >



          🌳 Vista Árbol



        </button>



        <button



          className={`view-toggle-btn${vista === "consola" ? " active" : ""}`}



          onClick={() => setVista("consola")}



        >



          ⌨️ Consola



        </button>



      </div>



      {vista === "consola" && (



        <div className={`bento-card bento-terminal slide-up ${historialTerminalExpanded ? "bento-terminal-expanded" : ""}`} style={{ marginTop: "20px" }}>



          <div className="terminal-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
            <div className="bento-badge terminal-badge" style={{ marginBottom: 0 }}>⌨️ CONSOLA DE AUDITORÍA</div>
            <button



              className="terminal-expand-toggle"



              onClick={() => setHistorialTerminalExpanded(!historialTerminalExpanded)}



              title={historialTerminalExpanded ? "Minimizar consola" : "Expandir consola a pantalla completa"}



              type="button"



            >



              {historialTerminalExpanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}



            </button>
          </div>



          <div className="terminal-body" id="historial-console-container" style={{ minHeight: "500px", maxHeight: "800px" }}>



            {scanLogs.length > 0 ? (



              scanLogs.map((log, i) => renderTerminalLine(log, i))
                        ) : (



              <div className="terminal-line" style={{ color: "var(--text-gray)" }}>



                No hay logs registrados para esta auditoría.



              </div>



            )}



          </div>



        </div>



      )}



      {vista === "arbol" && (

        <ErrorBoundary onReset={() => setVista("lista")}>

          <NetworkTree 

            devices={devices} 

            topology={topology} 

            isProcessing={isProcessing || isCurrentScanActive}

            scanMsg={scanEngine.scanMsg}
            localIp={localIp}

            onVulnClick={(ip) => {

              if (document.fullscreenElement) {

                document.exitFullscreen().catch(err => console.log(err));

              }

              setVista("lista");

              setTimeout(() => scrollToVuln(ip), 150);

            }}

          />

        </ErrorBoundary>

      )}



      {vista === "lista" && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <h2 className="print-section-devices" style={{ margin: 0, fontSize: 20 }}>
                Dispositivos {filterVulnOnly ? `con Vulnerabilidades (${(devices || []).filter(d => (d?.total_vulnerabilidades || 0) > 0).length})` : `(${(devices || []).length})`}
              </h2>
              {(devices || []).some(d => (d?.total_vulnerabilidades || 0) > 0) && (
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    onClick={() => setFilterVulnOnly(false)}
                    style={{
                      background: !filterVulnOnly ? 'rgba(0, 212, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                      border: `1px solid ${!filterVulnOnly ? 'rgba(0, 212, 255, 0.4)' : 'rgba(255, 255, 255, 0.1)'}`,
                      color: !filterVulnOnly ? '#38bdf8' : '#94a3b8',
                      padding: '5px 12px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    Todos ({(devices || []).length})
                  </button>
                  <button
                    onClick={() => setFilterVulnOnly(true)}
                    style={{
                      background: filterVulnOnly ? 'rgba(255, 51, 102, 0.18)' : 'rgba(255, 255, 255, 0.05)',
                      border: `1px solid ${filterVulnOnly ? 'rgba(255, 51, 102, 0.45)' : 'rgba(255, 255, 255, 0.1)'}`,
                      color: filterVulnOnly ? '#ff3366' : '#94a3b8',
                      padding: '5px 12px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    🚨 Con CVEs ({(devices || []).filter(d => (d?.total_vulnerabilidades || 0) > 0).length})
                  </button>
                </div>
              )}
            </div>

            {(devices || []).some(d => (d?.total_vulnerabilidades || 0) > 0) && (
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="cve-toggle-all-btn"
                  onClick={expandedDevices.size > 0 ? collapseAllVulns : expandAllVulns}
                  style={{
                    background: 'rgba(255, 255, 255, 0.06)',
                    border: '1px solid rgba(255, 255, 255, 0.15)',
                    color: '#e2e8f0',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    transition: 'all 0.2s ease'
                  }}
                >
                  {expandedDevices.size > 0 ? '▲ Colapsar todas las CVEs' : '▼ Expandir todas las CVEs'}
                </button>
              </div>
            )}
          </div>

          {devices && devices.length > 0 ? (
            <div className="device-list" style={{ marginBottom: 40 }}>
              {(filterVulnOnly ? devices.filter(d => (d.total_vulnerabilidades || 0) > 0) : devices).map((d, i) => {
                const isScanner = typeof isScannerHost === 'function' ? isScannerHost(d, localIp) : false;
                const isExpanded = expandedDevices.has(d.ip);
                const hasVulns = (d.total_vulnerabilidades || 0) > 0;

                // Extraer y ordenar vulnerabilidades de este dispositivo
                const deviceVulns = [];
                (d.puertos_abiertos || []).forEach(p => {
                  if (!p) return;
                  (p.vulnerabilidades || []).forEach(v => {
                    if (!v) return;
                    deviceVulns.push({
                      ...v,
                      puerto: typeof p === 'object' ? (p.puerto || p.port) : p,
                      servicio: typeof p === 'object' ? (p.servicio || p.service || '') : '',
                      version: typeof p === 'object' ? (p.version || '') : '',
                      ip: d.ip
                    });
                  });
                });
                deviceVulns.sort((a, b) => ((b && b.score) || 0) - ((a && a.score) || 0));

                const critCount = deviceVulns.filter(v => ((v && v.score) || 0) >= 9.0).length;
                const highCount = deviceVulns.filter(v => ((v && v.score) || 0) >= 7.0 && ((v && v.score) || 0) < 9.0).length;
                const medCount = deviceVulns.filter(v => ((v && v.score) || 0) >= 4.0 && ((v && v.score) || 0) < 7.0).length;
                const lowCount = deviceVulns.filter(v => ((v && v.score) || 0) < 4.0).length;

                return (
                  <div 
                    key={d.ip || i} 
                    id={`device-row-${d.ip}`} 
                    className={`device-item-container ${isExpanded && hasVulns ? 'is-expanded' : ''}`}
                  >
                    <div 
                      className={`device-card slide-up ${hasVulns ? 'device-vuln-highlight' : ''} ${isScanner ? 'device-scanner-highlight' : ''}`} 
                      style={{ 
                        animationDelay: `${i * 0.04}s`,
                        cursor: 'pointer'
                      }}
                      onClick={() => toggleDeviceVulns(d.ip)}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px', minWidth: 0 }}>
                        <div 
                          className="device-avatar-icon" 
                          title={d.dispositivo_tipo || d.categoria_nombre || 'Dispositivo'}
                          style={{
                            width: '42px',
                            height: '42px',
                            minWidth: '42px',
                            borderRadius: '10px',
                            background: isScanner ? 'var(--cyan-dim)' : 'rgba(255, 255, 255, 0.04)',
                            border: isScanner ? '1px solid var(--cyan-border)' : '1px solid rgba(255, 255, 255, 0.09)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '21px',
                            userSelect: 'none'
                          }}
                        >
                          {getDeviceIcon(d)}
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '5px', minWidth: 0, flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <div className="device-ip">{d.ip}</div>
                            {(() => {
                              const med = getDeviceConnectionMedium(d);
                              if (!med) return null;
                              return (
                                <span 
                                  title={med.detalle || `Conexión ${med.label}`}
                                  style={{
                                    padding: '2px 8px',
                                    borderRadius: '5px',
                                    background: 'rgba(255, 255, 255, 0.04)',
                                    border: '1px solid rgba(255, 255, 255, 0.1)',
                                    color: 'var(--text-secondary)',
                                    fontSize: '0.76rem',
                                    fontWeight: 600,
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px'
                                  }}
                                >
                                  {med.label}
                                </span>
                              );
                            })()}
                            {isScanner && (
                              <span style={{ 
                                background: 'var(--cyan-dim)', 
                                color: 'var(--cyan-400)', 
                                border: '1px solid var(--cyan-border)', 
                                borderRadius: '5px', 
                                padding: '2px 8px', 
                                fontSize: '0.75rem', 
                                fontWeight: 700,
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px'
                              }}>
                                Este Equipo
                              </span>
                            )}
                            {d.hostname && !['none', 'dispositivo oculto', 'dispositivo de red', 'n/a'].includes(d.hostname.toLowerCase()) && (
                              <span style={{ color: 'var(--text-primary)', fontSize: '0.82rem', fontWeight: 600 }}>
                                {d.hostname}
                              </span>
                            )}
                            {d.es_nuevo && <span className="badge-new">NUEVO</span>}
                            {hasVulns ? (
                              <span 
                                className="device-cve-toggle-badge has-cves"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleDeviceVulns(d.ip);
                                }}
                                title="Haz clic para desplegar u ocultar las vulnerabilidades de este equipo"
                              >
                                🛡️ {d.total_vulnerabilidades} CVE{d.total_vulnerabilidades > 1 ? 's' : ''} {isExpanded ? '▲ Ocultar' : '▼ Ver'}
                              </span>
                            ) : (
                              <span className="device-cve-toggle-badge" style={{ background: "rgba(16, 185, 129, 0.08)", color: "#34d399", border: "1px solid rgba(16, 185, 129, 0.22)" }}>
                                ✓ Seguro
                              </span>
                            )}

                            {/* Telemetría Compacta de Enlace (Neutro + puntito indicador) */}
                            {(() => {
                              const t = d.telemetria;
                              if (!t) return null;
                              const isDead = t.packet_loss >= 100 || t.status === "unreachable";
                              const isLoss = t.packet_loss > 0 && t.packet_loss < 100;
                              const isSlow = t.status === "slow" || (t.latency_ms && t.latency_ms > 80);

                              const dotColor = isDead ? "#ef4444" : (isLoss || isSlow) ? "#f59e0b" : "#10b981";
                              const labelText = isDead
                                ? `Sin respuesta (0/${t.packets_sent || 4})`
                                : isLoss
                                  ? `Pérdida ${t.packet_loss}% · ${t.latency_ms ?? 0} ms`
                                  : (t.latency_ms !== null && t.latency_ms !== undefined ? `${t.latency_ms} ms` : "<1 ms");

                              return (
                                <span 
                                  title={isDead ? `Sin respuesta ICMP (0/${t.packets_sent || 4})` : `Latencia: ${t.latency_ms ?? 0} ms | Pérdida: ${t.packet_loss || 0}%`}
                                  style={{
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "5px",
                                    padding: "2px 8px",
                                    borderRadius: "5px",
                                    fontSize: "0.74rem",
                                    fontWeight: 500,
                                    background: "rgba(255, 255, 255, 0.03)",
                                    color: "var(--text-muted)",
                                    border: "1px solid rgba(255, 255, 255, 0.07)"
                                  }}
                                >
                                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: dotColor, flexShrink: 0 }} />
                                  {labelText}
                                </span>
                              );
                            })()}
                          </div>
                          <div className="device-mac">
                            {(d.fabricante && d.fabricante !== "Desconocido") || (d.vendor && d.vendor !== "Desconocido") 
                              ? `Fabricante: ${d.fabricante && d.fabricante !== "Desconocido" ? d.fabricante : d.vendor}` 
                              : `MAC: ${d.mac}`}
                            {d.dispositivo_tipo ? ` • ${d.dispositivo_tipo}` : (d.categoria_nombre ? ` • ${d.categoria_nombre}` : '')}
                          </div>
                        </div>
                      </div>

                      <div className="device-stat">
                        <div className="device-stat-value" style={{ color: (d.max_score || 0) > 0 ? getScoreColor(d.max_score || 0) : 'var(--text-secondary)' }}>
                          {d.max_score ? Number(d.max_score).toFixed(1) : "0.0"}
                        </div>
                        <div className="device-stat-label">Riesgo Máx</div>
                      </div>

                      <div className="device-stat">
                        <div className="device-stat-value" style={{ color: hasVulns ? '#f87171' : 'var(--text-secondary)' }}>
                          {d.total_vulnerabilidades || 0}
                        </div>
                        <div className="device-stat-label">
                          {hasVulns ? (isExpanded ? "Ocultar ▲" : "Ver CVEs ▼") : "CVEs"}
                        </div>
                      </div>

                      <div className="device-date">
                        <div>Auditoría: {typeof d.fecha_auditoria === 'string' ? d.fecha_auditoria.split("T")[0] : "—"}</div>
                        {typeof d.primera_conexion === 'string' && (
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '3px' }}>
                            Entró: {d.primera_conexion.replace("T", " ").substring(0, 19)}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* CAJÓN DESPLEGABLE DE CVES ADJUNTO AL DISPOSITIVO */}
                    {isExpanded && (
                      <div className="device-cves-drawer">
                        <div className="device-cves-drawer-header">
                          <div className="device-cves-drawer-title">
                            <span>🛡️ {deviceVulns.length > 0 ? `Vulnerabilidades asociadas a ${d.hostname && d.hostname !== "Dispositivo Oculto" ? d.hostname : d.ip}` : `Estado de Seguridad: ${d.hostname || d.ip}`}</span>
                            <span style={{ color: '#64748b', fontSize: 11, fontWeight: 500 }}>
                              ({deviceVulns.length} detectadas)
                            </span>
                          </div>
                          <div className="device-cves-severity-chips">
                            {critCount > 0 && (
                              <span className="nt-badge" style={{ background: "rgba(255, 51, 102, 0.15)", color: "#ff3366", border: "1px solid rgba(255, 51, 102, 0.3)" }}>
                                {critCount} Crítica{critCount > 1 ? 's' : ''}
                              </span>
                            )}
                            {highCount > 0 && (
                              <span className="nt-badge" style={{ background: "rgba(255, 140, 0, 0.15)", color: "#ff8c00", border: "1px solid rgba(255, 140, 0, 0.3)" }}>
                                {highCount} Alta{highCount > 1 ? 's' : ''}
                              </span>
                            )}
                            {medCount > 0 && (
                              <span className="nt-badge" style={{ background: "rgba(255, 208, 0, 0.15)", color: "#ffd000", border: "1px solid rgba(255, 208, 0, 0.3)" }}>
                                {medCount} Media{medCount > 1 ? 's' : ''}
                              </span>
                            )}
                            {lowCount > 0 && (
                              <span className="nt-badge" style={{ background: "rgba(0, 255, 136, 0.15)", color: "#00ff88", border: "1px solid rgba(0, 255, 136, 0.3)" }}>
                                {lowCount} Baja{lowCount > 1 ? 's' : ''}
                              </span>
                            )}
                            {deviceVulns.length === 0 && (
                              <span className="nt-badge" style={{ background: "rgba(0, 255, 136, 0.15)", color: "#00ff88", border: "1px solid rgba(0, 255, 136, 0.3)" }}>
                                ✓ Sin vulnerabilidades conocidas
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Panel de Telemetría de Red y Paquetes */}
                        <div 
                          style={{
                            margin: "10px 14px 14px 14px",
                            padding: "12px 14px",
                            background: "rgba(15, 23, 42, 0.65)",
                            border: "1px solid rgba(255, 255, 255, 0.08)",
                            borderRadius: "8px",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            flexWrap: "wrap",
                            gap: "12px"
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "center", gap: "20px", flexWrap: "wrap" }}>
                            <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                              <span style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.5px" }}>
                                📦 Paquetes Recibidos
                              </span>
                              <span style={{ fontSize: "14px", fontWeight: 700, color: (d.telemetria?.packet_loss || 0) > 0 ? ((d.telemetria?.packet_loss || 0) >= 100 ? "#f87171" : "#fbbf24") : "#10b981" }}>
                                {d.telemetria ? `${d.telemetria.packets_recv || 0}/${d.telemetria.packets_sent || 4} (${d.telemetria.packet_loss || 0}% pérdida)` : "Sin prueba"}
                              </span>
                            </div>

                            <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                              <span style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.5px" }}>
                                ⏱️ Latencia Media (RTT)
                              </span>
                              <span style={{ fontSize: "14px", fontWeight: 700, color: "#38bdf8" }}>
                                {d.telemetria && d.telemetria.latency_ms !== null && d.telemetria.latency_ms !== undefined ? `${d.telemetria.latency_ms} ms` : (d.telemetria?.status === "unreachable" ? "—" : "<1 ms")}
                                {d.telemetria?.latency_min !== null && d.telemetria?.latency_min !== undefined && (
                                  <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 500, marginLeft: "6px" }}>
                                    (mín {d.telemetria.latency_min} / máx {d.telemetria.latency_max} ms)
                                  </span>
                                )}
                              </span>
                            </div>

                            <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                              <span style={{ fontSize: "11px", color: "#64748b", textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.5px" }}>
                                🚦 Diagnóstico del Enlace
                              </span>
                              <span style={{ fontSize: "12px", fontWeight: 600, color: (d.telemetria?.packet_loss || 0) >= 100 ? "#f87171" : ((d.telemetria?.packet_loss || 0) > 0 ? "#fbbf24" : "#10b981") }}>
                                {d.telemetria ? (
                                  (d.telemetria.packet_loss >= 100) 
                                    ? "🔴 Inaccesible / Posible Corte de Cable" 
                                    : (d.telemetria.packet_loss > 0) 
                                      ? "⚠️ Enlace Inestable (Pérdida parcial)" 
                                      : "🟢 Enlace Óptimo y Estable"
                                ) : "Listo para verificar"}
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Puertos abiertos del dispositivo */}
                        {(d.puertos_abiertos || []).length > 0 && (
                          <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#94a3b8', fontWeight: 700 }}>
                              Puertos Activos:
                            </span>
                            {(d.puertos_abiertos || []).map((p, pIdx) => {
                              const pNum = typeof p === 'object' ? (p.puerto || p.port) : p;
                              const pServ = typeof p === 'object' ? (p.servicio || p.service || '') : '';
                              const pProd = typeof p === 'object' ? (p.producto || '') : '';
                              const pVer = typeof p === 'object' ? (p.version || '') : '';
                              const prodInfo = [pProd, pVer].filter(Boolean).join(' ').trim();
                              return (
                                <span 
                                  key={pIdx}
                                  title={prodInfo ? `${pServ || 'TCP'} — ${prodInfo}` : (pServ || `TCP/${pNum}`)}
                                  style={{
                                    background: 'rgba(56, 189, 248, 0.12)',
                                    border: '1px solid rgba(56, 189, 248, 0.28)',
                                    color: '#38bdf8',
                                    borderRadius: '4px',
                                    padding: '2px 8px',
                                    fontSize: '11px',
                                    fontFamily: 'monospace',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px'
                                  }}
                                >
                                  <strong>:{pNum}</strong>
                                  {pServ && <span style={{ color: '#94a3b8' }}>({pServ}{prodInfo ? ` · ${prodInfo}` : ''})</span>}
                                </span>
                              );
                            })}
                          </div>
                        )}

                        {deviceVulns.length > 0 ? (
                          <div className="device-cve-list">
                            {deviceVulns.map((v, vi) => {
                              const scoreColor = getScoreColor(v.score || 0);
                              return (
                                <div key={vi} id={`vuln-${v.ip}-${vi}`} className="device-cve-item" style={{ borderLeftColor: scoreColor }}>
                                  <div className="device-cve-header">
                                    <div className="device-cve-score" style={{ background: `${scoreColor}22`, color: scoreColor, border: `1px solid ${scoreColor}55` }}>
                                      <strong>{v.score ? Number(v.score).toFixed(1) : "—"}</strong> {v.severidad || "N/A"}
                                    </div>
                                    <div className="device-cve-service">
                                      <span className="device-cve-port">Puerto :{v.puerto}</span>
                                      <span className="device-cve-proto">{v.servicio || "servicio"}{v.version ? ` · v${v.version}` : ''}</span>
                                    </div>
                                    <a 
                                      href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} 
                                      target="_blank" 
                                      rel="noreferrer" 
                                      className="device-cve-link"
                                      title="Consultar ficha técnica en NVD NIST"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      {v.cve_id} ↗
                                    </a>
                                  </div>
                                  <div className="device-cve-desc">
                                    <TranslatedText text={v.descripcion} />
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <div style={{ padding: '10px 14px', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: '6px', color: '#34d399', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span>🛡️</span>
                            <span>No se identificaron vulnerabilidades conocidas en los servicios abiertos de este equipo.</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-icon">📭</div>
              <p>{filterVulnOnly ? "No hay dispositivos con vulnerabilidades en este escaneo." : "No hay dispositivos en este escaneo."}</p>
            </div>
          )}
        </>
      )}

      </div>
    </ErrorBoundary>
  );
}



/* ========== APP ========== */



function App() {

  useEffect(() => {
    const handleUnload = () => {
      try {
        const url = (typeof window !== "undefined" && window.location.port !== "8000")
          ? `http://${window.location.hostname || "localhost"}:8000/api/bridge-unbind`
          : "/api/bridge-unbind";
        if (navigator.sendBeacon) {
          navigator.sendBeacon(url);
          // shutdown handled by session websocket and watchdog
        } else {
          fetch(url, { method: "POST", keepalive: true }).catch(() => {});
        }
      } catch (e) {}
    };

    window.addEventListener("beforeunload", handleUnload);
    // pagehide removed
    return () => {
      window.removeEventListener("beforeunload", handleUnload);
      // pagehide removed
    };
  }, []);




  useEffect(() => {



    let ws = null;



    let reconnectTimer = null;



    let isMounted = true;



    // Heartbeat HTTP complementario



    sendHeartbeat();



    const hbInterval = setInterval(() => {



      sendHeartbeat();



    }, 1500);



    const connectWebSocket = () => {



      if (!isMounted) return;



      try {



        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";



        const host = (window.location.port === "5173") ? "localhost:8000" : window.location.host;



        ws = new WebSocket(`${protocol}//${host}/ws/session`);



        ws.onopen = () => {



          const pingInterval = setInterval(() => {



            if (ws && ws.readyState === WebSocket.OPEN) {



              ws.send("ping");



            }



          }, 4000);



          ws._pingInterval = pingInterval;



        };



        ws.onclose = () => {



          if (ws && ws._pingInterval) clearInterval(ws._pingInterval);



          if (isMounted) {



            reconnectTimer = setTimeout(connectWebSocket, 1000);



          }



        };



        ws.onerror = () => {



          if (ws) ws.close();



        };



      } catch (err) {



        if (isMounted) {



          reconnectTimer = setTimeout(connectWebSocket, 1500);



        }



      }



    };



    connectWebSocket();



    return () => {



      isMounted = false;



      clearInterval(hbInterval);



      clearTimeout(reconnectTimer);



      if (ws) {



        if (ws._pingInterval) clearInterval(ws._pingInterval);



        ws.close();



      }



    };



  }, []);



  return (



    <AuthProvider>



      <Router>



        <Navbar />



        <GlobalScanBanner />



        <Routes>



          <Route path="/login" element={<LoginPage />} />



          <Route 



            path="/" 



            element={



              <ProtectedRoute>



                <Home />



              </ProtectedRoute>



            } 



          />



          <Route 



            path="/results" 



            element={



              <ProtectedRoute>



                <Results />



              </ProtectedRoute>



            } 



          />



          <Route 



            path="/history" 



            element={



              <ProtectedRoute>



                <ScanHistoryPage />



              </ProtectedRoute>



            } 



          />



          <Route 



            path="/history/:scanId" 



            element={



              <ProtectedRoute>



                <Historial />



              </ProtectedRoute>



            } 



          />



          <Route 



            path="/historial" 



            element={



              <ProtectedRoute>



                <Historial />



              </ProtectedRoute>



            } 



          />



        </Routes>



      </Router>



    </AuthProvider>



  );



}



export default App;



