import { useAuth } from "../context/AuthContext";
import { useNavigate } from "react-router-dom";
import { useState, useEffect } from "react";
import { Shield, Network, Activity, Lock } from "lucide-react";
import Skop0Logo from "../components/Skop0Logo";

function LoginPage() {
  const { loginWithGoogle, user } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (user) {
      navigate("/");
    }
  }, [user, navigate]);

  const handleLogin = async () => {
    setError("");
    setLoading(true);
    try {
      await loginWithGoogle();
      navigate("/");
    } catch (err) {
      console.error("Detalle del error de autenticación:", err);
      const code = err?.code || "";
      const msg = err?.message || "";
      if (code === "auth/popup-blocked") {
        setError("El navegador bloqueó la ventana emergente de Google. Por favor, reintenta.");
      } else if (code === "auth/unauthorized-domain") {
        setError(`Dominio (${window.location.hostname}) no autorizado. Abre Skop0 en http://localhost:8000.`);
      } else if (code === "auth/popup-closed-by-user") {
        setError("Inicio de sesión cancelado.");
      } else if (code === "auth/network-request-failed") {
        setError("Sin conexión con Google/Firebase. Verifica tu acceso a Internet.");
      } else if (code) {
        setError(`Error (${code}): ${msg}`);
      } else if (msg) {
        setError(msg);
      } else {
        setError("No se pudo iniciar sesión. Inténtalo de nuevo.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-split-root fade-in">
      {/* Panel Izquierdo: Escaparate Técnico */}
      <div className="login-showcase">
        <div className="login-showcase-grid-bg" />

        {/* Cabecera de Marca */}
        <div className="login-brand-bar">
          <div className="login-brand-left">
            <Skop0Logo size={34} className="login-brand-shield" />
            <span className="login-brand-name">
              Skop<span>0</span>
            </span>
          </div>
          <span className="login-version-chip">v1.3</span>
        </div>

        {/* Contenido Central + Diagrama SVG animado */}
        <div className="login-showcase-main">
          <div className="login-kicker">PLATAFORMA DE AUDITORÍA DE RED</div>
          <h1 className="login-headline">
            Visibilidad total de tu red y <span>topología en tiempo real.</span>
          </h1>
          <p className="login-lead">
            Descubre equipos en Capa 2/3, detecta vulnerabilidades CVE en puertos expuestos y audita subredes aisladas sin interrumpir tu conexión.
          </p>

          {/* Ilustración vectorial técnica minimalista (Topología en vivo) */}
          <div className="login-topo-preview" aria-hidden="true">
            <svg viewBox="0 0 540 155" fill="none" xmlns="http://www.w3.org/2000/svg" className="login-topo-svg">
              {/* Líneas de enlace con pulso sutil */}
              <path d="M74 78 H196" stroke="var(--cyan-border)" strokeWidth="1.6" />
              <path d="M74 78 H196" stroke="var(--cyan-400)" strokeWidth="1.6" strokeDasharray="5 7" className="topo-flow-line" />

              <path d="M254 78 C295 78, 305 32, 354 32" stroke="var(--border-base)" strokeWidth="1.5" />
              <path d="M254 78 C295 78, 305 32, 354 32" stroke="var(--cyan-400)" strokeWidth="1.4" strokeDasharray="4 8" className="topo-flow-line" />

              <path d="M254 78 H354" stroke="var(--border-base)" strokeWidth="1.5" />
              <path d="M254 78 H354" stroke="var(--purple-400)" strokeWidth="1.4" strokeDasharray="4 8" className="topo-flow-line" />

              <path d="M254 78 C295 78, 305 124, 354 124" stroke="var(--border-base)" strokeWidth="1.5" />
              <path d="M254 78 C295 78, 305 124, 354 124" stroke="var(--cyan-400)" strokeWidth="1.4" strokeDasharray="4 8" className="topo-flow-line" />

              {/* Nodo 1: Gateway / Router */}
              <rect x="16" y="52" width="58" height="52" rx="12" fill="var(--bg-card)" stroke="var(--cyan-border)" strokeWidth="1.3" />
              <circle cx="45" cy="73" r="6" fill="var(--cyan-dim)" stroke="var(--cyan-400)" strokeWidth="1.5" />
              <text x="45" y="95" textAnchor="middle" fill="var(--text-secondary)" fontSize="9" fontFamily="monospace">GW .1</text>

              {/* Nodo 2: Switch L2 */}
              <rect x="196" y="52" width="58" height="52" rx="12" fill="var(--bg-card)" stroke="var(--border-base)" strokeWidth="1.3" />
              <rect x="213" y="69" width="24" height="10" rx="3" fill="var(--cyan-dim)" stroke="var(--cyan-400)" strokeWidth="1.2" />
              <text x="225" y="95" textAnchor="middle" fill="var(--text-secondary)" fontSize="9" fontFamily="monospace">SW L2</text>

              {/* Endpoints Derecha */}
              <rect x="354" y="14" width="170" height="36" rx="9" fill="var(--bg-card)" stroke="var(--border-base)" strokeWidth="1.2" />
              <circle cx="371" cy="32" r="4" fill="#10b981" />
              <text x="383" y="30" fill="var(--text-primary)" fontSize="10.5" fontFamily="monospace" fontWeight="600">192.168.20.11</text>
              <text x="383" y="42" fill="var(--text-muted)" fontSize="8.5" fontFamily="sans-serif">Cámara IP • Seguro</text>

              <rect x="354" y="60" width="170" height="36" rx="9" fill="var(--bg-card)" stroke="rgba(239,68,68,0.45)" strokeWidth="1.2" />
              <circle cx="371" cy="78" r="4" fill="#ef4444" />
              <text x="383" y="76" fill="var(--text-primary)" fontSize="10.5" fontFamily="monospace" fontWeight="600">192.168.18.12</text>
              <text x="383" y="88" fill="#f87171" fontSize="8.5" fontFamily="sans-serif">Servidor SMB • CVEs</text>

              <rect x="354" y="106" width="170" height="36" rx="9" fill="var(--bg-card)" stroke="var(--border-base)" strokeWidth="1.2" />
              <circle cx="371" cy="124" r="4" fill="#10b981" />
              <text x="383" y="122" fill="var(--text-primary)" fontSize="10.5" fontFamily="monospace" fontWeight="600">192.168.18.113</text>
              <text x="383" y="134" fill="var(--text-muted)" fontSize="8.5" fontFamily="sans-serif">Endpoint Wi-Fi • 4 ms</text>
            </svg>
          </div>

          {/* 3 Pilares Sobrios */}
          <div className="login-pillars">
            <div className="login-pillar">
              <Network size={16} className="login-pillar-icon" />
              <div>
                <div className="login-pillar-title">Descubrimiento Multi-Interfaz</div>
                <div className="login-pillar-desc">Elige Ethernet o Wi-Fi y conecta subredes estáticas sin perder Internet.</div>
              </div>
            </div>
            <div className="login-pillar">
              <Shield size={16} className="login-pillar-icon" />
              <div>
                <div className="login-pillar-title">Análisis CVE Automatizado</div>
                <div className="login-pillar-desc">Identifica puertos expuestos, servicios vulnerables y puntajes CVSS.</div>
              </div>
            </div>
            <div className="login-pillar">
              <Activity size={16} className="login-pillar-icon" />
              <div>
                <div className="login-pillar-title">Historial & Respaldos</div>
                <div className="login-pillar-desc">Mapas de red interactivos guardados y sincronizados con tu cuenta.</div>
              </div>
            </div>
          </div>
        </div>

        {/* Pie Técnico */}
        <div className="login-showcase-footer">
          <span className="login-by-noneit">by <strong>NoneIT</strong></span>
        </div>
      </div>

      {/* Panel Derecho: Acceso Limpio */}
      <div className="login-auth-panel">
        <div className="login-auth-inner">
          <div className="login-auth-kicker">ACCESO A LA CONSOLA</div>
          <h2 className="login-auth-title">Iniciar sesión</h2>
          <p className="login-auth-subtitle">
            Inicia sesión con tu cuenta de Google para acceder al panel de auditoría y validar tu licencia.
          </p>

          {error && (
            <div className="login-error-banner">
              {error}
            </div>
          )}

          <button
            type="button"
            className="login-google-btn"
            onClick={handleLogin}
            disabled={loading}
          >
            {loading ? (
              <span className="login-btn-spinner" />
            ) : (
              <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
                <path fill="#4285F4" d="M23.49 12.27c0-.79-.07-1.54-.2-2.27H12v4.51h6.47a5.53 5.53 0 0 1-2.4 3.63v3h3.88c2.27-2.09 3.54-5.17 3.54-8.87z"/>
                <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3c-1.08.72-2.45 1.15-4.05 1.15-3.12 0-5.77-2.11-6.72-4.96H1.29v3.09A12 12 0 0 0 12 24z"/>
                <path fill="#FBBC05" d="M5.28 14.28A7.2 7.2 0 0 1 4.9 12c0-.79.14-1.56.38-2.28V6.63H1.29a12 12 0 0 0 0 10.74l3.99-3.09z"/>
                <path fill="#EA4335" d="M12 4.76c1.76 0 3.34.61 4.58 1.8l3.44-3.44C17.95 1.19 15.24 0 12 0A12 12 0 0 0 1.29 6.63l3.99 3.09c.95-2.85 3.6-4.96 6.72-4.96z"/>
              </svg>
            )}
            <span>{loading ? "Conectando con Google..." : "Continuar con Google"}</span>
          </button>

          <div className="login-security-note">
            <Lock size={13} />
            <span>Autenticación cifrada vía Google OAuth 2.0</span>
          </div>

          <div className="login-auth-footer">
            © 2026 NoneIT • Skop0 Security Suite
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
