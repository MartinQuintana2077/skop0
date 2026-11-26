import React, { useState, useEffect } from "react";
import { Crown, AlertTriangle, CheckCircle, RefreshCw, Copy, Check, ExternalLink, ShieldAlert, MessageCircle } from "lucide-react";
import { refreshSubscriptionStatus } from "../services/api";
import { useAuth } from "../context/AuthContext";

export default function SubscriptionModal({ isOpen, onClose, subscription: propSub, token: propToken, onRefreshed, reason = null }) {
  const auth = useAuth();
  const subscription = auth?.subscription || propSub;
  const token = propToken;

  const [refreshing, setRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [refreshSuccess, setRefreshSuccess] = useState(false);

  // Comprobar inmediatamente al abrir el modal
  useEffect(() => {
    if (!isOpen) return;
    if (auth?.refreshSubscription) {
      auth.refreshSubscription().then((fresh) => {
        if (fresh && onRefreshed) onRefreshed(fresh);
      }).catch(() => {});
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const isActive = subscription?.status === "active" && subscription?.can_scan === true;
  const isInactive = subscription?.status === "inactive" || (!subscription?.valid_until && !isActive);
  const isExpired = subscription?.status === "expired" || (!isActive && !isInactive);
  const daysRemaining = subscription?.days_remaining ?? 0;
  const validUntilFormatted = subscription?.formatted_date || "Pendiente de activación";
  const email = subscription?.email || auth?.user?.email || "Usuario Skop0";

  const handleRefresh = async () => {
    setRefreshing(true);
    setRefreshSuccess(false);
    try {
      let data = null;
      if (auth?.refreshSubscription) {
        data = await auth.refreshSubscription();
      } else if (token) {
        data = await refreshSubscriptionStatus(token);
      }
      if (data && onRefreshed) {
        onRefreshed(data);
      }
      setRefreshSuccess(true);
      setTimeout(() => setRefreshSuccess(false), 3000);
    } catch (err) {
      console.error("Error al refrescar suscripción:", err);
    } finally {
      setRefreshing(false);
    }
  };

  const handleCopyEmail = () => {
    if (email) {
      navigator.clipboard.writeText(email);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const whatsappNumber = "56961210402";
  const whatsappText = `Hola, me comunico sobre Skop0. Quisiera obtener más información para entender los planes, suscribirme o extender mi suscripción para mi cuenta: ${email}${subscription?.user_id ? ` (ID: ${subscription.user_id})` : ''}.`;
  const whatsappUrl = `https://wa.me/${whatsappNumber}?text=${encodeURIComponent(whatsappText)}`;

  return (
    <div 
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.78)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '16px'
      }}
      onClick={onClose}
    >
      <div 
        style={{
          backgroundColor: '#111318',
          border: '1px solid rgba(56, 189, 248, 0.28)',
          borderRadius: '16px',
          maxWidth: '520px',
          width: '100%',
          padding: '28px',
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.85), 0 0 35px rgba(14, 165, 233, 0.08)',
          position: 'relative',
          color: '#f8fafc',
          fontFamily: "'Inter', system-ui, sans-serif"
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Botón cerrar */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '16px',
            right: '16px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: 'none',
            color: '#94a3b8',
            cursor: 'pointer',
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '18px',
            fontWeight: 'bold',
            transition: 'background 0.2s, color 0.2s'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.12)';
            e.currentTarget.style.color = '#fff';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
            e.currentTarget.style.color = '#94a3b8';
          }}
          aria-label="Cerrar"
        >
          ✕
        </button>

        {/* Encabezado */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '22px' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: isActive 
              ? 'rgba(245, 158, 11, 0.15)' 
              : isInactive 
                ? 'rgba(234, 179, 8, 0.15)' 
                : 'rgba(239, 68, 68, 0.15)',
            border: `1px solid ${
              isActive 
                ? 'rgba(245, 158, 11, 0.35)' 
                : isInactive 
                  ? 'rgba(234, 179, 8, 0.35)' 
                  : 'rgba(239, 68, 68, 0.35)'
            }`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isActive ? '#fbbf24' : isInactive ? '#facc15' : '#f87171',
            flexShrink: 0
          }}>
            {isActive ? <Crown size={24} /> : isInactive ? <ShieldAlert size={24} /> : <AlertTriangle size={24} />}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
                Estado de Cuenta & Licencia
              </h3>
              {isActive && (
                <span style={{
                  background: 'rgba(245, 158, 11, 0.2)',
                  color: '#fbbf24',
                  border: '1px solid rgba(245, 158, 11, 0.4)',
                  padding: '2px 8px',
                  borderRadius: '12px',
                  fontSize: '10px',
                  fontWeight: 800,
                  letterSpacing: '0.5px'
                }}>
                  PRO
                </span>
              )}
            </div>
            <p style={{ fontSize: '12px', color: '#94a3b8', margin: '4px 0 0' }}>
              {isActive 
                ? "Licencia activa — Acceso habilitado a escaneo y auditorías" 
                : "Acceso a auditorías restringido a cuentas autorizadas"}
            </p>
          </div>
        </div>

        {/* Banner de Bloqueo de Escaneo si fue disparado al intentar auditar */}
        {reason === "scan_blocked" && (
          <div style={{
            background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(220, 38, 38, 0.08))',
            border: '1px solid rgba(239, 68, 68, 0.45)',
            borderRadius: '12px',
            padding: '14px 16px',
            marginBottom: '18px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            boxShadow: '0 4px 18px rgba(239, 68, 68, 0.15)'
          }}>
            <ShieldAlert size={22} color="#f87171" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontSize: '13.5px', fontWeight: 800, color: '#fca5a5', marginBottom: '3px' }}>
                Acceso Restringido a Auditorías
              </div>
              <p style={{ fontSize: '12px', color: '#fecaca', margin: 0, lineHeight: 1.45 }}>
                Esta cuenta requiere una licencia activa otorgada por el administrador para iniciar auditorías de red.
                Copia tu correo a continuación y solicítala al administrador, o pulsa "Comprobar Activación" si ya fue autorizada.
              </p>
            </div>
          </div>
        )}

        {/* Tarjeta de Estado Actual */}
        <div style={{
          background: isActive
            ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.12), rgba(18, 19, 26, 0.9))'
            : isInactive
              ? 'linear-gradient(135deg, rgba(234, 179, 8, 0.12), rgba(18, 19, 26, 0.9))'
              : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${
            isActive 
              ? 'rgba(245, 158, 11, 0.35)' 
              : isInactive 
                ? 'rgba(234, 179, 8, 0.35)' 
                : 'rgba(239, 68, 68, 0.35)'
          }`,
          borderRadius: '14px',
          padding: '18px',
          marginBottom: '18px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
            <div>
              <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.6px', color: '#94a3b8' }}>
                Plan de Servicio
              </span>
              <h4 style={{ fontSize: '16px', fontWeight: 800, margin: '4px 0 0', color: isActive ? '#fbbf24' : isInactive ? '#facc15' : '#f87171' }}>
                {isActive ? "Licencia Profesional Activa (PRO)" : isInactive ? "Cuenta Inactiva (Sin Licencia)" : "Licencia Vencida"}
              </h4>
            </div>

            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 10px',
              borderRadius: '20px',
              fontSize: '11px',
              fontWeight: 700,
              border: `1px solid ${isActive ? 'rgba(74, 222, 128, 0.4)' : isInactive ? 'rgba(234, 179, 8, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
              background: isActive ? 'rgba(74, 222, 128, 0.15)' : isInactive ? 'rgba(234, 179, 8, 0.15)' : 'rgba(239, 68, 68, 0.15)',
              color: isActive ? '#4ade80' : isInactive ? '#facc15' : '#f87171'
            }}>
              <span style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: isActive ? '#4ade80' : isInactive ? '#facc15' : '#f87171'
              }}></span>
              {isActive ? "Activo" : isInactive ? "Inactivo" : "Vencido"}
            </div>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '12px',
            paddingTop: '12px',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)'
          }}>
            <div>
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>Tiempo restante:</span>
              <p style={{ fontSize: '15px', fontWeight: 800, color: '#f8fafc', margin: '3px 0 0' }}>
                {isActive ? `${daysRemaining} ${daysRemaining === 1 ? 'día' : 'días'}` : "0 días"}
              </p>
            </div>
            <div>
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>Válida hasta:</span>
              <p style={{ fontSize: '15px', fontWeight: 800, color: '#f8fafc', margin: '3px 0 0' }}>
                {validUntilFormatted}
              </p>
            </div>
          </div>

          {!isActive && (
            <div style={{
              marginTop: '12px',
              padding: '10px 12px',
              borderRadius: '8px',
              fontSize: '12px',
              lineHeight: 1.5,
              background: isInactive ? 'rgba(234, 179, 8, 0.1)' : 'rgba(239, 68, 68, 0.1)',
              border: `1px solid ${isInactive ? 'rgba(234, 179, 8, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
              color: isInactive ? '#fde047' : '#fca5a5'
            }}>
              {isInactive 
                ? "🔒 Tu cuenta aún no ha sido activada por el administrador. Se requiere una licencia activa para iniciar auditorías. Tu historial y respaldos locales permanecen 100% disponibles."
                : "⚠️ Tu periodo de licencia ha finalizado. Solicita la renovación con el administrador para continuar escaneando redes."}
            </div>
          )}
        </div>

        {/* Sección de Cuenta & Correo */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid rgba(255, 255, 255, 0.07)',
          borderRadius: '12px',
          padding: '12px 14px',
          marginBottom: '14px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: '#94a3b8' }}>
              Tu Correo Registrado
            </span>
            <button 
              onClick={handleCopyEmail}
              style={{
                background: 'transparent',
                border: 'none',
                color: copied ? '#4ade80' : '#38bdf8',
                fontSize: '11px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? "¡Copiado!" : "Copiar"}
            </button>
          </div>
          <div style={{
            background: '#090a0f',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '8px',
            padding: '8px 12px',
            fontFamily: "'Fira Code', monospace",
            fontSize: '12px',
            color: '#e2e8f0',
            userSelect: 'all',
            wordBreak: 'break-all'
          }}>
            {email}
          </div>
        </div>

        {/* Sección de Instrucciones de Renovación / Suscripción */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid rgba(255, 255, 255, 0.07)',
          borderRadius: '12px',
          padding: '14px 16px',
          marginBottom: '20px'
        }}>
          <p style={{ fontSize: '13px', fontWeight: 700, color: '#f8fafc', margin: '0 0 5px' }}>
            {isActive ? "¿Deseas entender planes, suscribirte o extender tu licencia?" : "¿Deseas entender los planes o suscribirte a Skop0?"}
          </p>
          <p style={{ fontSize: '12px', color: '#94a3b8', lineHeight: 1.5, margin: '0 0 10px' }}>
            Escríbenos directamente a nuestro WhatsApp oficial para resolver dudas sobre los planes, entender su alcance, contratar una nueva suscripción o extender tu periodo activo.
          </p>
          <a
            href={whatsappUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              background: 'rgba(37, 211, 102, 0.12)',
              border: '1px solid rgba(37, 211, 102, 0.35)',
              color: '#4ade80',
              padding: '8px 14px',
              borderRadius: '8px',
              fontSize: '12px',
              fontWeight: 700,
              textDecoration: 'none',
              transition: 'all 0.2s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'rgba(37, 211, 102, 0.22)';
              e.currentTarget.style.transform = 'translateY(-1.5px)';
              e.currentTarget.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.35)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'rgba(37, 211, 102, 0.12)';
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
            onMouseDown={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
            }}
          >
            <MessageCircle size={15} color="#4ade80" />
            <span>Consultar, entender o suscribirse por WhatsApp</span>
            <ExternalLink size={12} />
          </a>
        </div>

        {/* Mensaje de confirmación de refresco */}
        {refreshSuccess && (
          <div style={{
            marginBottom: '14px',
            padding: '10px 12px',
            borderRadius: '8px',
            background: 'rgba(74, 222, 128, 0.1)',
            border: '1px solid rgba(74, 222, 128, 0.3)',
            color: '#4ade80',
            fontSize: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <CheckCircle size={15} /> ¡Estado de cuenta verificado exitosamente con el servidor!
          </div>
        )}

        {/* Botones de acción inferiores */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          paddingTop: '16px',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)'
        }}>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            style={{
              padding: '9px 15px',
              borderRadius: '9px',
              background: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: '#e2e8f0',
              fontSize: '12px',
              fontWeight: 600,
              cursor: refreshing ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              opacity: refreshing ? 0.6 : 1,
              transition: 'background 0.2s'
            }}
            onMouseEnter={(e) => !refreshing && (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.12)')}
            onMouseLeave={(e) => !refreshing && (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.06)')}
            title="Consulta Firestore para comprobar si el administrador ya activó tu licencia"
          >
            <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} />
            {refreshing ? "Comprobando..." : "Comprobar Activación"}
          </button>

          <button
            onClick={onClose}
            style={{
              padding: '9px 24px',
              borderRadius: '9px',
              background: 'linear-gradient(135deg, #0ea5e9, #38bdf8)',
              border: 'none',
              color: '#090a0f',
              fontSize: '12px',
              fontWeight: 800,
              cursor: 'pointer',
              boxShadow: '0 4px 15px rgba(14, 165, 233, 0.3)',
              transition: 'transform 0.15s, opacity 0.15s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.opacity = '0.92'}
            onMouseLeave={(e) => e.currentTarget.style.opacity = '1'}
          >
            Entendido
          </button>
        </div>

      </div>
    </div>
  );
}
