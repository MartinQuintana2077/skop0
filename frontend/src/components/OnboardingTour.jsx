import React, { useState, useEffect, useCallback } from "react";
import { Network, Rocket, Crosshair, Activity, Radio, BarChart, ChevronRight, ChevronLeft } from "lucide-react";

const TOUR_STEPS = [
  {
    selector: '[data-tour="tour-interface-selector"]',
    badge: "Paso 1 de 6 • Conexión Física",
    title: "Selector de Tarjeta de Red",
    description:
      "¿Conectaste cámaras o un switch por cable Ethernet y tienes Internet por Wi-Fi? Aquí puedes elegir exactamente qué tarjeta escanear para no mezclar redes ni perder tu conexión.",
    tip: "Usa el botón 'Refrescar' si acabas de conectar un cable o adaptador USB.",
    icon: Network,
  },
  {
    selector: '[data-tour="tour-main-scan"]',
    badge: "Paso 2 de 6 • Escaneo Automático",
    title: "Lanzar Auditoría Inteligente",
    description:
      "Es el botón principal de Skop0. Con un solo clic analiza toda tu red actual, detecta los dispositivos conectados, descubre routers intermedios y evalúa si tienen puertos vulnerables.",
    tip: "Ideal cuando ya estás conectado directamente a la red que quieres auditar.",
    icon: Rocket,
  },
  {
    selector: '[data-tour="tour-target-scan"]',
    badge: "Paso 3 de 6 • Subredes y Cámaras IP",
    title: "Escanear Objetivo Específico",
    description:
      "Si tus equipos o cámaras tienen IP fija en otro segmento (por ejemplo, 192.168.20.0/24) o quieres auditar un único dispositivo, escríbelo aquí.",
    tip: "Skop0 creará un puente automático hacia esa subred sin desconectarte de Internet y sin duplicar direcciones IP.",
    icon: Crosshair,
  },
  {
    selector: '[data-tour="tour-terminal"]',
    badge: "Paso 4 de 6 • Monitoreo en Vivo",
    title: "Consola de Auditoría en Tiempo Real",
    description:
      "Aquí verás paso a paso todo lo que el motor de Skop0 está haciendo: barrido de Capa 2 (ARP), detección de fabricantes y análisis de servicios.",
    tip: "Puedes presionar el botón de expandir arriba a la derecha para verla en pantalla completa.",
    icon: Activity,
  },
  {
    selector: '[data-tour="tour-wifi"]',
    badge: "Paso 5 de 6 • Entorno Inalámbrico",
    title: "Explorador de Redes Wi-Fi",
    description:
      "Visualiza las redes inalámbricas cercanas, comprueba la calidad de su señal y cambia de red directamente desde la aplicación antes de lanzar un escaneo.",
    tip: "Útil para auditar distintos puntos de acceso en una misma oficina o planta.",
    icon: Radio,
  },
  {
    selector: '[data-tour="tour-history"]',
    badge: "Paso 6 de 6 • Reportes y Topología",
    title: "Historial y Mapas de Red",
    description:
      "Todas tus auditorías quedan guardadas aquí. Al entrar podrás explorar el Mapa de Topología interactivo, revisar vulnerabilidades CVE y exportar respaldos.",
    tip: "Puedes volver a abrir este tutorial cuando quieras desde el botón '❓ Tutorial' en la barra superior.",
    icon: BarChart,
  },
];

export default function OnboardingTour({ isOpen, onClose }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [targetRect, setTargetRect] = useState(null);

  const updateTargetPosition = useCallback(() => {
    if (!isOpen) return;
    const step = TOUR_STEPS[currentStep];
    if (!step) return;

    const el = document.querySelector(step.selector);
    if (el) {
      const rect = el.getBoundingClientRect();
      setTargetRect({
        top: rect.top,
        left: rect.left,
        width: rect.width,
        height: rect.height,
      });
    } else {
      setTargetRect(null);
    }
  }, [isOpen, currentStep]);

  // Hacer scroll suave hacia el elemento cuando cambia el paso
  useEffect(() => {
    if (!isOpen) {
      setCurrentStep(0);
      return;
    }

    const step = TOUR_STEPS[currentStep];
    if (!step) return;

    const el = document.querySelector(step.selector);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    // Actualizar coordenadas inmediatamente y tras la animación de scroll
    updateTargetPosition();
    const t1 = setTimeout(updateTargetPosition, 180);
    const t2 = setTimeout(updateTargetPosition, 420);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [isOpen, currentStep, updateTargetPosition]);

  // Escuchar cambios de tamaño o scroll de la ventana
  useEffect(() => {
    if (!isOpen) return;
    window.addEventListener("resize", updateTargetPosition);
    window.addEventListener("scroll", updateTargetPosition, true);
    return () => {
      window.removeEventListener("resize", updateTargetPosition);
      window.removeEventListener("scroll", updateTargetPosition, true);
    };
  }, [isOpen, updateTargetPosition]);

  // Navegación con teclado
  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e) => {
      if (e.key === "Escape") {
        onClose();
      } else if (e.key === "ArrowRight" || e.key === "Enter") {
        if (currentStep < TOUR_STEPS.length - 1) {
          setCurrentStep((s) => s + 1);
        } else {
          onClose();
        }
      } else if (e.key === "ArrowLeft") {
        if (currentStep > 0) {
          setCurrentStep((s) => s - 1);
        }
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, currentStep, onClose]);

  if (!isOpen) return null;

  const step = TOUR_STEPS[currentStep];
  const IconComp = step.icon;
  const pad = 8;

  // Calcular posición óptima de la tarjeta explicativa sin salirse de la pantalla
  const vw = typeof window !== "undefined" ? window.innerWidth : 1280;
  const vh = typeof window !== "undefined" ? window.innerHeight : 800;
  const cardWidth = Math.min(390, vw - 32);
  const cardHeightEstimate = 275;

  let tooltipTop = vh / 2 - cardHeightEstimate / 2;
  let tooltipLeft = vw / 2 - cardWidth / 2;

  if (targetRect) {
    const spaceBelow = vh - (targetRect.top + targetRect.height + pad);
    const spaceAbove = targetRect.top - pad;
    const spaceRight = vw - (targetRect.left + targetRect.width + pad);
    const spaceLeft = targetRect.left - pad;

    if (spaceBelow >= cardHeightEstimate + 20) {
      tooltipTop = targetRect.top + targetRect.height + pad + 14;
      tooltipLeft = targetRect.left + targetRect.width / 2 - cardWidth / 2;
    } else if (spaceAbove >= cardHeightEstimate + 20) {
      tooltipTop = targetRect.top - pad - cardHeightEstimate - 14;
      tooltipLeft = targetRect.left + targetRect.width / 2 - cardWidth / 2;
    } else if (spaceRight >= cardWidth + 24) {
      tooltipTop = targetRect.top + targetRect.height / 2 - cardHeightEstimate / 2;
      tooltipLeft = targetRect.left + targetRect.width + pad + 16;
    } else if (spaceLeft >= cardWidth + 24) {
      tooltipTop = targetRect.top + targetRect.height / 2 - cardHeightEstimate / 2;
      tooltipLeft = targetRect.left - pad - cardWidth - 16;
    } else {
      tooltipTop = Math.max(16, vh - cardHeightEstimate - 20);
      tooltipLeft = vw / 2 - cardWidth / 2;
    }

    // Asegurar márgenes dentro de la ventana
    tooltipLeft = Math.max(16, Math.min(tooltipLeft, vw - cardWidth - 16));
    tooltipTop = Math.max(16, Math.min(tooltipTop, vh - cardHeightEstimate - 16));
  }

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 10000,
        pointerEvents: "auto",
      }}
    >
      {/* Recorte Spotlight alrededor del elemento activo */}
      {targetRect ? (
        <div
          style={{
            position: "fixed",
            top: `${targetRect.top - pad}px`,
            left: `${targetRect.left - pad}px`,
            width: `${targetRect.width + pad * 2}px`,
            height: `${targetRect.height + pad * 2}px`,
            borderRadius: "16px",
            boxShadow:
              "0 0 0 9999px rgba(6, 8, 15, 0.82), 0 0 28px rgba(45, 212, 191, 0.5), inset 0 0 12px rgba(45, 212, 191, 0.25)",
            border: "2px solid #2dd4bf",
            transition: "all 0.35s cubic-bezier(0.16, 1, 0.3, 1)",
            pointerEvents: "none",
            zIndex: 10001,
          }}
        />
      ) : (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(6, 8, 15, 0.82)",
            zIndex: 10001,
          }}
        />
      )}

      {/* Tarjeta Flotante Explicativa */}
      <div
        style={{
          position: "fixed",
          top: `${tooltipTop}px`,
          left: `${tooltipLeft}px`,
          width: `${cardWidth}px`,
          background: "linear-gradient(165deg, #161923 0%, #0d1017 100%)",
          border: "1px solid rgba(45, 212, 191, 0.45)",
          borderRadius: "16px",
          padding: "22px",
          color: "#f8fafc",
          boxShadow: "0 20px 50px rgba(0, 0, 0, 0.85), 0 0 25px rgba(14, 165, 233, 0.18)",
          zIndex: 10002,
          transition: "top 0.35s cubic-bezier(0.16, 1, 0.3, 1), left 0.35s cubic-bezier(0.16, 1, 0.3, 1)",
        }}
      >
        {/* Cabecera del paso */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
          <span
            style={{
              background: "rgba(45, 212, 191, 0.14)",
              border: "1px solid rgba(45, 212, 191, 0.35)",
              color: "#2dd4bf",
              fontSize: "0.72rem",
              fontWeight: 700,
              padding: "3px 10px",
              borderRadius: "99px",
              textTransform: "uppercase",
              letterSpacing: "0.4px",
            }}
          >
            {step.badge}
          </span>

          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "#64748b",
              fontSize: "0.78rem",
              fontWeight: 600,
              cursor: "pointer",
              padding: "2px 6px",
            }}
            title="Cerrar recorrido guiado (Esc)"
          >
            Saltar ✕
          </button>
        </div>

        {/* Título con icono */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "10px" }}>
          <div
            style={{
              width: "36px",
              height: "36px",
              borderRadius: "10px",
              background: "rgba(14, 165, 233, 0.15)",
              border: "1px solid rgba(14, 165, 233, 0.35)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#38bdf8",
              flexShrink: 0,
            }}
          >
            <IconComp size={18} />
          </div>
          <h4 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 700, color: "#f8fafc" }}>
            {step.title}
          </h4>
        </div>

        {/* Descripción sencilla */}
        <p style={{ margin: "0 0 12px 0", fontSize: "0.86rem", color: "#cbd5e1", lineHeight: 1.5 }}>
          {step.description}
        </p>

        {/* Consejo rápido */}
        {step.tip && (
          <div
            style={{
              background: "rgba(14, 165, 233, 0.08)",
              borderLeft: "3px solid #38bdf8",
              borderRadius: "4px 8px 8px 4px",
              padding: "8px 10px",
              fontSize: "0.78rem",
              color: "#94a3b8",
              marginBottom: "16px",
              lineHeight: 1.4,
            }}
          >
            💡 <strong style={{ color: "#e2e8f0" }}>Tip:</strong> {step.tip}
          </div>
        )}

        {/* Indicadores de puntos + Botones Anterior / Siguiente */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: "6px" }}>
          <div style={{ display: "flex", gap: "5px" }}>
            {TOUR_STEPS.map((_, idx) => (
              <span
                key={idx}
                onClick={() => setCurrentStep(idx)}
                style={{
                  width: idx === currentStep ? "18px" : "7px",
                  height: "7px",
                  borderRadius: "99px",
                  background: idx === currentStep ? "#2dd4bf" : "rgba(255, 255, 255, 0.18)",
                  cursor: "pointer",
                  transition: "all 0.25s ease",
                }}
              />
            ))}
          </div>

          <div style={{ display: "flex", gap: "8px" }}>
            {currentStep > 0 && (
              <button
                onClick={() => setCurrentStep((s) => s - 1)}
                style={{
                  padding: "7px 12px",
                  borderRadius: "8px",
                  border: "1px solid rgba(255, 255, 255, 0.12)",
                  background: "rgba(255, 255, 255, 0.04)",
                  color: "#cbd5e1",
                  fontSize: "0.8rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                }}
              >
                <ChevronLeft size={14} /> Anterior
              </button>
            )}

            <button
              onClick={() => {
                if (currentStep < TOUR_STEPS.length - 1) {
                  setCurrentStep((s) => s + 1);
                } else {
                  onClose();
                }
              }}
              style={{
                padding: "7px 14px",
                borderRadius: "8px",
                border: "none",
                background: "linear-gradient(135deg, #2dd4bf 0%, #0ea5e9 100%)",
                color: "#06080f",
                fontSize: "0.82rem",
                fontWeight: 700,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "4px",
                boxShadow: "0 3px 10px rgba(45, 212, 191, 0.25)",
              }}
            >
              {currentStep < TOUR_STEPS.length - 1 ? (
                <>
                  Siguiente <ChevronRight size={14} />
                </>
              ) : (
                "¡Entendido!"
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
