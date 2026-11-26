import React, { useId } from "react";

/**
 * Emblema oficial de Skop0: Cero Escáner (Itálica Pura -14°, Haz /).
 * Se adapta dinámicamente a las 5 paletas CSS de la aplicación (--cyan-400 / --purple-400).
 */
export default function Skop0Logo({ size = 32, className = "" }) {
  const rawId = useId();
  const gradId = `skop0-grad-${rawId.replace(/[^a-zA-Z0-9_-]/g, "")}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradId} x1="10" y1="10" x2="54" y2="54" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="var(--cyan-400, #22d3ee)" />
          <stop offset="100%" stopColor="var(--purple-400, #a855f7)" />
        </linearGradient>
      </defs>
      <g transform="translate(32 32) skewX(-14) translate(-32 -32)">
        <rect
          x="17"
          y="11"
          width="30"
          height="42"
          rx="15"
          fill={`url(#${gradId})`}
          fillOpacity="0.12"
          stroke={`url(#${gradId})`}
          strokeWidth="5.8"
        />
      </g>
      <line
        x1="9"
        y1="47"
        x2="55"
        y2="17"
        stroke={`url(#${gradId})`}
        strokeWidth="4.4"
        strokeLinecap="round"
      />
      <circle cx="9" cy="47" r="3.2" fill="var(--cyan-400, #22d3ee)" />
      <circle cx="55" cy="17" r="3.2" fill="var(--purple-400, #a855f7)" />
    </svg>
  );
}
