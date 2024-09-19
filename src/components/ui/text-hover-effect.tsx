"use client";
import React, { useRef, useEffect, useState } from "react";
import { motion } from "framer-motion";

export const TextHoverEffect = ({
  text,
  duration,
  className = "",
  rotate = 0,
  x = 0,
  y = 0,
}: {
  text: string;
  duration?: number;
  automatic?: boolean;
  className?: string;
  rotate?: number;
  x?: number | string;
  y?: number | string;
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const [hovered, setHovered] = useState(false);
  const [maskPosition, setMaskPosition] = useState({ cx: "50%", cy: "50%" });

  useEffect(() => {
    if (svgRef.current && cursor.x !== null && cursor.y !== null) {
      const svgRect = svgRef.current.getBoundingClientRect();
      const cxPercentage = ((cursor.x - svgRect.left) / svgRect.width) * 100;
      const cyPercentage = ((cursor.y - svgRect.top) / svgRect.height) * 100;
      setMaskPosition({
        cx: `${cxPercentage}%`,
        cy: `${cyPercentage}%`,
      });
    }
  }, [cursor]);
  return (
    <motion.div 
      className={`w-full h-full ${className}`}
      style={{ rotate, x, y }}
      transition={{ duration: 0.5, ease: "easeInOut" }}
    >
      <svg
        ref={svgRef}
        width="70%"
        height="70%"
        viewBox="0 0 800 400"
        preserveAspectRatio="xMidYMid meet"
        xmlns="http://www.w3.org/2000/svg"
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        onMouseMove={(e) => setCursor({ x: e.clientX, y: e.clientY })}
        className="select-none m-auto "
      >
        <defs>
          <linearGradient
            id="textGradient"
            gradientUnits="userSpaceOnUse"
            cx="50%"
            cy="50%"
            r="25%"
          >
            {hovered && (
              <>
                <stop offset="0%" stopColor="#FFD700" />
                <stop offset="25%" stopColor="#FF4500" />
                <stop offset="50%" stopColor="#1E90FF" />
                <stop offset="75%" stopColor="#00FFFF" />
                <stop offset="100%" stopColor="#9400D3" />
              </>
            )}
          </linearGradient>

          <motion.radialGradient
            id="revealMask"
            gradientUnits="userSpaceOnUse"
            r="20%"
            animate={maskPosition}
            transition={{
              type: "spring",
              stiffness: 300,
              damping: 50,
            }}
          >
            <stop offset="0%" stopColor="white" />
            <stop offset="100%" stopColor="black" />
          </motion.radialGradient>
          <mask id="textMask">
            <rect
              x="0"
              y="0"
              width="100%"
              height="100%"
              fill="url(#revealMask)"
            />
          </mask>
        </defs>
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          strokeWidth="1"
          className="font-[lexend-zetta] font-bold stroke-text0 dark:stroke-surface0 fill-transparent"
          style={{ fontSize: "200px", opacity: hovered ? 0.7 : 0 }}
        >
          {text}
        </text>
        <motion.text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          strokeWidth="1"
          className="font-[montserrat] font-bold fill-transparent stroke-text0 dark:stroke-surface0"
          initial={{ strokeDashoffset: 2000, strokeDasharray: 2000 }}
          animate={{
            strokeDashoffset: 0,
            strokeDasharray: 2000,
          }}
          transition={{
            duration: 4,
            ease: "easeInOut",
          }}
          style={{ fontSize: "200px" }}
        >
          {text}
        </motion.text>
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          stroke="url(#textGradient)"
          strokeWidth="1"
          mask="url(#textMask)"
          className="font-[montserrat] font-bold fill-transparent"
          style={{ fontSize: "200px" }}
        >
          {text}
        </text>
      </svg>
    </motion.div>
  );
};