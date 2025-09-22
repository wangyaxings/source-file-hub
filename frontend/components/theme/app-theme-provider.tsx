"use client";

import React from "react";
import { ConfigProvider, theme as antdTheme } from "antd";

const LIGHT_TOKENS = {
  colorPrimary: "hsl(222, 47%, 11%)",
  colorBgBase: "hsl(0, 0%, 100%)",
  colorTextBase: "hsl(222, 84%, 4.9%)",
  colorInfo: "hsl(222, 47%, 11%)",
  colorSuccess: "#16a34a",
  colorWarning: "#ca8a04",
  colorError: "#dc2626",
  borderRadius: 8,
};

const DARK_TOKENS = {
  colorPrimary: "hsl(210, 40%, 98%)",
  colorBgBase: "hsl(222, 84%, 4.9%)",
  colorTextBase: "hsl(210, 40%, 98%)",
  colorInfo: "hsl(210, 40%, 98%)",
  colorSuccess: "#22c55e",
  colorWarning: "#facc15",
  colorError: "#f87171",
  borderRadius: 8,
};

function resolveInitialMode(): "light" | "dark" {
  if (typeof window === "undefined") {
    return "light";
  }
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

export function AppThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = React.useState<"light" | "dark">(resolveInitialMode);

  React.useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const target = document.documentElement;
    const observer = new MutationObserver(() => {
      setMode(target.classList.contains("dark") ? "dark" : "light");
    });

    observer.observe(target, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  const themeConfig = React.useMemo(() => {
    const algorithm = mode === "dark" ? [antdTheme.darkAlgorithm] : [antdTheme.defaultAlgorithm];
    const token = mode === "dark" ? DARK_TOKENS : LIGHT_TOKENS;

    return {
      algorithm,
      token,
      components: {
        Layout: {
          bodyBg: "transparent",
          headerBg: "transparent",
          footerBg: "transparent",
        },
        Menu: {
          itemSelectedColor: token.colorPrimary,
        },
      },
    } as const;
  }, [mode]);

  return (
    <ConfigProvider theme={themeConfig} componentSize="middle">
      {children}
    </ConfigProvider>
  );
}

export default AppThemeProvider;
