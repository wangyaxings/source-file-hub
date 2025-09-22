"use client";

import React from "react";
import { useServerInsertedHTML } from "next/navigation";
import { StyleProvider, createCache, extractStyle } from "@ant-design/cssinjs";

interface AntdRegistryProps {
  children: React.ReactNode;
}

export function AntdRegistry({ children }: AntdRegistryProps) {
  const [cache] = React.useState(() => createCache());

  useServerInsertedHTML(() => (
    <style
      id="antd"
      dangerouslySetInnerHTML={{ __html: extractStyle(cache, true) }}
    />
  ));

  return (
    <StyleProvider cache={cache} hashPriority="high">
      {children}
    </StyleProvider>
  );
}

export default AntdRegistry;
