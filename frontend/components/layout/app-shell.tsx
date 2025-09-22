"use client";

import React from "react";
import { Layout } from "antd";

const { Header, Sider, Content, Footer } = Layout;

interface AppShellProps {
  header?: React.ReactNode;
  sider?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
}

export function AppShell({ header, sider, footer, children }: AppShellProps) {
  return (
    <Layout className="min-h-screen">
      {header ? <Header className="px-4 lg:px-6">{header}</Header> : null}
      <Layout>
        {sider ? (
          <Sider
            width={240}
            theme="light"
            breakpoint="lg"
            collapsedWidth={0}
            className="border-r border-border"
          >
            {sider}
          </Sider>
        ) : null}
        <Content className="px-4 py-6 lg:px-6">
          {children}
        </Content>
      </Layout>
      {footer ? <Footer className="px-4 py-4 border-t border-border">{footer}</Footer> : null}
    </Layout>
  );
}

export default AppShell;
