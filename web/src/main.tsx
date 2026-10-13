import React from "react";
import ReactDOM from "react-dom/client";
import { App as AntApp, ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: "#3263e7",
          colorInfo: "#3263e7",
          colorSuccess: "#139a72",
          colorWarning: "#c78419",
          colorError: "#d74c56",
          borderRadius: 9,
          fontFamily:
            '-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif',
          colorBgLayout: "#f4f6fa",
        },
        components: {
          Table: { headerBg: "#f8fafc", headerColor: "#66728a" },
          Button: { fontWeight: 500 },
          Layout: { siderBg: "#0b1529" },
        },
      }}
    >
      <AntApp>
        <App />
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
);
