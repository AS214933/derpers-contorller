import type { DERPNode } from "./types";

export function nodeControls(node: Pick<DERPNode, "enabled" | "published">) {
  const inMap = node.enabled && node.published;
  return {
    inMap,
    canQueueTasks: node.enabled,
    publication: !node.enabled
      ? node.published
        ? "已停用 · Map 已排除"
        : "已停用"
      : inMap
        ? "已发布到 Map"
        : "未发布",
  };
}

export function deploymentDirectory(nodeID: string): string {
  const id = nodeID.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 32) || "node";
  return `/opt/derpers/${id}`;
}
export function deploymentEnvironment(nodeID: string, token: string): string {
  return `# 与下载的 compose.yaml 放在同一目录，保存为 node.env\nNODE_DIR=${deploymentDirectory(nodeID)}\nENROLLMENT_TOKEN=${token}\n# 公共可信控制器证书保留为空；私有 CA 使用 /trust/controller-ca.crt\nTRUST_DIR=./trust\nCONTROLLER_CA_FILE=\n`;
}
export function deploymentCommands(nodeID: string): string {
  const dir = deploymentDirectory(nodeID);
  return `# 在节点主机进入存放 compose.yaml 和 node.env 的目录\n# 使用具备 Docker 及目标目录写入权限的账户\nmkdir -p ${dir}/agent ${dir}/config ./trust\n# 先验证，--quiet 不输出渲染后的秘密\ndocker compose --env-file node.env -f compose.yaml config --quiet\ndocker compose --env-file node.env -f compose.yaml up -d\n`;
}
