import { describe, expect, it } from "vitest";
import {
  deploymentCommands,
  deploymentDirectory,
  deploymentEnvironment,
  nodeControls,
} from "./node-admin";

describe("disabled nodes cannot be advertised or newly queued for remote actions", () => {
  it("excludes a disabled node even when the saved publication flag is true", () => {
    expect(nodeControls({ enabled: false, published: true })).toEqual({
      inMap: false,
      canQueueTasks: false,
      publication: "已停用 · Map 已排除",
    });
  });
  it("distinguishes an enabled unpublished node from an active published node", () => {
    expect(nodeControls({ enabled: true, published: false })).toMatchObject({
      inMap: false,
      canQueueTasks: true,
      publication: "未发布",
    });
    expect(nodeControls({ enabled: true, published: true })).toMatchObject({
      inMap: true,
      canQueueTasks: true,
    });
  });
});
describe("downloaded node deployment instructions", () => {
  it("supplies an absolute NODE_DIR matching the generated Compose variables", () => {
    const env = deploymentEnvironment("abc123", "short-lived-token");
    expect(env).toContain("NODE_DIR=/opt/derpers/abc123\n");
    expect(env).toContain("ENROLLMENT_TOKEN=short-lived-token\n");
    expect(env).toContain("CONTROLLER_CA_FILE=\n");
    const commands = deploymentCommands("abc123");
    expect(commands).toContain(
      "mkdir -p /opt/derpers/abc123/agent /opt/derpers/abc123/config ./trust",
    );
    expect(commands).toContain(
      "--env-file node.env -f compose.yaml config --quiet",
    );
    expect(commands).toContain("--env-file node.env -f compose.yaml up -d");
    expect(commands).not.toContain("short-lived-token");
  });
  it("keeps displayed shell paths safe and separate for each node", () => {
    expect(deploymentDirectory("one")).not.toBe(deploymentDirectory("two"));
    expect(deploymentDirectory("../../node;$(command)")).toMatch(
      /^\/opt\/derpers\/[a-zA-Z0-9_-]+$/,
    );
  });
});
