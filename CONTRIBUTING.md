# 贡献与提交约定

提交消息和 PR 标题采用 Conventional Commits：

```text
type(scope): concise description
```

- `feat`：新增功能；`fix`：修复错误；`docs`：文档；`test`：测试；`ci`：GitHub Actions；`build`：构建与依赖；`refactor`：不改变行为的重构；`chore`：维护。
- scope 按改动范围选用，例如 `controller`、`agent`、`web`、`dns`、`build`、`e2e`；跨模块变更可以省略。
- 标题使用简洁英文、动词原形，不加结尾句号，控制在 72 个字符以内。
- 一次提交表达一个完整意图。互不相关的构建修复、功能和文档分开提交；对应测试与实现一起提交。
- 复杂变更在正文说明问题、改变的行为及验证结果。破坏兼容性的变更使用 `!`，并在正文提供 `BREAKING CHANGE:` 和迁移步骤。
- PR 标题遵守同一格式；描述说明最终变更和实际验证结果。合并前确认 squash 后的提交标题也符合约定。

示例：

```text
feat(controller): support multiple Headscale authorization sources
fix(build): pin the commit behind the Tailscale release tag
fix(dns): serialize node provisioning and record ownership changes
test(e2e): reject clients during verification transport failures
docs: document certificate and DNS recovery procedures
```

提交前运行与改动有关的检查。Go 使用 `gofmt`、`go vet ./...` 和 `go test ./...`；网页在 `web/` 执行 `npm test` 和 `npm run build`。数据库集成测试通过 `TEST_DATABASE_URL` 连接测试 PostgreSQL，每个用例使用独立 schema。

镜像和中继改动须由 GitHub Actions 的原生双架构、双端口真实 E2E 验证。构建成功、协议探针成功或单元测试通过，均不能替代真实中继测试。
