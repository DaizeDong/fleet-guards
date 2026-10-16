# fleet-guards

Git 仓库共用的发布检查套件，提供九条检测规则、数据边界和检查缺失时阻断操作的钩子。每台机器只放一份本地 checkout，消费仓用两个很小的钩子转发脚本接入。

Python 消费方通过[已安装的运行时包](PACKAGE.md)取得伴生仓解析和存储契约。

[![守卫套件](https://img.shields.io/badge/%E5%AE%88%E5%8D%AB%E5%A5%97%E4%BB%B6-%E6%9C%AC%E5%9C%B0%20checkout-orange?style=flat)](#安装)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![检测规则](https://img.shields.io/badge/%E6%A3%80%E6%B5%8B%E8%A7%84%E5%88%99-9-green?style=flat)](#里面有什么)
[![语言](https://img.shields.io/badge/%E8%AF%AD%E8%A8%80-EN%20%2F%20CN-blue?style=flat)](#语言)
[![Roadmap](https://img.shields.io/badge/Roadmap-v0.1.0-purple?style=flat)](ROADMAP.md)

[English](README.md) | [中文版](README_CN.md)

---

## ⭐ 先读这里, 设计理念

这套工具结合存储边界、标识符扫描和明确的失败报告。

**真实产出与公开源码分离。** 2026-07 的审计发现，仓内相对输出路径把真实运行记录写进了公开仓。记录即使不含邮箱或电话，也可能包含私有事实，因此内容扫描只能补充存储边界。每个路径必须在 `.dataclass.json` 中分类，真实产出存入独立的 PRIVATE 伴生仓。

**只放行声明的合成标识符。** 结构规则检查合成命名空间之外的标识符，私有词表补充扫描器无法推断的名称。公开扫描器不携带私有标识符，私有词表保留在公开仓之外。

**检查不完整时失败。** 套件 checkout 缺失、`fleet.guards` 没设、声明不存在或 Git 读取失败，都必须阻断对应检查。报告应区分“检查完成且没有发现”和“没有完成检查”。

## 它是什么（不是什么）

它是舰队的安全套件：扫描器、数据边界、伴生仓解析器和 git 钩子。每台机器一份 checkout，位置由全局 git 配置项 `fleet.guards` 指定。只有用 `.githooks/` 转发脚本接入的仓库才被检查，没有机器级钩子，也没有 CI 步骤。

九条检测规则，由五个工具里的 38 条正则实现。它们实际挡的是：

| 规则 | 说人话 |
|---|---|
| PERSONAL-MAILBOX | 即将公开的东西里出现了真实私人邮箱 |
| EMAIL | 任何不属于已声明合成命名空间的地址 |
| PHONE | 一个 NANP 电话号码 |
| ZIP | 出现在收货或地址词附近的邮编 |
| USER-PATH | 带着机主用户名的机器路径 |
| PRIVATE-PATH | 只存在于维护者机器上的路径 |
| AUTHOR-EMAIL | 这次提交即将签上的身份 |
| CROSS-REPO | 一个仓点名了另一个仓的私有伴生仓 |
| DENYLIST | 任何结构规则都推不出来的手工私有词 |

此外还有 13 条识别真实运行产出的文件名模式、四个误报抑制器，以及十二个不承担任何安全职责的纯文本辅助函数。

本仓是 Git 钩子工具，没有 Claude Code skill 或 plugin 入口。文风和加载预算脚本由 `fleet-style` 维护。

## 安装

每台机器一次：

    git clone https://github.com/DaizeDong/fleet-guards.git <path>
    git config --global fleet.guards <path>        # 用正斜杠，例如 C:/src/fleet-guards
    pip install -e "$(git config --get fleet.guards)"

这份 checkout 始终停在 `main`。改套件在它的 `git worktree` 里改，钩子运行的那份 checkout 就永远不会处在改了一半的状态。合并前想用 worktree 里的钩子试一次，只对单条命令覆盖这个配置项：`git -c fleet.guards=<worktree> commit ...`。

## 让一个仓库接入

提交两个转发脚本，并让仓库的钩子指向它们：

    git config core.hooksPath .githooks
    git update-index --chmod=+x .githooks/pre-commit .githooks/pre-push

`.githooks/pre-commit`：

```sh
#!/bin/sh
# Privacy checks run from the local fleet-guards checkout named by git config fleet.guards.
G=$(git config --get fleet.guards)
if [ -z "$G" ] || [ ! -s "$G/hooks/pre-commit" ]; then
  echo "BLOCKED: git config fleet.guards is unset or has no hooks/pre-commit; nothing was checked." >&2
  exit 1
fi
exec sh "$G/hooks/pre-commit" "$@"
```

`.githooks/pre-push` 与之相同，两处都换成 `hooks/pre-push`。同时使用 `fleet-style` 破折号检查的仓库，在 `exec` 之前加上那一段（见 fleet-style 的 README）。

转发脚本用普通的 `git config --get` 读 `fleet.guards`，所以 `git -c fleet.guards=...` 能覆盖它。配置项没设，或者 checkout 里没有对应钩子，一律拦下；没有任何备用位置。

用 Git LFS 的仓库必须在 `.githooks/` 的转发脚本里自己调 LFS 的钩子（pre-push 里在 `exec` 之前加 `git lfs pre-push "$@"`，另加对应的 post-checkout、post-commit、post-merge 转发脚本），因为 `core.hooksPath=.githooks` 替换掉了 `git lfs install` 放钩子的那个目录。

每个仓库保留自己的 `.pii-allow` 和 `.dataclass.json`：哪些发现可豁免、哪些路径是 TOOL、FIXTURE 或 DATA，是关于那个仓库的事实。

## 实际跑什么

`hooks/pre-commit` 承载两个阶段的逻辑，`hooks/pre-push` 只是带 `--phase pre-push` 重新执行它。

- **提交：** 先对照 `~/.pii-guard/identities.conf` 断言提交身份，再跑 `publication_guard.py pre-commit`，它执行 `pii_guard.py --staged`（只扫这次要提交的内容）和 `data_boundary.py`。
- **推送：** `publication_guard.py pre-push`，执行 `pii_guard.py --tree --history` 和 `data_boundary.py`。只删除 ref 的推送不发布任何内容，直接跳过。

两者都直接调用 `python`，解释器缺失或不可用时返回非零，即被拦下。

[发布策略](docs/PUBLICATION_POLICY.md)决定范围：只有当前证据证明全部物理及生效 fetch/push 目标均为 PRIVATE，才允许私有内容；证据缺失时继续执行公开策略。PRIVATE 仓仍检查声明、schema、fixture、路径和提交身份。直接运行 `pii_guard.py --tree --history` 或 `data_boundary.py` 始终采用公开策略。伴生仓准入、证据有效期和传输要求见 [COMPANION.md](COMPANION.md#verifying-a-companion)。

## 里面有什么

| 路径 | 是什么 |
| --- | --- |
| `tools/pii_guard.py` | 扫描器。基于白名单，结构化，可以扫暂存区、工作树或完整历史。 |
| `tools/data_boundary.py` | 检查路径分类、fixture 和真实产出边界。 |
| `tools/publication_guard.py` | 根据已证明的仓库可见性选择提交和推送策略。 |
| `tools/datadir.py` | 解析器。决定真实运行产出往哪写，而答案永远在仓库之外。 |
| `tools/storage_contract.py` | 校验伴生仓的 `storage.contract.json` 和路径归属。 |
| `fleet_guards/` | 安装的 Python 包；`fleet_guards.runtime` 暴露解析器和存储契约。 |
| `hooks/` | `pre-commit`（两个阶段）与 `pre-push`（重新执行前者），消费仓的转发脚本最终 exec 进来的本体。 |
| `.githooks/` | 本仓自己的接入转发脚本。 |
| `COMPANION.md` | 公开仓与私有伴生仓之间的契约。 |

## 输出示例

```
$ python tools/pii_guard.py --tree
pii_guard: clean (tree)  [28 file(s) scanned, 0 skipped]

$ python tools/data_boundary.py
data_boundary: clean (0 DATA + 0 sealed paths not tracked, 0 FIXTUREs generator-reproducible,
28 tracked files carry no real-run shape)
```

报告列出实际检查和排除数量，用于判断覆盖范围；空扫描或未完成扫描不能作为通过证据。

## 在 Windows 上起进程

套件起的每一个进程都经过 `_no_window()`。没有控制台的进程（`pythonw`、计划任务、服务）启动控制台程序时，Windows 会弹出一个窗口。这个辅助函数只在调用方没有控制台时才加 `CREATE_NO_WINDOW`，所以钩子未重定向的输出不会被藏起来；它拒绝 `DETACHED_PROCESS` 和 `CREATE_NEW_CONSOLE`。每个工具文件各带一份副本，因为这些工具是按路径一个文件一个文件加载的。

## 局限

pre-commit 框架会拒绝安装：`pre-commit install` 打印 "Cowardly refusing to install hooks with `core.hooksPath` set"，并建议你去掉那个设置。照它说的做，你会得到一个能用的格式化器和零闸门。改为在 `.githooks/pre-commit` 转发脚本的 `exec` 之前调 `pre-commit run`，这样会重写文件的格式化器没法把改动绕过扫描。

**散文中的私有事实仍是缺口。** DATA 不在公开源码中，可以避免把这些文件误带进产物。结构规则识别标识符，私有词表识别已配置名称，但它们不能证明一段文字没有泄露私事。公开示例必须使用合成数据。

## 语言

English (`README.md`) · 中文 (`README_CN.md`)

## Roadmap · Contributing · License

见 [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) · [COMPANION.md](COMPANION.md)。
