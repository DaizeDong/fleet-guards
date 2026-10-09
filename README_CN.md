# fleet-guards

Git 仓库共用的发布检查套件，提供九条检测规则、数据边界和检查缺失时阻断操作的钩子。消费仓通过 Git submodule 固定使用的版本。

Python 消费方可构建[共享文件系统、凭据检查与运行时包](PACKAGE.md)。包版本 0.2.1 将现有
解析器与 PRIVATE 准入实现映射进 wheel；消费方显式提供自己的根目录，源码里只保留一份实现。

[![守卫套件](https://img.shields.io/badge/%E5%AE%88%E5%8D%AB%E5%A5%97%E4%BB%B6-Git%20%E5%AD%90%E6%A8%A1%E5%9D%97-orange?style=flat)](#安装)
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

**检查不完整时失败。** 扫描器缺失、子模块为空、声明不存在或 Git 读取失败，都必须阻断对应检查。报告应区分“检查完成且没有发现”和“没有完成检查”。

## 它是什么（不是什么）

它是舰队的安全套件：扫描器、数据边界、伴生仓解析器、它们的测试、两个 git 钩子，以及一个 composite
CI action，由其他仓库以 submodule 形式挂在 `guards/` 上消费。

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

此外还有 13 条识别真实运行产出的文件名模式、四个误报抑制器，以及十二个不承担任何安全职责的纯文本
辅助函数。

本仓通过 Git/CI 使用，没有 Claude Code skill 或 plugin 入口。文风和加载预算检查由 `fleet-style` 维护；最初拆出的 `dash_guard` 和 `load_budget` 占当时套件的 17.5%。本子模块必须保持公开，确保公开消费仓能在 CI 中获取。

旧部署把 17 个文件、每套 7,643 行复制到 22 个消费仓，历史清单记录磁盘上约有 191,000 行。安装器依赖人工维护的仓库列表；2026-08-31 的审计发现，两个遗漏的公开仓仍使用 fail-open pre-push 钩子。现在每个消费仓用自身版本历史中的 submodule 指针声明依赖。

## 安装

    git submodule add -b main https://github.com/DaizeDong/fleet-guards.git guards
    git config core.hooksPath .githooks

安装时必须一并提交 fail-closed 的 `.githooks/pre-commit` 和 `.githooks/pre-push` 转发脚本。转发脚本
必须在 `guards/hooks/<hook>` 缺失时停住，存在时再 exec 过去。让 git 直接指向一个空的 submodule 会静
默地关掉闸门；被提交进来的转发脚本，正是察觉「克隆不完整」的那个东西。

如果还要保留机器级的提交说明检查，可按[英文安装说明](README.md#install)增加可选的
`.githooks/commit-msg` 转发脚本，并用 `git add --chmod=+x .githooks/commit-msg` 设置可执行位。
`core.hooksPath` 仍指向 `.githooks`；套件会查询 Git 的全局钩子目录，并原样返回检查结果。

伴生仓检查只加载目标仓已登记的 fleet-guards 子模块中的解析器，支持自定义子模块路径。
独立部署应运行该仓自己的 `tools/data_boundary.py`，也可用 `--companion-dir` 明确指定数据目录。
子模块或解析器缺失时检查会失败，不会转去加载消费仓里遗留的副本。

`.gitmodules` 使用 HTTPS URL，确保其他机器和 CI 可以解析。首次迁移使用本机 SSH 主机别名，导致三个 workflow 均以 "Could not read from remote repository" 失败。

克隆时带 `--recursive`，或者事后补 `git submodule update --init`。CI 必须在 `actions/checkout` 上设
`submodules: true`。

## 快速上手

一个消费仓的整个 workflow 就是 checkout、python，加一行：

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # 扫历史才是重点；浅克隆等于什么都没扫
          submodules: true
      - uses: actions/setup-python@v5
      - uses: ./guards/ci/pii-guard
```

在消费仓根目录手工跑同样这几项：

```bash
python guards/tools/publication_guard.py ci
python guards/tools/test_companion_contract.py
```

常规钩子和 CI 使用[发布策略](docs/PUBLICATION_POLICY.md)：只有当前证据证明全部物理及生效 fetch/push 目标均为 PRIVATE，才允许私有内容；证据缺失时继续执行公开策略。PRIVATE 仓仍检查声明、schema、fixture、路径和提交身份。直接运行 `pii_guard.py --tree --history` 或 `data_boundary.py` 始终采用公开策略。伴生仓准入、证据有效期和传输要求见 [COMPANION.md](COMPANION.md#verifying-a-companion)。

## 里面有什么

| 路径 | 是什么 |
| --- | --- |
| `tools/pii_guard.py` | 扫描器。基于白名单，结构化，跑工作树也跑完整历史。 |
| `tools/data_boundary.py` | 检查路径分类、fixture 和真实产出边界。 |
| `tools/publication_guard.py` | 根据已证明的仓库可见性选择常规钩子和 CI 策略。 |
| `tools/datadir.py` | 解析器。决定真实运行产出往哪写，而答案永远在仓库之外。 |
| `tools/fleet_sync.py` | 分发已验证的上游更新，并推进各消费仓的 gitlink。 |
| `tools/test_*.py` | 套件自己的测试，含那一层私有部分在 runner 上永远不存在的策略层。 |
| `hooks/` | `pre-commit` 与 `pre-push`，消费仓的转发脚本最终 exec 进来的本体。 |
| `ci/pii-guard/action.yml` | 每个消费仓按本地路径引用的 composite action。 |
| `templates/fleet-sync.yml` | 消费仓为接入自动同步而拷走的那一个 workflow。 |
| `templates/upstream-notify.yml` | 自定义上游（包括私有仓）拷走、用来通知自己那批消费仓的 workflow。 |
| `COMPANION.md` | 公开仓与私有伴生仓之间的契约，由一个测试对着解析器逐条核对。 |
| `docs/AUTOMATIC_SYNC.md` | 消费仓怎么接入，以及分发路径为什么长这样。 |

## 怎么更新一个消费仓

    git submodule update --remote guards
    git add guards && git commit -m "guards: bump"

一个 submodule 钉住一个 commit。消费仓可以用上面的命令手工更新，也可以接入
[自动同步](docs/AUTOMATIC_SYNC.md)。接入之后，上游检查通过就会发出一个 dispatch 事件，消费仓在自己的
默认分支上记录一次普通的 gitlink 更新提交。它自己的提交闸门和 CI 照常运行。同一条路径也能跟随别的仓库，私有仓
也行，按声明的分支和检查 workflow 来；见[私有或自定义上游](docs/AUTOMATIC_SYNC.md#private-or-custom-upstreams)。

## 输出示例

```
$ python tools/pii_guard.py --tree
pii_guard: clean (tree)  [28 file(s) scanned, 0 skipped]

$ python tools/data_boundary.py
data_boundary: clean (0 DATA + 0 sealed paths not tracked, 0 FIXTUREs generator-reproducible,
28 tracked files carry no real-run shape)
```

报告列出实际检查和排除数量，用于判断覆盖范围；空扫描或未完成扫描不能作为通过证据。

## 必须知道的那个失效形态

不带 `--recursive` 的普通 `git clone` 会留下一个空的 `guards/`。不设 `submodules: true` 的 CI checkout
同理。钩子对缺失的扫描器是 fail closed 的，所以这种状态会大声拦住提交，而不是静默放行，这也是整套安排
唯一安全的理由。任何时候看到 guards 目录是空的，答案都是 `git submodule update --init`，永远不是
`--no-verify`。

## 在 Windows 上起进程

套件起的每一个进程都经过 `_no_window()`，任何绕过它的 `subprocess` 调用、`os.system`、`os.popen` 或进程池，
都会让 `tools/test_no_console_window.py` 失败。理由是实测出来的，不是推演的：一个自己没有控制台的进程
（`pythonw`、计划任务、服务）启动控制台程序时，子进程会拿到一个新控制台，而 Windows 会把它显示成一个窗口。
一个在每行日志都去证明私有伴生仓的守护进程，每次证明跑大约 19 条 git 命令，八小时里弹出了约 9,000 个终端窗口。

这个辅助函数只在调用方没有控制台时才加 `CREATE_NO_WINDOW`。有控制台时，子进程共用它，什么都不会弹出；
这时再加这个标志，反而会把子进程没有重定向的输出和终端提示挪进一个隐藏控制台，钩子的发现就没人看得到了。
它拒绝 `DETACHED_PROCESS`，因为 Windows 在它旁边会忽略 `CREATE_NO_WINDOW`，没有控制台的子进程再起的子进程
又会弹窗；也拒绝 `CREATE_NEW_CONSOLE`，那本身就是一个窗口。每个工具文件各带一份副本，因为消费仓是按路径
一个文件一个文件加载的；同一个测试保证每份副本完全一致。

## 局限

以下兼容性结论来自一个消费仓的检查，不能代表所有消费方配置。

pre-commit 框架会拒绝安装：`pre-commit install` 打印 "Cowardly refusing to install hooks with
`core.hooksPath` set"，并建议你去掉那个设置。照它说的做，你会得到一个能用的格式化器和零闸门。
`.githooks/` 里的转发脚本会在配置和二进制都在时自己去调 `pre-commit run`，所以两者都跑，而闸门排在最
后：一个会重写文件的格式化器没法把改动绕过扫描。

该次检查通过了 ruff 默认规则；更严格的配置报告了 155 条把 %-格式化改成 f-string 的建议。消费仓使用自己的 lint 策略时，可用 `extend-exclude = ["guards", "style"]` 排除子模块。

你自己那个同名模块会赢。当仓库自己的目录排在 `sys.path` 前面时，`import datadir` 解析到的是仓库自己那
份，不是套件这份。根目录的 `conftest.py` 同样赢过这里的那份。反过来只会在你把套件路径排到前面时发生，
那是一个选择，不是默认。

该次消费仓检查中，新增顶层 package 和测试正常收集，`find_packages()` 不收集子模块，根目录 `pytest` 不收集套件测试，而显式 `pytest guards/tools/` 会收集。`pytest.ini` 的 `testpaths` 没有改变结果，测试结束后子模块保持 clean。

**散文中的私有事实仍是缺口。** DATA 不在公开源码中，可以避免把这些文件误带进产物。结构规则识别标识符，私有词表识别已配置名称，但它们不能证明一段文字没有泄露私事。公开示例必须使用合成数据。

## 语言

English (`README.md`) · 中文 (`README_CN.md`)

## Roadmap · Contributing · License

见 [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) · [COMPANION.md](COMPANION.md)。

与本仓规范之间的每一处偏离及其理由，记录在
[docs/2026-09-22-spec-adaptation.md](docs/2026-09-22-spec-adaptation.md)。
