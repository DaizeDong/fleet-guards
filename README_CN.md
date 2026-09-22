# fleet-guards

这个舰队的闸门套件，集中在一个仓库里，以 git submodule 的形式被消费：九条检测规则、一道数据边界，以及一组在自己缺席时拒绝放行的钩子。

[![守卫套件](https://img.shields.io/badge/%E5%AE%88%E5%8D%AB%E5%A5%97%E4%BB%B6-Git%20%E5%AD%90%E6%A8%A1%E5%9D%97-orange?style=flat)](#安装)
[![检测规则](https://img.shields.io/badge/%E6%A3%80%E6%B5%8B%E8%A7%84%E5%88%99-9-green?style=flat)](#里面有什么)
[![语言](https://img.shields.io/badge/%E8%AF%AD%E8%A8%80-EN%20%2F%20CN-blue?style=flat)](#语言)
[![Roadmap](https://img.shields.io/badge/Roadmap-v0.1.0-purple?style=flat)](ROADMAP.md)

[English](README.md) | [中文版](README_CN.md)

---

## ⭐ 先读这里, 设计理念

有三条承诺贯穿全仓，它们比规则清单更值得先看。

**出口处的筛子拦不住一根对着它的管子。** `pii_guard` 读的是即将发布出去的内容，把闻着像私事的东
西标出来。那是兜底，不是主控制。2026-07 的审计查出公开仓里装着真实运行产出，而且不是谁手工粘进
去的，是 skill 自己天天写进去的，按设计写：一份决策账本、一份购买记录、一份活动日志。一条带进场
价的持仓记录里没有地址也没有电话，内容扫描器根本无从闻起。所以主控制是结构性的：每个路径必属
`.dataclass.json` 里声明的某一类，凡是真实运行产出的东西都住在私有伴生仓里，在公开仓中物理上不
存在。

**用白名单，因为黑名单是由泄漏的那个人写的。** 一份手工列出的禁词表，只能挡住作者本来就想得到的
那些；而一个装满真实标识符的文件，本身就是你想避免发布的那份文档。所以扫描器标记的是：一切长得
像真实世界标识符、又不属于已声明的合成命名空间的东西，包括谁都没预料到的供应商。它里面没有任何
私有数据，可以放心公开。私有词表只待在一台机器上，永远不进任何仓库。

**缺席是失败，不是跳过的理由。** 凡是「某项检查有可能缺席」的状态，一律判为拦截：submodule 目录
空着、扫描器文件不在、`.dataclass.json` 压根没写、git 命令执行失败而不是列出了零个文件。一个包在
`if [ -f ... ]` 里的步骤，会在文件缺失时从报告里整条消失，而一份少了一行的报告，读起来跟全都通过
的报告一模一样。「干净」和「根本没查」必须是两种不同的输出。

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

它**不是** Claude Code 的 skill 或 plugin，也不带 `SKILL.md`：这里没有任何东西会被 agent 调用。它
**不是**文风套件，纯属文风与架构的那两道闸门，`dash_guard` 和 `load_budget`，住在 `fleet-style`：
它们占这个仓 17.5% 的行数，而其中没有一行是在阻止某个标识符进入公开历史。它**不是**私有仓，也绝不
能变成私有仓：一个私有 submodule 会让每一个公开消费者的 CI 当场挂掉。

在这个仓存在之前，套件是手工拷进每一个消费仓的：17 个文件、7,643 行，乘以 22 个仓，磁盘上约 191,000
行。那些拷贝是逐字节相同的，一个安装器就能把它们全部重新同步，所以重复本身并不是代价。真正的代价
是：安装器依据的是一份手写的仓库清单，而一个不在清单里的仓，用安装器自己的话说，得到的是「一道
闸门的样子，和零维护」。两个公开仓正是因为这个原因长期挂着一个 fail open 的 pre-push 钩子，2026-08-31
查出。submodule 把那份清单换成了一个住在消费仓自己身上的指针。

## 安装

    git submodule add -b main https://github.com/DaizeDong/fleet-guards.git guards
    git config core.hooksPath .githooks

安装时必须一并提交 fail-closed 的 `.githooks/pre-commit` 和 `.githooks/pre-push` 转发脚本。转发脚本
必须在 `guards/hooks/<hook>` 缺失时停住，存在时再 exec 过去。让 git 直接指向一个空的 submodule 会静
默地关掉闸门；被提交进来的转发脚本，正是察觉「克隆不完整」的那个东西。

一定要用 HTTPS URL，不要用 ssh 主机别名。`.gitmodules` 是提交并共享的，所以这个 url 必须对每一个克隆
者都能解析，包括 CI runner。第一次迁移用了本机 ssh 别名，三个 workflow 全部当场以 "Could not read from
remote repository" 失败。

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
python guards/tools/pii_guard.py --tree --history
python guards/tools/data_boundary.py
python guards/tools/test_companion_contract.py
```

## 里面有什么

| 路径 | 是什么 |
| --- | --- |
| `tools/pii_guard.py` | 扫描器。基于白名单，结构化，跑工作树也跑完整历史。 |
| `tools/data_boundary.py` | 主控制。问的是：这个仓是一件未初始化的工具，还是装着某个人的人生。 |
| `tools/datadir.py` | 解析器。决定真实运行产出往哪写，而答案永远在仓库之外。 |
| `tools/fleet_sync.py` | 分发已验证的上游更新，并推进各消费仓的 gitlink。 |
| `tools/test_*.py` | 套件自己的测试，含那一层私有部分在 runner 上永远不存在的策略层。 |
| `hooks/` | `pre-commit` 与 `pre-push`，消费仓的转发脚本最终 exec 进来的本体。 |
| `ci/pii-guard/action.yml` | 每个消费仓按本地路径引用的 composite action。 |
| `templates/fleet-sync.yml` | 消费仓为接入自动同步而拷走的那一个 workflow。 |
| `COMPANION.md` | 公开仓与私有伴生仓之间的契约，由一个测试对着解析器逐条核对。 |
| `docs/AUTOMATIC_SYNC.md` | 消费仓怎么接入，以及分发路径为什么长这样。 |

## 怎么更新一个消费仓

    git submodule update --remote guards
    git add guards && git commit -m "guards: bump"

一个 submodule 钉住一个 commit。消费仓可以用上面的命令手工更新，也可以接入
[自动同步](docs/AUTOMATIC_SYNC.md)。接入之后，上游检查通过就会发出一个 dispatch 事件，消费仓在自己的
默认分支上记录一次普通的 gitlink 更新提交。它自己的提交闸门和 CI 照常运行。

## 输出示例

```
$ python tools/pii_guard.py --tree
pii_guard: clean (tree)  [28 file(s) scanned, 0 skipped]

$ python tools/data_boundary.py
data_boundary: clean (0 DATA + 0 sealed paths not tracked, 0 FIXTUREs generator-reproducible,
28 tracked files carry no real-run shape)
```

两个都打印一个计数，而计数正是重点。一份「什么都没扫」的 clean，正是这个套件花了大部分行数在防的那
件事。

## 必须知道的那个失效形态

不带 `--recursive` 的普通 `git clone` 会留下一个空的 `guards/`。不设 `submodules: true` 的 CI checkout
同理。钩子对缺失的扫描器是 fail closed 的，所以这种状态会大声拦住提交，而不是静默放行，这也是整套安排
唯一安全的理由。任何时候看到 guards 目录是空的，答案都是 `git submodule update --init`，永远不是
`--no-verify`。

## 局限

**装上这个 submodule 之后，有四件事的行为会变。** 这是在一个真实消费仓上实测的，不是推演的，而且只有
一件会真的挡住你。

pre-commit 框架会拒绝安装：`pre-commit install` 打印 "Cowardly refusing to install hooks with
`core.hooksPath` set"，并建议你去掉那个设置。照它说的做，你会得到一个能用的格式化器和零闸门。
`.githooks/` 里的转发脚本会在配置和二进制都在时自己去调 `pre-commit run`，所以两者都跑，而闸门排在最
后：一个会重写文件的格式化器没法把改动绕过扫描。

有人拿 linter 走进来。这套件在 ruff 默认规则下是干净的。在一套更强硬的规则下则不干净，也不可能干净：
那个级别下有 155 条发现是「把 %-格式化改写成 f-string」，散落在一个扫描器里，而这种改动买不到任何正确
性。要开就用 `extend-exclude = ["guards", "style"]` 把 submodule 排除掉。

你自己那个同名模块会赢。当仓库自己的目录排在 `sys.path` 前面时，`import datadir` 解析到的是仓库自己那
份，不是套件这份。根目录的 `conftest.py` 同样赢过这里的那份。反过来只会在你把套件路径排到前面时发生，
那是一个选择，不是默认。

其余的都查过，都是非事件：新增的顶层 package 和它的测试照常被收集，`find_packages()` 从 submodule 里返
回零个包，根目录跑 `pytest` 不会把套件的测试卷进来（`pytest guards/tools/` 仍然照跑，这是刻意的），带
`testpaths` 的 `pytest.ini` 在这里什么都不改，测试跑完 submodule 也从不显示为 dirty。

**这套件关不掉的是什么。** 边界让 agent 抄不到真实文件，因为手边根本没有真实文件。结构规则认形状，私
有词表认名字。这三者都认不出「没点名任何标识符、却泄露了一件私事」的散文。那一件背后没有任何机制，只
有一条规则：永远不要用真实的例子。

## 语言

English (`README.md`) · 中文 (`README_CN.md`)

## Roadmap · Contributing · License

见 [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) · [COMPANION.md](COMPANION.md)。

与本仓规范之间的每一处偏离及其理由，记录在
[docs/2026-09-22-spec-adaptation.md](docs/2026-09-22-spec-adaptation.md)。
