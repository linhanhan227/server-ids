"""命令行接口。

子命令::

    irtrace run        执行完整流水线 (采集 -> 分析 -> 报告)
    irtrace collect    仅执行采集
    irtrace analyze    仅执行分析 (需先有采集产物, 见 --run-dir)
    irtrace list       列出已注册插件
    irtrace verify     校验证据哈希链完整性
    irtrace doctor     环境自检 (权限、依赖命令、可用采集器)
    irtrace intel      威胁情报平台管理 (list / check / cache)
    irtrace web        启动 Web 可视化控制台 (只读)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from irtrace import __version__
from irtrace.settings import load_settings
from irtrace.core.context import RunContext
from irtrace.core.pipeline import Orchestrator
from irtrace.core.registry import registry

logger = logging.getLogger("irtrace")


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="irtrace",
        description="Linux 服务器入侵溯源检测框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "通用选项示例:\n"
            "  irtrace run --format json markdown html     # 推荐: 选项置于子命令之后\n"
            "  irtrace -w /opt/irtrace doctor              # 单值选项亦可置于子命令之前\n"
            "\n"
            "注意: --format / --only / --skip 支持多值, 若置于子命令之前会\n"
            "      连同子命令名一起被吞掉, 请务必写在子命令之后。\n"
        ),
    )
    p.add_argument("-V", "--version", action="version", version=f"irtrace {__version__}")
    _add_common_options(p, sub=False)

    sub = p.add_subparsers(dest="command")

    # 子命令同样接受通用选项, 使 `irtrace run --format json` 与
    # `irtrace --format json run` 两种写法均可用。
    for name, help_text in (
        ("run", "执行完整流水线"),
        ("collect", "仅采集"),
        ("list", "列出已注册插件"),
        ("doctor", "环境自检"),
    ):
        _add_common_options(sub.add_parser(name, help=help_text), sub=True)

    az = sub.add_parser("analyze", help="对已有 run 重跑分析与报告")
    _add_common_options(az, sub=True)
    az.add_argument("--run-dir", default=None,
                    help="已有 runs/<id> 目录; 从其中 result.json 还原事件后重分析")

    v = sub.add_parser("verify", help="校验证据哈希链")
    _add_common_options(v, sub=True)
    v.add_argument("run_dir", help="run 目录路径")

    # Web 可视化控制台
    web = sub.add_parser("web", help="启动 Web 可视化控制台")
    _add_common_options(web, sub=True)
    web.add_argument("--host", default="127.0.0.1",
                     help="监听地址 (默认 127.0.0.1, 仅本机可访问)")
    web.add_argument("--port", type=int, default=8787, help="监听端口 (默认 8787)")
    web.add_argument("--open", action="store_true", help="启动后自动打开浏览器")

    # 威胁情报平台管理
    it = sub.add_parser("intel", help="威胁情报平台管理")
    _add_common_options(it, sub=True)
    it_sub = it.add_subparsers(dest="intel_action")
    it_sub.add_parser("list", help="列出情报平台及可用状态")
    pull = it_sub.add_parser("pull", help="手动拉取在线情报并写入本地库")
    pull.add_argument("--provider", action="append", default=None,
                      help="只拉指定源，可重复。不填则拉已启用的 Key 源，没有则拉公开列表")
    chk = it_sub.add_parser("check", help="只查本地威胁库")
    chk.add_argument("indicator", help="待查询指标 (IP / 域名 / 哈希 / URL)")
    chk.add_argument("--type", dest="itype", default="ip",
                     choices=["ip", "domain", "hash", "url"], help="指标类型")
    cache = it_sub.add_parser("cache", help="情报缓存管理")
    cache.add_argument("--clear", action="store_true", help="清空本地情报缓存")

    # AI 模型：配置与单次真实判定
    ai = sub.add_parser("ai", help="AI 模型辅助检测")
    _add_common_options(ai, sub=True)
    ai_sub = ai.add_subparsers(dest="ai_action")
    ai_sub.add_parser("status", help="查看模型是否已配置（不回显 Key）")
    ai_set = ai_sub.add_parser("set", help="保存模型连接，Key 写入明文 SQLite")
    ai_set.add_argument("--protocol", choices=["openai", "codex"], default="openai")
    ai_set.add_argument("--base-url", default="", help="OpenAI 兼容接口根地址")
    ai_set.add_argument("--model", required=True, help="模型名")
    ai_set.add_argument("--api-key", default="", help="留空表示不改已有 Key")
    ai_set.add_argument("--timeout", type=int, default=60)
    ai_check = ai_sub.add_parser("check", help="用真实模型判定一个指标")
    ai_check.add_argument("indicator", help="IP / 域名 / 哈希")
    ai_check.add_argument("--type", dest="itype", default="ip",
                          choices=["ip", "domain", "hash", "url"])
    return p


def _add_common_options(p: argparse.ArgumentParser, *, sub: bool) -> None:
    """注册通用选项。

    ``sub=True`` 时默认值使用 ``argparse.SUPPRESS``: 若用户未在子命令后提供该选项,
    属性不会被写入 namespace, 从而保留主解析器已解析的值 (避免默认值覆盖)。
    """
    S = argparse.SUPPRESS
    p.add_argument("-w", "--workspace", default=(S if sub else "."),
                   help="工作区根目录 (默认当前目录)")
    p.add_argument("-c", "--config", default=(S if sub else None),
                   help="已停用。配置在 Web 控制台写入 data/secrets.db")
    p.add_argument("--plugin-dir", default=(S if sub else None), help="额外插件目录")
    p.add_argument("--only", nargs="+", metavar="NAME", default=(S if sub else None),
                   help="仅启用指定采集器/分析器")
    p.add_argument("--skip", nargs="+", metavar="NAME", default=(S if sub else None),
                   help="跳过指定采集器/分析器")
    p.add_argument("--format", nargs="+", metavar="FMT", default=(S if sub else None),
                   help="报告格式: json markdown html")
    p.add_argument("--dry-run", action="store_true", default=(S if sub else False),
                   help="演练模式, 不执行任何命令")
    p.add_argument("--timeout", type=int, default=(S if sub else None),
                   help="单条命令超时秒数")
    p.add_argument("-v", "--verbose", action="store_true", default=(S if sub else False),
                   help="输出调试日志")


# --------------------------------------------------------------------------- #
def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _load_plugins(args) -> None:
    registry.discover()
    if args.plugin_dir:
        loaded = registry.load_external(args.plugin_dir)
        logger.info("已加载外部插件模块: %s", ", ".join(loaded) or "无")


def _build_context(args, *, persistent: bool = True) -> RunContext:
    if getattr(args, "config", None):
        raise SystemExit("不再读取配置文件。请在 Web 控制台「设置」里修改 data/secrets.db")
    config = load_settings(args.workspace)

    # CLI 覆盖
    if args.timeout:
        config["general"]["command_timeout"] = args.timeout
    if args.dry_run:
        config["general"]["dry_run"] = True
    if args.only:
        config["collectors"]["enable_only"] = args.only
        config["analyzers"]["enable_only"] = args.only
    if args.skip:
        config["collectors"]["disable"] = args.skip
        config["analyzers"]["disable"] = args.skip
    if args.format:
        config["reporters"]["formats"] = args.format

    return RunContext(
        workspace=args.workspace,
        config=config,
        dry_run=config["general"]["dry_run"],
        command_timeout=config["general"]["command_timeout"],
        max_file_bytes=config["general"]["max_file_bytes"],
        persistent=persistent,
    )


# --------------------------------------------------------------------------- #
def cmd_run(args) -> int:
    ctx = _build_context(args)
    try:
        orch = Orchestrator(ctx)
        logger.info("=== 开始溯源分析 (run_id=%s) ===", ctx.run_id)
        result = orch.run()
        _print_summary(ctx, result["outputs"])
        return 0
    finally:
        ctx.close()


def cmd_collect(args) -> int:
    ctx = _build_context(args)
    try:
        orch = Orchestrator(ctx)
        res = orch.collect()
        logger.info("采集完成: 事件=%d 证据=%d", len(res.events), len(res.evidence))
        print(f"run_dir: {ctx.run_dir}")
        return 0
    finally:
        ctx.close()


def cmd_analyze(args) -> int:
    """对已有 run 重跑分析与报告。

    ``--run-dir`` 指向 ``runs/<id>`` 时, 从其中的 ``result.json`` 还原事件;
    不传则只分析本次新上下文 (通常为空, 仅用于演练)。
    """
    ctx = _build_context(args)
    try:
        run_dir = getattr(args, "run_dir", None)
        if run_dir:
            loaded = _load_events_from_run(Path(run_dir))
            if loaded is None:
                print(f"[!] 未找到可重放的 result.json: {run_dir}", file=sys.stderr)
                return 2
            for event in loaded:
                ctx.add_event(event)
            logger.info("已从 %s 还原 %d 条事件", run_dir, len(loaded))
        orch = Orchestrator(ctx)
        n = orch.analyze()
        outputs = orch.report()
        logger.info("分析完成: 结论=%d", n)
        _print_summary(ctx, outputs)
        return 0
    finally:
        ctx.close()


def _load_events_from_run(run_dir: Path):
    """读取已有 JSON 报告里的事件。找不到返回 None。"""
    from irtrace.core.models import Event
    candidates = [run_dir / "result.json", run_dir / "reports" / "result.json"]
    path = next((p for p in candidates if p.exists()), None)
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] 无法解析 {path}: {exc}", file=sys.stderr)
        return None
    return [Event.from_dict(item) for item in payload.get("events", [])]


def cmd_list(args) -> int:
    _load_plugins(args)
    print("已注册插件:\n")
    for kind, label in (("collector", "采集器"), ("analyzer", "分析器"),
                        ("reporter", "报告器")):
        print(f"[{label}]")
        for p in registry.by_kind(kind):
            req = f"  依赖: {', '.join(p.requires_commands)}" if p.requires_commands else ""
            print(f"  - {p.name:<18} {p.description}{req}")
        print()
    return 0


def cmd_verify(args) -> int:
    ledger = Path(args.run_dir) / "evidence-ledger.jsonl"
    if not ledger.exists():
        print(f"[!] 未找到账本: {ledger}", file=sys.stderr)
        return 2
    ctx = RunContext(workspace=Path(args.run_dir).parents[1])
    ctx._ledger_path = ledger  # 指向已有账本
    try:
        ctx.verify_ledger()
    except Exception as exc:  # noqa: BLE001
        print(f"[×] 证据链校验失败: {exc}", file=sys.stderr)
        return 1
    n = sum(1 for ln in ledger.read_text(encoding="utf-8").splitlines() if ln.strip())
    print(f"[√] 证据哈希链完整, 共 {n} 条记录。")
    return 0


def cmd_doctor(args) -> int:
    _load_plugins(args)
    ctx = _build_context(args, persistent=False)
    print(f"工作区      : {ctx.workspace}")
    print(f"平台        : {'Linux' if ctx.is_linux else '非 Linux (采集器将跳过)'}")
    print(f"主机名      : {ctx.hostname}")
    print(f"执行用户    : {ctx.operator}")
    print(f"dry-run     : {ctx.dry_run}")
    print()
    print("外部命令可用性:")
    for cmd in ("ss", "netstat", "last", "lastb", "systemctl", "find", "lsmod", "ps"):
        mark = "√" if ctx.which(cmd) else "×"
        print(f"  [{mark}] {cmd}")
    print()
    print("采集器可用性:")
    for p in registry.by_kind("collector"):
        reason = p.preflight(ctx)
        print(f"  [{'√' if not reason else '×'}] {p.name:<18} {reason or '可用'}")
    return 0


def cmd_ai(args) -> int:
    """AI 模型：status / set / check。Key 只显示掩码。"""
    from irtrace.ai.client import ModelError, load_model_config
    from irtrace.secrets import SecretStore, mask_secret

    action = getattr(args, "ai_action", None) or "status"
    ctx = _build_context(args, persistent=(action == "check"))
    store = SecretStore(ctx.workspace)

    if action == "set":
        extra = {
            "protocol": args.protocol,
            "base_url": (args.base_url or "").strip().rstrip("/"),
            "model": args.model.strip(),
            "timeout": int(args.timeout),
        }
        if args.protocol == "openai" and not extra["base_url"]:
            print("[!] OpenAI 兼容协议必须提供 --base-url", file=sys.stderr)
            return 2
        current = store.get("ai_model")
        if current is None:
            if args.protocol == "openai" and not args.api_key.strip():
                print("[!] 首次保存必须提供 --api-key", file=sys.stderr)
                return 2
            store.set("ai_model", args.api_key.strip() or "codex-cli", extra=extra)
        else:
            store.update("ai_model", api_key=args.api_key, extra=extra, enabled=True)
        print(f"[√] 已保存模型 {extra['model']}（{extra['protocol']}），Key 不回显")
        return 0

    config = load_model_config(ctx.workspace)
    if action == "status":
        stored = store.get("ai_model")
        print(f"协议    : {config.protocol}")
        print(f"模型    : {config.model or '-'}")
        print(f"接口    : {config.base_url or '-'}")
        print(f"Key     : {mask_secret(stored['api_key']) if stored else '未配置'}")
        print(f"可用    : {'是' if config.configured else '否'}")
        if not config.configured:
            print("保存示例: irtrace ai set --base-url https://host/v1 --model <name> --api-key <key>")
        return 0

    if not config.configured:
        print("[!] 模型未配置。先执行 irtrace ai set", file=sys.stderr)
        return 2

    from irtrace.core.models import Category, Event
    from irtrace.intel import IndicatorType, IntelAggregator

    itype = IndicatorType(args.itype)
    from irtrace.analyzers.ai_assist import _intel_for_assist
    intel_cfg = _intel_for_assist(ctx)
    report = IntelAggregator.from_config(intel_cfg, ctx=ctx).lookup(args.indicator, itype)
    ctx.add_event(Event(
        timestamp=None, category=Category.NETWORK, source="ai",
        action="indicator_lookup",
        src_ip=args.indicator if itype == IndicatorType.IP else None,
        dst_ip=args.indicator if itype == IndicatorType.IP else None,
        message=f"待判定 {itype.label} {args.indicator}",
    ))
    ctx.config["intel"] = intel_cfg
    from irtrace.analyzers.ai_assist import AIAssistAnalyzer
    try:
        findings = AIAssistAnalyzer().analyze(ctx)
    except ModelError as exc:
        print(f"[!] 模型调用失败: {exc}", file=sys.stderr)
        return 2
    if not findings:
        reason = ctx.stats.get("ai_assist", {}).get("reason", "无结论")
        print(f"[!] 未得到模型判定: {reason}", file=sys.stderr)
        return 2
    finding = findings[0]
    details = finding.details
    print(f"指标    : {args.indicator} ({itype.label})")
    print(f"判定    : {'失陷/恶意' if details.get('compromised') else '未判定失陷'}")
    print(f"在线情报: {'是' if details.get('online') else '否（仅本地，不算高精度）'}")
    print(f"来源    : {', '.join(details.get('sources') or []) or '-'}")
    print(f"说明    : {finding.description}")
    ctx.close()
    return 0


def cmd_intel(args) -> int:
    """威胁情报平台管理: list / check / cache。"""
    from irtrace.intel import IndicatorType, IntelAggregator
    from irtrace.intel.registry import intel_registry

    intel_registry.discover()
    # 仅 `check` 会落盘证据, 其余子命令使用临时上下文, 不污染 runs/
    action = getattr(args, "intel_action", None)
    ctx = _build_context(args, persistent=(action == "check"))
    cfg = dict(ctx.config.get("intel", {}))

    if action in (None, "list"):
        print("已注册威胁情报平台:\n")
        print(f"{'名称':<14}{'类型':<8}{'状态':<10}说明")
        print("-" * 78)
        agg = IntelAggregator.from_config(cfg, ctx=ctx)
        active = {p.name for p in agg.providers}
        for name in intel_registry.names():
            cls_ = intel_registry.get(name)
            inst = cls_(dict(cfg.get("platforms", {}).get(name, {}),
                             workspace=str(ctx.workspace)))
            kind = "离线" if inst.offline else "在线"
            if name in active:
                status = "已启用"
            elif inst.unavailable_reason():
                status = "不可用"
            else:
                status = "未启用"
            print(f"{name:<14}{kind:<8}{status:<10}{inst.description}")
            if inst.unavailable_reason():
                print(f"{'':<32}└─ {inst.unavailable_reason()}")
            if not inst.offline:
                print(f"{'':<32}└─ API Key 环境变量: {inst.api_key_env or 'N/A'}"
                      f"　权重 {inst.weight}")
        print(f"\n检测使用: {', '.join(sorted(active)) or '无'}（只读本地库）")
        cross = bool((ctx.config.get("ai") or {}).get("cross_validate"))
        print(f"AI 交叉验证: {'开启' if cross else '关闭（默认）'}")
        print("\n在线情报只在手动拉取时请求: irtrace intel pull")
        return 0

    if action == "pull":
        from irtrace.intel.pull import pull_threats
        summary = pull_threats(ctx.workspace, getattr(args, "provider", None))
        print(f"拉取时间  : {summary['pulled_at']}")
        print(f"来源      : {', '.join(summary['providers']) or '无'}")
        print(f"写入      : {summary['stored']} 条")
        if summary["errors"]:
            print("未完成    :")
            for item in summary["errors"]:
                print(f"  - {item}")
        return 0 if summary["providers"] else 2

    if action == "check":
        from irtrace.intel.aggregator import DEFAULT_OFFLINE_PROVIDERS
        cfg["providers"] = list(DEFAULT_OFFLINE_PROVIDERS)
        agg = IntelAggregator.from_config(cfg, ctx=ctx)
        if not agg.providers:
            print("[!] 没有可用的情报源, 请检查 [intel] 配置。", file=sys.stderr)
            return 2
        itype = IndicatorType(args.itype)
        report = agg.lookup(args.indicator, itype)

        print(f"\n指标      : {report.indicator} ({itype.label})")
        print(f"判定      : {'恶意' if report.is_malicious else '未发现恶意'}")
        print(f"综合评分  : {report.score}/100　置信度: {report.confidence}")
        print(f"级别      : {report.severity.value}")
        print(f"命中来源  : {', '.join(report.malicious_sources) or '-'}")
        print(f"标签      : {', '.join(report.tags) or '-'}")
        print("\n各平台结果:")
        for v in report.verdicts:
            if v.error:
                print(f"  [×] {v.provider:<12} {v.error}")
            else:
                flag = "恶意" if v.malicious else "正常"
                print(f"  [{'!' if v.malicious else '√'}] {v.provider:<12} "
                      f"{flag} 评分={v.score:<6} 置信={v.confidence}")
                if v.description:
                    print(f"      {v.description}")
        print(f"\n证据已落盘: {ctx.run_dir / 'evidence' / 'intel'}")
        ctx.close()
        return 0 if not report.is_malicious else 0

    if action == "cache":
        agg = IntelAggregator.from_config(cfg, ctx=ctx)
        if getattr(args, "clear", False):
            n = agg.cache.clear() if agg.cache else 0
            print(f"[√] 已清空情报缓存, 删除 {n} 条记录。")
        else:
            stats = agg.cache.stats() if agg.cache else {"entries": 0}
            print(f"情报缓存目录: {agg.cache.dir if agg.cache else '未启用'}")
            print(f"缓存条目    : {stats.get('entries', 0)}")
            print("使用 --clear 清空缓存。")
        return 0

    return 0


def cmd_web(args) -> int:
    """启动 Web 可视化控制台 (只读)。"""
    from irtrace.web import serve

    workspace = Path(args.workspace).resolve()
    runs_dir = workspace / "runs"
    if not runs_dir.is_dir() or not any(runs_dir.iterdir()):
        logger.warning("工作区尚无分析记录: %s", runs_dir)
        logger.warning("请先执行: sudo python -m irtrace run")

    try:
        serve(workspace, host=args.host, port=args.port,
              open_browser=getattr(args, "open", False))
    except OSError as exc:
        print(f"[×] 无法启动控制台 ({args.host}:{args.port}): {exc}", file=sys.stderr)
        print("    端口可能已被占用, 请用 --port 指定其他端口。", file=sys.stderr)
        return 2
    return 0


def _print_summary(ctx: RunContext, outputs: List[str]) -> None:
    s = ctx.summary()
    print("\n" + "=" * 62)
    print(f"  溯源分析完成  run_id={s['run_id']}")
    print("=" * 62)
    print(f"  主机        : {s['host']}")
    print(f"  归一化事件  : {s['events']}")
    print(f"  证据条目    : {s['evidence']}")
    print(f"  分析结论    : {s['findings']}  {s['findings_by_severity']}")
    print(f"  采集告警    : {s['warnings']}")
    print(f"  运行目录    : {s['run_dir']}")
    if outputs:
        print("  报告输出    :")
        for o in outputs:
            print(f"    - {o}")
    print("=" * 62 + "\n")


# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))

    if not args.command:
        parser.print_help()
        return 1

    _load_plugins(args)

    handlers = {
        "run": cmd_run, "collect": cmd_collect, "analyze": cmd_analyze,
        "list": cmd_list, "verify": cmd_verify, "doctor": cmd_doctor,
        "intel": cmd_intel, "web": cmd_web, "ai": cmd_ai,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
