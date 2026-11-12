#!/usr/bin/env python3
"""Summarizes logs written by the ZapretA dev build (see docs/DEV_LOGS.md).

Usage: analyze_devlog.py <devlogs folder | ZapretA-devlogs-*.zip | session_*.jsonl>

Prints, per session: the setup, which goals/sites were tried, what the DNS
looked like, how every strategy ended, the winner, the most common probe
failures, watchdog rounds, hostnames the engine saw and engine start-up output.
"""
import collections
import glob
import io
import json
import os
import re
import sys
import zipfile


def read_sources(path):
    """Returns {file name: bytes} for a folder, a zip or a single file."""
    files = {}
    if os.path.isdir(path):
        for name in glob.glob(os.path.join(path, "**", "*"), recursive=True):
            if os.path.isfile(name):
                files[os.path.relpath(name, path)] = open(name, "rb").read()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if not info.is_dir():
                    files[info.filename] = archive.read(info)
    else:
        files[os.path.basename(path)] = open(path, "rb").read()
    return files


def text(data):
    return data.decode("utf-8", errors="replace").lstrip("﻿")


def events_of(data):
    for line in text(data).splitlines():
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def short(value, limit=160):
    value = str(value).replace("\n", " ")
    return value if len(value) <= limit else value[: limit - 1] + "…"


def main(path):
    files = read_sources(path)
    sessions = sorted(n for n in files if os.path.basename(n).startswith("session_") and n.endswith(".jsonl"))
    if not sessions:
        print("Нет файлов session_*.jsonl")
        return 1
    for name in sessions:
        report_session(name, list(events_of(files[name])), files)
    return 0


def report_session(name, events, files):
    sid = re.search(r"session_(\d{8}-\d{6})", name).group(1)
    print("=" * 78)
    print(f"СЕССИЯ {sid}  ({len(events)} событий)")
    print("=" * 78)
    by_kind = collections.defaultdict(list)
    for e in events:
        by_kind[e.get("kind")].append(e)

    for e in by_kind["session_start"]:
        print(f"Версия {e.get('app_version')}, DEV={e.get('dev_build')}, {e.get('os')}/{e.get('arch')}, args={e.get('args')}")
    for e in by_kind["engine_prepared"][-1:]:
        print(f"Движок {e.get('engine_id')} winws sha256={e.get('winws_sha256', '')[:16]}…")
    for e in by_kind["panic"]:
        print("!!! PANIC:", short(e.get("info"), 300))

    print("\n-- Что пробовали открыть --")
    for e in by_kind["goals"][-1:]:
        print("Цели:", ", ".join(e.get("groups", [])))
        print("Сайты пользователя:", e.get("user_sites"), "| IP:", e.get("user_ips"), "| исключения:", e.get("user_excludes"))
        print("Настройки:", short(e.get("settings"), 300))

    print("\n-- DNS: системный и DoH --")
    seen = {}
    for e in by_kind["dns"]:
        seen[e["name"]] = e  # last answer per name
    for name_, e in seen.items():
        print(f"{name_}\n    system: {short(e.get('system'), 230)}\n    doh:    {short(e.get('doh'), 230)}")

    print("\n-- Подбор --")
    for e in by_kind["search_start"]:
        print(f"Старт: цели={e.get('goals')}, кэш={e.get('cached')}, полный={e.get('forced_full')}, кандидатов={e.get('candidates')}")
    for e in by_kind["search_report"]:
        goals = e.get("goals", [])
        base = dict(zip(goals, e.get("baseline", [])))
        print("Без обхода:", {k: ("да" if v else "НЕТ") for k, v in base.items()})
        for v in e.get("verdicts", []):
            print(f"  {short(v.get('label') or v.get('id'), 60):60} {short(v.get('verdict'), 110)}")
        print("Итог:", short(e.get("result"), 300))
    for e in by_kind["winner"]:
        print(f"ПОБЕДИТЕЛЬ: {e.get('label')}  {dict(zip(e.get('goals', []), e.get('results', [])))}")

    print("\n-- Проверки (probe): отказы по хостам и причинам --")
    probes = by_kind["probe"]
    fails = collections.Counter()
    examples = {}
    for p in probes:
        if not p.get("passed"):
            reason = p.get("error") or f"HTTP {p.get('status')} bytes={p.get('bytes')} kbps={p.get('kbps')}"
            reason = re.sub(r"https?://\S+", "<url>", reason)
            key = (p.get("host"), short(reason, 140))
            fails[key] += 1
            examples.setdefault(key, p)
    total_ok = sum(1 for p in probes if p.get("passed"))
    print(f"Всего проверок {len(probes)}, успешных {total_ok}")
    for (host, reason), count in fails.most_common(25):
        print(f"  {count:4}×  {host:34} {reason}")

    print("\n-- Результат по стратегиям и хостам (✓/✗ по проверкам) --")
    table = collections.defaultdict(lambda: collections.defaultdict(list))
    for p in probes:
        table[p.get("strategy") or "(без обхода)"][p.get("host")].append(bool(p.get("passed")))
    for strategy, hosts in table.items():
        cells = " ".join(f"{h}:{''.join('✓' if x else '✗' for x in r)}" for h, r in hosts.items())
        print(f"  {short(strategy, 38):38} {short(cells, 120)}")

    print("\n-- Движок --")
    for e in by_kind["engine_start_failed"]:
        print(f"НЕ ЗАПУСТИЛСЯ {e.get('strategy')}: {e.get('error')}")
    for e in by_kind["engine_exited_early"]:
        print(f"Сразу закрылся: {e.get('strategy')}")
    for e in by_kind["engine_output"]:
        tail = e.get("tail", "").strip()
        if tail:
            print(f"Вывод движка ({e.get('strategy')}):\n    " + short(tail, 700).replace("\\n", "\n    "))
    starts = by_kind["engine_start"]
    print(f"Запусков движка: {len(starts)}")
    if starts:
        print("Пример argv:", short(" ".join(starts[-1].get("argv", [])), 400))

    print("\n-- Сторожевой таймер --")
    for e in by_kind["watchdog"]:
        print(f"  {e.get('t')}: {e.get('score')} из {e.get('running_score')} (сбоев до этого {e.get('failures_so_far')})")
    for e in by_kind["watchdog_control"]:
        if not e.get("control_ok") or e.get("engine_exited"):
            print(f"  {e.get('t')}: control_ok={e.get('control_ok')} engine_exited={e.get('engine_exited')}")

    print("\n-- Сайты из кэша DNS Windows (что открывали) --")
    names = [n for e in by_kind["dns_cache_new"] for n in e.get("names", [])]
    print(f"{len(names)} имён:", short(", ".join(names[:120]), 1500))

    print("\n-- Хосты в логе движка (--debug) --")
    counter = collections.Counter()
    profiles = collections.Counter()
    for fname, data in files.items():
        base = os.path.basename(fname)
        if base.startswith("engine_") and base.endswith(".log") and sid in base:
            for line in text(data).splitlines():
                m = re.search(r"hostname[:=]\s*'?([A-Za-z0-9._-]+\.[A-Za-z]{2,})'?", line)
                if m:
                    counter[m.group(1).lower()] += 1
                m = re.search(r"desync profile (\d+) matches", line)
                if m:
                    profiles[m.group(1)] += 1
    if counter:
        for host, count in counter.most_common(40):
            print(f"  {count:6}  {host}")
        print("  профили:", dict(profiles))
    else:
        print("  (пусто: нет engine_*.log или формат строк иной — смотрите сам файл)")

    print("\n-- Журнал для человека (summary) --")
    for fname, data in files.items():
        if os.path.basename(fname) == f"summary_{sid}.txt":
            lines = text(data).splitlines()
            print("\n".join(lines[-60:]))
    system = [n for n in files if os.path.basename(n) == f"system_{sid}.txt"]
    print("\nsystem_*.txt:", "есть" if system else "нет")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
