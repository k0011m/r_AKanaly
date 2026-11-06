import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path

import guest_agent


DEFAULT_AGENT_DIR = Path(r"C:\Users\Public\CodexGuestAgent")


# 常駐agentが使うディレクトリをまとめて作成し、Host側とのファイル受け渡し場所を固定する。
def ensure_dirs(agent_dir):
    paths = {
        "queue": agent_dir / "queue",
        "processing": agent_dir / "processing",
        "responses": agent_dir / "responses",
        "logs": agent_dir / "logs"
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


# 途中終了した要求を重複処理しないよう、queueからprocessingへ原子的に近い形で移動する。
def claim_request(request_path, processing_dir):
    claimed = processing_dir / request_path.name
    try:
        request_path.replace(claimed)
        return claimed
    except OSError:
        return None


# 単発agentと同じ抽象操作を処理し、常駐agent用のメタ情報を付けて返す。
def handle_claimed_request(request_path, response_dir):
    started = time.time()
    response_path = response_dir / request_path.name
    try:
        request = json.loads(request_path.read_text(encoding="utf-8-sig"))
        if request.get("action") == "extract_zip":
            request_path.unlink()
        result = {
            "ok": True,
            "request": guest_agent.public_request(request),
            "result": guest_agent.handle_request(request),
            "elapsed_sec": round(time.time() - started, 3),
            "handled_by": "resident_agent"
        }
    except Exception as exc:
        result = {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
            "elapsed_sec": round(time.time() - started, 3),
            "handled_by": "resident_agent"
        }
    temporary = response_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(response_path)
    try:
        request_path.unlink()
    except OSError:
        pass
    return result


# ポーリング方式でHostから置かれたJSON要求を処理する。
def run_loop(agent_dir, interval):
    paths = ensure_dirs(agent_dir)
    log_path = paths["logs"] / "resident_agent.log"
    pid_path = agent_dir / "resident_agent.pid"
    pid_path.write_text(str(os.getpid()), encoding="ascii")
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} resident_agent started pid={os.getpid()}\n")
        log.flush()
        while True:
            for request_path in sorted(paths["queue"].glob("*.json")):
                claimed = claim_request(request_path, paths["processing"])
                if not claimed:
                    continue
                result = handle_claimed_request(claimed, paths["responses"])
                log.write(
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"{claimed.name} ok={result.get('ok')} action={result.get('request', {}).get('action')}\n"
                )
                log.flush()
            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-dir", default=str(DEFAULT_AGENT_DIR))
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    run_loop(Path(args.agent_dir), args.interval)


if __name__ == "__main__":
    sys.exit(main())
