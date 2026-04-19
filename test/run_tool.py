import argparse
import json
import os
import sys

# Đưa thư mục gốc của project vào sys.path để có thể import flow_sast_mcp
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flow_sast_mcp.tools import (
    repo_intel,
    semgrep,
    api_parser,
    secrets,
    gitnexus,
    joern
)

def print_result(res):
    print(json.dumps(res, indent=2, ensure_ascii=False, default=str))

def main():
    parser = argparse.ArgumentParser(description="Chạy trực tiếp các tool của flow-sast-mcp (Bypass MCP)")
    parser.add_argument("tool", choices=[
        "repo_intel", "semgrep", "api_parse", "secrets", "gitnexus_context"
    ], help="Tên tool cần chạy")
    default_temp_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'dummy_repo'))
    parser.add_argument("--repo", default=default_temp_repo, help="Đường dẫn tuyệt đối đến repository (mặc định: thư mục dummy_repo)")
    parser.add_argument("--run-id", default="test_local_run", help="Mã run_id (mặc định: test_local_run)")
    parser.add_argument("--stack", default="auto", help="Framework/Ngôn ngữ truyền vào (dùng cho semgrep/api_parse)")

    args = parser.parse_args()

    print(f"========================================")
    print(f"🚀 BẮT ĐẦU CHẠY TOOL: {args.tool.upper()}")
    print(f"📁 Repo   : {args.repo}")
    print(f"🆔 Run ID : {args.run_id}")
    if args.tool in ["semgrep", "api_parse"]:
        print(f"📚 Stack  : {args.stack}")
    print(f"========================================\n")

    try:
        if args.tool == "repo_intel":
            result = repo_intel.run(run_id=args.run_id, repo=args.repo)
            print_result(result)

        elif args.tool == "semgrep":
            result = semgrep.run(run_id=args.run_id, repo=args.repo, stack=args.stack)
            print_result(result)

        elif args.tool == "api_parse":
            result = api_parser.run(run_id=args.run_id, repo=args.repo, stack=args.stack)
            print_result(result)

        elif args.tool == "secrets":
            result = secrets.run(run_id=args.run_id, repo=args.repo)
            print_result(result)

        elif args.tool == "gitnexus_context":
            result = gitnexus.run_context(run_id=args.run_id, repo=args.repo)
            print_result(result)

        print(f"\n✅ CHẠY XONG TOOL: {args.tool.upper()}")
        
    except Exception as e:
        print(f"\n❌ LỖI TRONG QUÁ TRÌNH CHẠY: {e}")

if __name__ == "__main__":
    main()
