import shutil
import subprocess
import sys

# Ensure stdout uses utf-8 if possible, but fallback to ascii safe chars
def print_safe(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode('ascii', 'ignore').decode('ascii'))

def check_tool(name: str, check_cmd: list[str], optional: bool = False):
    print_safe(f"Checking {name}...")
    
    # Check if the binary exists in PATH
    executable = shutil.which(check_cmd[0])
    if not executable:
        status = "[WARNING] Missing (Optional)" if optional else "[FAIL] Missing (Required)"
        print_safe(f"  {status}: '{check_cmd[0]}' not found in PATH.\n")
        return False
    
    try:
        # Run the version/check command using the resolved executable path
        # This prevents WinError 2 on Windows when trying to run .cmd/.bat files without shell=True
        full_cmd = [executable] + check_cmd[1:]
        result = subprocess.run(
            full_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            timeout=10
        )
        if result.returncode == 0 or (name == "Java (for Joern)" and result.returncode == 0):
            # Print the first line of the output as the version
            output = result.stdout.strip().split('\n')[0]
            print_safe(f"  [OK] Installed: {output}\n")
            return True
        else:
            print_safe(f"  [FAIL] Error running {check_cmd[0]}: exit code {result.returncode}\n")
            return False
    except Exception as e:
        print_safe(f"  [FAIL] Error checking {name}: {e}\n")
        return False

def check_http_service(name: str, url: str, optional: bool = True):
    print_safe(f"Checking {name}...")
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                print_safe(f"  [OK] Service is reachable at {url}\n")
                return True
            else:
                print_safe(f"  [FAIL] Service returned status {response.status}\n")
                return False
    except urllib.error.URLError as e:
        status = "[WARNING] Missing (Optional)" if optional else "[FAIL] Missing (Required)"
        print_safe(f"  {status}: Cannot connect to {url} ({e.reason}).\n")
        return False
    except Exception as e:
        status = "[WARNING] Missing (Optional)" if optional else "[FAIL] Missing (Required)"
        print_safe(f"  {status}: Error checking {url}: {e}\n")
        return False

def main():
    print_safe("========================================")
    print_safe("   flow-sast-mcp Prerequisites Check    ")
    print_safe("========================================\n")

    tools = [
        # (Display Name, [Command, args], is_optional)
        ("Python", ["python", "--version"], False),
        ("Git", ["git", "--version"], False),
        ("Node.js (for GitNexus)", ["node", "--version"], True),
        ("Java (for Joern)", ["java", "-version"], True),
        ("Docker", ["docker", "--version"], True),
        ("Semgrep", ["semgrep", "--version"], True),
        ("Gitleaks", ["gitleaks", "version"], True),
        ("GitNexus", ["gitnexus", "--version"], True),
    ]

    all_required_passed = True
    for name, cmd, optional in tools:
        passed = check_tool(name, cmd, optional)
        if not passed and not optional:
            all_required_passed = False

    # Check Joern server
    passed = check_http_service("Joern REST Server", "http://localhost:8888/health", True)
    if not passed:
        print_safe("  Note: Joern is usually run as a background REST server via joern-server.sh")
        print_safe("        If it's running on a different port, update JOERN_BASE_URL in .env.\n")

    print_safe("========================================")
    if all_required_passed:
        print_safe("[OK] All REQUIRED tools are installed.")
        print_safe("Note: Optional tools enable advanced features like Joern CFG or GitNexus.")
    else:
        print_safe("[FAIL] Some REQUIRED tools are missing. Please install them.")
        sys.exit(1)

if __name__ == "__main__":
    main()
