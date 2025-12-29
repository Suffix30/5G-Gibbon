#!/usr/bin/env python3
import subprocess
import sys
import os
import platform
import shutil
from pathlib import Path

BANNER = """
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║    ███████╗ ██████╗        ██████╗ ██╗██████╗ ██████╗  ██████╗ ███╗   ██╗  ║
║    ██╔════╝██╔════╝       ██╔════╝ ██║██╔══██╗██╔══██╗██╔═══██╗████╗  ██║  ║
║    ███████╗██║  ███╗█████╗██║  ███╗██║██████╔╝██████╔╝██║   ██║██╔██╗ ██║  ║
║    ╚════██║██║   ██║╚════╝██║   ██║██║██╔══██╗██╔══██╗██║   ██║██║╚██╗██║  ║
║    ███████║╚██████╔╝      ╚██████╔╝██║██████╔╝██████╔╝╚██████╔╝██║ ╚████║  ║
║    ╚══════╝ ╚═════╝        ╚═════╝ ╚═╝╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝  ║
║                                                                            ║
║              5G Core Network Security Testing Toolkit                      ║
║                           Installer v1.0                                   ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
"""

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_color(msg: str, color: str = Color.WHITE, bold: bool = False):
    prefix = Color.BOLD if bold else ""
    print(f"{prefix}{color}{msg}{Color.RESET}")

def print_step(step: int, total: int, msg: str):
    print_color(f"[{step}/{total}] {msg}", Color.CYAN)

def print_success(msg: str):
    print_color(f"[OK] {msg}", Color.GREEN)

def print_warning(msg: str):
    print_color(f"[!] {msg}", Color.YELLOW)

def print_error(msg: str):
    print_color(f"[X] {msg}", Color.RED)

def run_command(cmd: list, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check
        )
        return result
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {' '.join(cmd)}")
        if e.stderr:
            print_error(e.stderr)
        raise

def check_python_version():
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_error(f"Python 3.8+ required. Found: {version.major}.{version.minor}")
        sys.exit(1)
    print_success(f"Python version: {version.major}.{version.minor}.{version.micro}")

def check_pip():
    try:
        result = run_command([sys.executable, "-m", "pip", "--version"], capture=True)
        print_success(f"pip available: {result.stdout.strip()}")
        return True
    except Exception:
        print_error("pip not found")
        return False

def check_privileges():
    system = platform.system()
    
    if system == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print_success("Running with administrator privileges")
            else:
                print_warning("Not running as administrator - some features may require elevation")
            return is_admin
        except Exception:
            return False
    else:
        if os.geteuid() == 0:
            print_success("Running as root")
            return True
        else:
            print_warning("Not running as root - some features may require sudo")
            return False

def check_system_dependencies():
    system = platform.system()
    missing = []
    
    if system == "Linux":
        deps = ["libpcap-dev", "tcpdump"]
        for dep in deps:
            result = subprocess.run(["which", dep.replace("-dev", "")], capture_output=True)
            if result.returncode != 0:
                result = subprocess.run(["dpkg", "-l", dep], capture_output=True)
                if result.returncode != 0:
                    missing.append(dep)
    elif system == "Darwin":
        deps = ["libpcap", "tcpdump"]
        for dep in deps:
            result = subprocess.run(["which", dep], capture_output=True)
            if result.returncode != 0:
                missing.append(dep)
    elif system == "Windows":
        npcap_path = Path(r"C:\Windows\System32\Npcap")
        if not npcap_path.exists():
            print_warning("Npcap not detected - required for packet capture")
            print_warning("Download from: https://npcap.com/")
            missing.append("Npcap")
    
    if missing:
        print_warning(f"Missing system dependencies: {', '.join(missing)}")
        if system == "Linux":
            print_warning("Install with: sudo apt-get install " + " ".join(missing))
        elif system == "Darwin":
            print_warning("Install with: brew install " + " ".join(missing))
    else:
        print_success("System dependencies satisfied")
    
    return len(missing) == 0

def create_virtual_environment(venv_path: Path):
    if venv_path.exists():
        print_warning(f"Virtual environment already exists at {venv_path}")
        response = input("Recreate? [y/N]: ").strip().lower()
        if response == 'y':
            shutil.rmtree(venv_path)
        else:
            return venv_path
    
    print_color(f"Creating virtual environment at {venv_path}", Color.CYAN)
    run_command([sys.executable, "-m", "venv", str(venv_path)])
    print_success("Virtual environment created")
    
    return venv_path

def get_venv_python(venv_path: Path) -> Path:
    system = platform.system()
    if system == "Windows":
        return venv_path / "Scripts" / "python.exe"
    else:
        return venv_path / "bin" / "python"

def install_dependencies(venv_path: Path, dev: bool = False):
    python = get_venv_python(venv_path)
    
    run_command([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    print_success("pip upgraded")
    
    requirements = Path("requirements.txt")
    if requirements.exists():
        print_color("Installing from requirements.txt", Color.CYAN)
        run_command([str(python), "-m", "pip", "install", "-r", str(requirements)])
        print_success("Dependencies installed from requirements.txt")
    
    pyproject = Path("pyproject.toml")
    if pyproject.exists():
        print_color("Installing package", Color.CYAN)
        if dev:
            run_command([str(python), "-m", "pip", "install", "-e", ".[dev]"])
        else:
            run_command([str(python), "-m", "pip", "install", "-e", "."])
        print_success("Package installed")

def create_activation_script(venv_path: Path):
    project_root = Path.cwd()
    system = platform.system()
    
    if system == "Windows":
        script_path = project_root / "activate.bat"
        content = f"""@echo off
call "{venv_path}\\Scripts\\activate.bat"
cd /d "{project_root}"
echo.
echo 5G-Gibbon environment activated
echo Run 'python run.py --help' to get started
echo.
"""
        with open(script_path, 'w') as f:
            f.write(content)
        
        ps_script_path = project_root / "activate.ps1"
        ps_content = f"""& "{venv_path}\\Scripts\\Activate.ps1"
Set-Location "{project_root}"
Write-Host ""
Write-Host "5G-Gibbon environment activated" -ForegroundColor Cyan
Write-Host "Run 'python run.py --help' to get started" -ForegroundColor Green
Write-Host ""
"""
        with open(ps_script_path, 'w') as f:
            f.write(ps_content)
        
        print_success(f"Created activation scripts: activate.bat, activate.ps1")
    else:
        script_path = project_root / "activate.sh"
        content = f"""#!/bin/bash
source "{venv_path}/bin/activate"
cd "{project_root}"
echo ""
echo "5G-Gibbon environment activated"
echo "Run 'python run.py --help' to get started"
echo ""
"""
        with open(script_path, 'w') as f:
            f.write(content)
        os.chmod(script_path, 0o755)
        
        print_success(f"Created activation script: activate.sh")

def create_directories():
    dirs = ["reports", "logs", "data"]
    for d in dirs:
        path = Path(d)
        path.mkdir(exist_ok=True)
    print_success(f"Created directories: {', '.join(dirs)}")

def verify_installation(venv_path: Path):
    python = get_venv_python(venv_path)
    
    modules = [
        ("scapy", "scapy.all"),
        ("rich", "rich"),
        ("psutil", "psutil"),
        ("flask", "flask"),
        ("h2", "h2"),
    ]
    
    all_ok = True
    for name, import_path in modules:
        result = subprocess.run(
            [str(python), "-c", f"import {import_path}"],
            capture_output=True
        )
        if result.returncode == 0:
            print_success(f"Module {name} installed correctly")
        else:
            print_error(f"Module {name} failed to import")
            all_ok = False
    
    toolkit_modules = [
        ("5G Protocol", "protocol.protocol_layers"),
        ("4G S1AP", "protocol.s1ap"),
        ("4G Diameter", "protocol.diameter"),
        ("LTE Attacks", "attacks.lte_attacks"),
        ("Discovery", "discovery.network_discovery"),
        ("CLI", "core.cli"),
    ]
    
    print()
    print_color("Verifying toolkit modules:", Color.CYAN)
    for name, import_path in toolkit_modules:
        result = subprocess.run(
            [str(python), "-c", f"import {import_path}"],
            capture_output=True
        )
        if result.returncode == 0:
            print_success(f"{name} module verified")
        else:
            print_warning(f"{name} module has import issues (may still work)")
    
    result = subprocess.run(
        [str(python), "run.py", "--help"],
        capture_output=True
    )
    if result.returncode == 0:
        print_success("CLI verified working")
    else:
        print_error("CLI failed to run")
        all_ok = False
    
    return all_ok

def print_completion_message(venv_path: Path, system: str):
    print()
    print_color("=" * 60, Color.GREEN)
    print_color("  Installation Complete!", Color.GREEN, bold=True)
    print_color("=" * 60, Color.GREEN)
    print()
    
    print_color("Quick Start:", Color.CYAN, bold=True)
    print()
    
    if system == "Windows":
        print_color("  1. Activate the environment:", Color.WHITE)
        print_color("     .\\activate.bat", Color.YELLOW)
        print_color("     # or for PowerShell:", Color.WHITE)
        print_color("     .\\activate.ps1", Color.YELLOW)
    else:
        print_color("  1. Activate the environment:", Color.WHITE)
        print_color("     source ./activate.sh", Color.YELLOW)
    
    print()
    print_color("  2. Run the toolkit:", Color.WHITE)
    print_color("     python run.py --help", Color.YELLOW)
    print_color("     python run.py           # Interactive mode", Color.YELLOW)
    print()
    
    print_color("Docker Usage:", Color.CYAN, bold=True)
    print_color("  docker-compose up -d gibbon-dashboard", Color.YELLOW)
    print_color("  docker-compose run gibbon scan --network 10.0.0.0/24", Color.YELLOW)
    print()
    
    print_color("Documentation:", Color.CYAN, bold=True)
    print_color("  See docs/ folder for guides:", Color.WHITE)
    print_color("    INSTALLATION.md  - Setup instructions", Color.WHITE)
    print_color("    USER_GUIDE.md    - CLI commands", Color.WHITE)
    print_color("    HONEYPOT.md      - Honeypot setup", Color.WHITE)
    print_color("    DOCKER.md        - Container deployment", Color.WHITE)
    print()

def main():
    print(BANNER)
    
    system = platform.system()
    print_color(f"Detected OS: {system} ({platform.release()})", Color.CYAN)
    print()
    
    total_steps = 8
    
    print_step(1, total_steps, "Checking Python version")
    check_python_version()
    
    print_step(2, total_steps, "Checking pip")
    check_pip()
    
    print_step(3, total_steps, "Checking privileges")
    check_privileges()
    
    print_step(4, total_steps, "Checking system dependencies")
    check_system_dependencies()
    
    print_step(5, total_steps, "Creating virtual environment")
    venv_path = Path.cwd() / "venv"
    create_virtual_environment(venv_path)
    
    print_step(6, total_steps, "Installing dependencies")
    dev_mode = "--dev" in sys.argv
    install_dependencies(venv_path, dev=dev_mode)
    
    print_step(7, total_steps, "Creating directories and scripts")
    create_directories()
    create_activation_script(venv_path)
    
    print_step(8, total_steps, "Verifying installation")
    success = verify_installation(venv_path)
    
    if success:
        print_completion_message(venv_path, system)
    else:
        print()
        print_error("Installation completed with errors")
        print_warning("Some features may not work correctly")
        print_warning("Check the error messages above and try installing missing components manually")
        sys.exit(1)

if __name__ == "__main__":
    main()

