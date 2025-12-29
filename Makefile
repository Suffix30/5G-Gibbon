.PHONY: help install install-dev clean test lint format docker-build docker-run dashboard report lte-scan lte-assess

PYTHON := python
PIP := pip
DOCKER := docker
COMPOSE := docker-compose

help:
	@echo ""
	@echo "5G-Gibbon Toolkit - Available Commands"
	@echo "======================================="
	@echo ""
	@echo "Setup:"
	@echo "  make install       Install dependencies"
	@echo "  make install-dev   Install with development dependencies"
	@echo "  make clean         Clean build artifacts and cache"
	@echo ""
	@echo "Development:"
	@echo "  make test          Run tests"
	@echo "  make lint          Run linters"
	@echo "  make format        Format code with black"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-run    Run interactive container"
	@echo "  make dashboard     Start dashboard container"
	@echo ""
	@echo "Toolkit:"
	@echo "  make run           Run interactive mode"
	@echo "  make scan          Run network scan (5G/4G)"
	@echo "  make report        Generate sample report"
	@echo ""
	@echo "4G/LTE:"
	@echo "  make lte-scan      Scan for 4G LTE components"
	@echo "  make lte-assess    Run 4G/LTE security assessment"
	@echo ""

install:
	$(PYTHON) install.py

install-dev:
	$(PYTHON) install.py --dev

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ 2>/dev/null || true

test:
	$(PYTHON) -m pytest tests/ -v

lint:
	$(PYTHON) -m basedpyright .
	$(PYTHON) -m black --check .
	$(PYTHON) -m isort --check-only .

format:
	$(PYTHON) -m black .
	$(PYTHON) -m isort .

docker-build:
	$(DOCKER) build -t 5g-gibbon:latest .

docker-run:
	$(DOCKER) run -it --rm \
		--network host \
		--privileged \
		--cap-add NET_ADMIN \
		--cap-add NET_RAW \
		-v $(PWD)/reports:/app/reports \
		-v $(PWD)/logs:/app/logs \
		5g-gibbon:latest

dashboard:
	$(COMPOSE) up -d gibbon-dashboard
	@echo ""
	@echo "Dashboard running at http://localhost:8080"
	@echo "Stop with: docker-compose down"
	@echo ""

dashboard-stop:
	$(COMPOSE) down

run:
	$(PYTHON) run.py

scan:
	@read -p "Enter target network (e.g., 10.0.0.0/24): " network; \
	$(PYTHON) run.py scan --network $$network

report:
	$(PYTHON) -c "from reporting.html_report import ReportGenerator, Finding, SeverityLevel, ScanResult, AttackResult; \
		from datetime import datetime; \
		gen = ReportGenerator(); \
		gen.set_metadata('Demo Report', 'Security Assessment', '10.0.0.0/24'); \
		gen.add_finding(Finding('Test Finding', SeverityLevel.HIGH, 'Demo finding', 'Test Component')); \
		print('Report generated:', gen.generate_html('demo_report.html'))"

venv:
	$(PYTHON) -m venv venv
	@echo "Activate with: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)"

requirements:
	$(PIP) freeze > requirements.txt

lte-scan:
	@read -p "Enter MME IP (e.g., 10.0.0.1): " mme; \
	read -p "Enter HSS IP (e.g., 10.0.0.2): " hss; \
	$(PYTHON) run.py lte hss-probe --hss $$hss; \
	$(PYTHON) run.py lte rogue-enb --mme $$mme

lte-assess:
	@read -p "Enter MME IP (e.g., 10.0.0.1): " mme; \
	read -p "Enter HSS IP (e.g., 10.0.0.2): " hss; \
	$(PYTHON) run.py lte assessment --mme $$mme --hss $$hss

.DEFAULT_GOAL := help

