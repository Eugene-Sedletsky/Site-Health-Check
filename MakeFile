help:
	@echo "Available targets"
	@echo "   install            - instal dependencies"
	@echo "   run                - Run application"
	@echo "   help               - Display this help message"
	@ech0 "   check_dependencies - Check poetry dependencies"

check_dependencies:
	@echo "Running hard check for dependencies..."
	poetry check
	poetry install --no-root --dry-run

install:
	poetry lock --no-update
	poetry install --no-root

run:
	poetry run python main.py

run-1:
	poetry run python .\ssl_check.py

run-2:
	poetry run python .\sslyze_check.py