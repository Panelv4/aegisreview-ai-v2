.PHONY: install dev test scan lint docker up

install:
	pip install -r requirements-dev.txt
	pip install -e .

dev:
	python run.py

test:
	python -m pytest tests/ -q

scan:
	python -m aegis samples/vulnerable-app

gate:
	python -m aegis samples/vulnerable-app --max-critical 0 --max-high 0; \
	  echo "exit=$$?"

docker:
	docker build -t aegisreview:2.0 .

up:
	docker compose up --build
