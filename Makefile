PYTHON ?= python3
EVIDENCE_DIR ?= evidence/latest
SPLUNK_MODE ?= local
SPLUNK_PASSWORD ?= changeme-please-change

.PHONY: test lab-up lab-down lab-seed lab-investigate lab-export lab-reproduce lab-deploy

test:
	$(PYTHON) -m pytest tests

lab-up:
	@if [ "$$ACCEPT_SPLUNK_TERMS" != "1" ]; then \
		echo "Refusing to start Splunk until ACCEPT_SPLUNK_TERMS=1 is set by an authorized operator."; \
		exit 2; \
	fi
	SPLUNK_PASSWORD="$(SPLUNK_PASSWORD)" docker compose -f compose/splunk.yml up -d

lab-down:
	docker compose -f compose/splunk.yml down -v --remove-orphans

lab-seed:
	$(PYTHON) -m splunk_incident_lab.cli seed --output $(EVIDENCE_DIR)/raw/events.jsonl

lab-investigate:
	$(PYTHON) -m splunk_incident_lab.cli investigate --mode $(SPLUNK_MODE) --events $(EVIDENCE_DIR)/raw/events.jsonl --output $(EVIDENCE_DIR)

lab-export:
	$(PYTHON) -m splunk_incident_lab.cli export --evidence $(EVIDENCE_DIR)

lab-reproduce: lab-seed lab-investigate lab-export

lab-deploy:
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/telemetry-generator.yaml

