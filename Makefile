PYTHON ?= python3
EVIDENCE_DIR ?= evidence/latest
SPLUNK_MODE ?= local
SPLUNK_PASSWORD ?= changeme-please-change
SPLUNK_WEB_PORT ?= 8000
SPLUNK_HEC_PORT ?= 8088
SPLUNKD_PORT ?= 8089

.PHONY: test lab-up lab-down lab-seed lab-investigate lab-export lab-validate lab-reproduce rollback-demo lab-deploy lab-kind-up lab-kind-down lab-k8s-secret lab-run-k8s lab-k8s-logs lab-verify-k8s

test:
	$(PYTHON) -m pytest tests

lab-up:
	@if [ "$$ACCEPT_SPLUNK_TERMS" != "1" ]; then \
		echo "Refusing to start Splunk until ACCEPT_SPLUNK_TERMS=1 is set by an authorized operator."; \
		exit 2; \
	fi
	SPLUNK_PASSWORD="$(SPLUNK_PASSWORD)" SPLUNK_WEB_PORT="$(SPLUNK_WEB_PORT)" SPLUNK_HEC_PORT="$(SPLUNK_HEC_PORT)" SPLUNKD_PORT="$(SPLUNKD_PORT)" docker compose -f compose/splunk.yml up -d

lab-down:
	SPLUNK_PASSWORD="$(SPLUNK_PASSWORD)" SPLUNK_WEB_PORT="$(SPLUNK_WEB_PORT)" SPLUNK_HEC_PORT="$(SPLUNK_HEC_PORT)" SPLUNKD_PORT="$(SPLUNKD_PORT)" docker compose -f compose/splunk.yml down -v --remove-orphans

lab-seed:
	$(PYTHON) -m splunk_incident_lab.cli seed --output $(EVIDENCE_DIR)/raw/events.jsonl

lab-investigate:
	$(PYTHON) -m splunk_incident_lab.cli investigate --mode $(SPLUNK_MODE) --events $(EVIDENCE_DIR)/raw/events.jsonl --output $(EVIDENCE_DIR)

lab-export:
	$(PYTHON) -m splunk_incident_lab.cli export --evidence $(EVIDENCE_DIR)

lab-validate:
	$(PYTHON) -m splunk_incident_lab.cli validate --evidence $(EVIDENCE_DIR)

lab-reproduce: lab-seed lab-investigate lab-export lab-validate

rollback-demo:
	$(PYTHON) -m splunk_incident_lab.cli demo-rollback --output evidence/rollback-demo

lab-deploy:
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/telemetry-generator.yaml

lab-kind-up:
	kind create cluster --name splunk-incident-lab

lab-kind-down:
	kind delete cluster --name splunk-incident-lab

lab-k8s-secret:
	kubectl apply -f k8s/namespace.yaml
	kubectl -n splunk-incident-lab create secret generic splunk-incident-lab-splunk --from-literal=password="$(SPLUNK_PASSWORD)" --dry-run=client -o yaml | kubectl apply -f -

lab-run-k8s:
	mkdir -p $(EVIDENCE_DIR)/kubernetes
	@job="checkout-telemetry-generator-manual-$$(date +%s)"; \
	kubectl -n splunk-incident-lab create job --from=cronjob/checkout-telemetry-generator "$$job"; \
	kubectl -n splunk-incident-lab wait --for=condition=complete "job/$$job" --timeout=180s; \
	kubectl -n splunk-incident-lab logs "job/$$job" > $(EVIDENCE_DIR)/kubernetes/telemetry-generator.log

lab-k8s-logs:
	kubectl -n splunk-incident-lab get pods,jobs,cronjobs

lab-verify-k8s:
	$(PYTHON) -m splunk_incident_lab.cli verify-k8s --output $(EVIDENCE_DIR)/raw/kubernetes-splunk-results.json
