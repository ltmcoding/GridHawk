SEEDS ?= 4711 1009 2 77 314 1618 2718 8080 9001 13 555 42
PY    ?= python3

.PHONY: help scenarios detect score rf clean cloud replay
help:
	@echo "make scenarios   generate scenarios + sealed manifests"
	@echo "make detect      run the detector over each replay"
	@echo "make score       score findings against the manifests"
	@echo "make rf          synthesise RF sweeps and run the carrier detector"
	@echo "make cloud       start the fake vendor cloud (foreground)"
	@echo "make replay      drive real TLS sessions at the cloud (needs 'make cloud')"

scenarios:
	@for s in $(SEEDS); do $(PY) -m sim.scenario --seed $$s; done

detect:
	@for s in $(SEEDS); do $(PY) detect.py --events runs/$$s.events.json --out found/$$s.jsonl; done

score:
	@$(PY) -m sim.score --verbose

rf:
	@$(PY) -m sim.rf_synth --preset single     --out runs/rf_single.csv --seed 7
	@$(PY) -m sim.rf_synth --preset dual       --out runs/rf_dual.csv   --seed 7
	@$(PY) -m sim.rf_synth --preset dual_close --out runs/rf_close.csv  --seed 7
	@$(PY) -c "from collectors.rf import run_file; \
	  [print(p, '->', run_file(p,'ISM-433',1,433.92e6)[0][0].fields['n_carriers'], 'carriers') \
	   for p in ('runs/rf_single.csv','runs/rf_dual.csv','runs/rf_close.csv')]"

cloud:
	@$(PY) -m sim.cloud.server --bind 127.0.0.1 --port 8443

replay:
	@$(PY) -m sim.inverter.client --events runs/4711.events.json --host 127.0.0.1 --port 8443 --speed 600

clean:
	@rm -f runs/*.json runs/*.csv found/*.jsonl truth/*.json
