# One command per step of the pipeline. Everything here runs offline and needs
# no model API key: the generation stage is the only part that does, and it is
# exercised separately (see README, "复现一条 CVE").

PY     ?= python
IMAGE  ?= cpg/cuda112-py3:1.0
CVE    ?= CVE-2024-0076

.PHONY: help image verify mutate report demo test lint

help:
	@echo "make image   构建运行时镜像 $(IMAGE)"
	@echo "make verify  在容器里跑样本并重放判定（不需要 API key）"
	@echo "make mutate  在种子样本上做变异，产出报告与发现"
	@echo "make demo    verify + mutate + report"
	@echo "make test    单元测试"
	@echo "make lint    静态检查"

image:
	docker build -t $(IMAGE) -f docker/Dockerfile .

verify:
	@mkdir -p demo/$(CVE)/out
	$(PY) -m src.run_artifacts --dir demo/$(CVE)/artifacts --image $(IMAGE) \
	  --out demo/$(CVE)/out/observation.txt \
	  --invocation "nvdisasm {artifact}" \
	  --invocation "cuobjdump --dump-elf {artifact}"
	$(PY) -m src.regrade --cve $(CVE) \
	  --samples demo/$(CVE)/artifacts \
	  --log demo/$(CVE)/out/observation.txt

mutate:
	$(PY) -m src.mutation_campaign --cve $(CVE) \
	  --seed demo/$(CVE)/seed/poc.cubin --image $(IMAGE) \
	  --workdir demo/$(CVE)/out/mutation

report:
	$(PY) -m src.status_report --out demo/$(CVE)/out/status.zh-CN.md

demo: verify mutate report

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tools tests
