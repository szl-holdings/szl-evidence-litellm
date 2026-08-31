# szl-evidence-litellm — standalone distribution entry point.
# szl-receipts is the trust core and a peer dependency of the plugin:
# it is always installed FIRST (not published to any index).
PY ?= python3

.PHONY: install test build verify clean

install:
	$(PY) -m pip install -q -e packages/szl-receipts
	$(PY) -m pip install -q -e 'packages/szl-evidence-litellm[dev]'
	$(PY) -m pip install -q pytest ruff build

test:
	cd packages/szl-receipts && $(PY) -m pytest tests
	cd packages/szl-evidence-litellm && $(PY) -m pytest tests

build:
	$(PY) -m build --outdir dist/ packages/szl-receipts
	$(PY) -m build --outdir dist/ packages/szl-evidence-litellm
	cd dist && sha256sum * > SHA256SUMS.txt

verify: install test build
	@echo "OK: install + tests + distributions"

clean:
	rm -rf dist build *.egg-info packages/*/src/*.egg-info
