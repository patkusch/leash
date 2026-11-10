.PHONY: test demo

PY ?= python3

test:
	PYTHONPATH=src:tests $(PY) -m unittest discover -s tests

# run leash on the example project in docs/example (no home-folder files, no network)
demo:
	PYTHONPATH=src $(PY) -m leash docs/example --no-user --no-gh --all
