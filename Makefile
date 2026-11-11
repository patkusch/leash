.PHONY: test demo bench

PY ?= python3

test:
	PYTHONPATH=src:tests $(PY) -m unittest discover -s tests

# run leash on the example project in docs/example (no home-folder files, no network)
demo:
	PYTHONPATH=src $(PY) -m leash docs/example --no-user --no-gh --all

# planted leaks and harmless lookalikes: prints what was caught, fails on any miss or false alarm
bench:
	$(PY) bench/run.py --write
