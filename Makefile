
PYTHON := python3

.PHONY: all test experiments clean

all: test

test:
	$(PYTHON) test.py

experiments:
	$(PYTHON) experiment.py

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} +
