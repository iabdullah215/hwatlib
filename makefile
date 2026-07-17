install:
	python3 -m pip install -e .

push:
	python3 -m build
	twine upload dist/*

test:
	pytest

cov:
	pytest --cov=hwatlib --cov-report=term-missing

# Mutation testing over the scoring logic (see [tool.mutmut] in pyproject).
# Requires the 'mutation' extra: pip install -e ".[dev,mutation,async,dns]"
mutants:
	mutmut run
	mutmut results

docs:
	pdoc -o site hwatlib

docs-serve:
	pdoc hwatlib

clean:
	rm -rf build dist *.egg-info site
