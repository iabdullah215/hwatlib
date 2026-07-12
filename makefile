install:
	python3 -m pip install -e .

push:
	python3 -m build
	twine upload dist/*

docs:
	pdoc -o site hwatlib

docs-serve:
	pdoc hwatlib

clean:
	rm -rf build dist *.egg-info site
