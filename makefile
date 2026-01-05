install:
	python3 -m pip install -e .

push:
	python3 -m build
	twine upload dist/*

clean:
	rm -rf build dist *.egg-info
