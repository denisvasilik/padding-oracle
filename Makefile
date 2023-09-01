
run:
	FLASK_ENV=development FLASK_APP=tools/server.py flask run

test:
	python3 -m pytest -v tests

test-simple-mock:
	python3 -m pytest -v tests/test_padding_oracle.py::test_simple_oracle_mock
