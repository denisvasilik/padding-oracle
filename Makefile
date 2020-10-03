
run:
	FLASK_ENV=development FLASK_APP=tools/server.py flask run

test:
	python3 -m pytest -v tests
