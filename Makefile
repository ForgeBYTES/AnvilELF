IMAGE_NAME=anvilelf
CONTAINER_NAME=anvilelf
PROJECT_DIR=$(PWD)

DOCKER_EXEC=docker exec -it $(CONTAINER_NAME)

.PHONY: install shell check fix test clean

install: clean
	docker build --build-arg UID=$(shell id -u) --build-arg GID=$(shell id -g) -t $(IMAGE_NAME) .
	docker run -itd -v $(PROJECT_DIR):/src --name $(CONTAINER_NAME) --user $(shell id -u):$(shell id -g) $(IMAGE_NAME) /bin/bash

shell:
	$(DOCKER_EXEC) /bin/bash

check:
	@$(DOCKER_EXEC) /bin/bash -c " \
		python -m isort --check-only --split-on-trailing-comma --diff /src && \
		python -m black --line-length 79 --check /src && \
		python -m flake8 /src && \
		python -m mypy --explicit-package-bases /src && \
		python -m pytest --cov-branch --cov-report=xml --cov=/src --cov-report=term-missing -vv /src/tests"

fix:
	@$(DOCKER_EXEC) /bin/bash -c " \
		python -m isort /src --atomic && \
		python -m black --line-length 79 /src"

test:
	$(DOCKER_EXEC) python -m pytest --cov-branch --cov-report=xml --cov=/src --cov-report=term-missing -vv /src/tests

clean:
	@if [ -n "$$(docker ps -q -f name=$(CONTAINER_NAME))" ]; then docker stop $(CONTAINER_NAME); fi
	@if [ -n "$$(docker ps -aq -f name=$(CONTAINER_NAME))" ]; then docker rm $(CONTAINER_NAME); fi
	@if [ -n "$$(docker images -aq $(IMAGE_NAME))" ]; then docker rmi $(IMAGE_NAME); fi
