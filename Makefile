IMAGE_NAME=anvilelf
CONTAINER_NAME=anvilelf
PROJECT_DIR=$(PWD)

DOCKER_EXEC=docker exec -it $(CONTAINER_NAME)

.PHONY: install shell check fix test clean

install: clean
	docker build -t $(IMAGE_NAME) .
	docker run -itd -v $(PROJECT_DIR):/src --name $(CONTAINER_NAME) --user $(id -u):$(id -g) $(IMAGE_NAME) /bin/bash

shell:
	$(DOCKER_EXEC) /bin/bash

check:
	@$(DOCKER_EXEC) /bin/bash -c " \
		isort --check-only /src && \
		black --line-length 79 --check /src && \
		flake8 /src && \
		mypy --explicit-package-bases /src && \
		python -m pytest -v /src/tests"

fix:
	@$(DOCKER_EXEC) /bin/bash -c " \
		isort /src && \
		black --line-length 79 /src"

test:
	$(DOCKER_EXEC) python -m pytest -v /src/tests

clean:
	@if [ -n "$$(docker ps -q -f name=$(CONTAINER_NAME))" ]; then docker stop $(CONTAINER_NAME); fi
	@if [ -n "$$(docker ps -aq -f name=$(CONTAINER_NAME))" ]; then docker rm $(CONTAINER_NAME); fi
	@if [ -n "$$(docker images -q $(IMAGE_NAME))" ]; then docker rmi $(IMAGE_NAME); fi
