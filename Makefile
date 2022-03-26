install:
	conda env create --file conda.yml

update:
	conda env update --file conda.yml --prune

redis:
	docker-compose up -d redis

redis-cli:
	docker exec -it fides-redis redis-cli

down:
	docker-compose down

test:
	pytest tests

sync-text:
	git submodule update --remote --rebase

pull-text:
	git submodule update --init --recursive