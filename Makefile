default: build run
	
run-image:
	docker run -it --rm --name n8n -p 5678:5678 docker.n8n.io/n8nio/n8n:latest

install:
	pnpm install

build:
	pnpm run build

run:
	pnpm start

run-qp:
	pnpm start:qp
