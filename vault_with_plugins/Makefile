up:
	docker-compose up -d $(c)
start:
	docker-compose start $(c)
down:
	docker-compose down $(c)
destroy:
	docker-compose down -v $(c)
stop:
	docker-compose stop $(c)
initialize_server:
	docker exec -it vault-server /etc/vault/config/initialize_vault.sh