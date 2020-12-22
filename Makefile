up:
	docker-compose up -d $(c)
start:
	docker-compose start $(c)
logs:
	docker-compose logs $(c)
down:
	docker-compose down $(c)
destroy:
	docker-compose down -v $(c)
stop:
	docker-compose stop $(c)
initialize_vault_server:
	docker exec -it vault-server /etc/vault/config/initialize_vault.sh