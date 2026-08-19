module github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker

go 1.22

require (
	github.com/SomeonesDads/seleksilabpro-2/shared v0.0.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/rabbitmq/amqp091-go v1.10.0
)

replace github.com/SomeonesDads/seleksilabpro-2/shared => ../../shared
