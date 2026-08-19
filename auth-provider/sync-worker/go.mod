module github.com/SomeonesDads/seleksilabpro-2/auth-provider/sync-worker

go 1.22

require (
	github.com/SomeonesDads/seleksilabpro-2/shared v0.0.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/rabbitmq/amqp091-go v1.10.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/SomeonesDads/seleksilabpro-2/shared => ../../shared
