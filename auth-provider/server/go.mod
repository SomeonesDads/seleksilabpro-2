module github.com/SomeonesDads/seleksilabpro-2/auth-provider/server

go 1.25.0

require (
	github.com/SomeonesDads/seleksilabpro-2/shared v0.0.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/golang-migrate/migrate/v4 v4.18.3
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.23.0
	github.com/rabbitmq/amqp091-go v1.10.0
	golang.org/x/crypto v0.36.0
	gorm.io/driver/postgres v1.6.2
	gorm.io/gorm v1.31.2
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/SomeonesDads/seleksilabpro-2/shared => ../../shared
