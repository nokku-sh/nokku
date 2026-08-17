module github.com/nokku-sh/nokku

go 1.26.6

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260709200747-435963d16310.1
	connectrpc.com/connect v1.20.0
	connectrpc.com/cors v0.1.0
	connectrpc.com/grpchealth v1.5.0
	connectrpc.com/grpcreflect v1.3.0
	connectrpc.com/otelconnect v0.9.0
	connectrpc.com/validate v0.6.0
	connectrpc.com/vanguard v0.4.0
	github.com/AfterShip/email-verifier v1.4.1
	github.com/aws/aws-sdk-go-v2 v1.43.6
	github.com/aws/aws-sdk-go-v2/config v1.32.37
	github.com/aws/aws-sdk-go-v2/credentials v1.19.36
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.2
	github.com/brianvoe/gofakeit/v7 v7.15.0
	github.com/caarlos0/env/v11 v11.4.1
	github.com/coder/websocket v1.8.15
	github.com/crewjam/saml v0.5.1
	github.com/go-webauthn/webauthn v0.17.4
	github.com/google/uuid v1.6.0
	github.com/hashicorp/vault/api v1.23.0
	github.com/ip2location/ip2location-go/v9 v9.8.0
	github.com/jackc/pgerrcode v0.0.0-20250907135507-afb5586c32a6
	github.com/jackc/pgx/v5 v5.10.0
	github.com/jackc/tern/v2 v2.4.2
	github.com/mizuchilabs/kagi v0.0.0
	github.com/mizuchilabs/kata v0.1.3
	github.com/redis/go-redis/v9 v9.22.0
	github.com/rs/cors v1.11.1
	github.com/scaleway/scaleway-sdk-go v1.0.0-beta.37
	github.com/scaleway/tink-go-scwkms v0.1.2
	github.com/stripe/stripe-go/v86 v86.3.0
	github.com/tink-crypto/tink-go-awskms/v3 v3.0.0
	github.com/tink-crypto/tink-go-hcvault/v2 v2.5.0
	github.com/tink-crypto/tink-go/v2 v2.8.0
	github.com/urfave/cli/v3 v3.11.0
	github.com/vearutop/statigz v1.5.0
	github.com/wneessen/go-mail v0.8.1
	go.opentelemetry.io/contrib/bridges/otelslog v0.20.0
	go.opentelemetry.io/contrib/instrumentation/runtime v0.70.0
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.21.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0
	go.opentelemetry.io/otel/sdk v1.45.0
	go.opentelemetry.io/otel/sdk/log v0.21.0
	go.opentelemetry.io/otel/sdk/metric v1.45.0
	gocloud.dev v0.46.0
	golang.org/x/crypto v0.55.0
	golang.org/x/image v0.45.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/time v0.15.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260810153831-ec0a7760b754
	google.golang.org/protobuf v1.36.12
)

require (
	buf.build/go/protovalidate v1.3.0 // indirect
	cel.dev/expr v0.25.3 // indirect
	cloud.google.com/go/iam v1.13.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.18 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.37 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager v0.3.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.6 // indirect
	github.com/aws/smithy-go v1.27.8 // indirect
	github.com/beevik/etree v1.7.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-oidc/v3 v3.20.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/cel-go v0.31.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/wire v0.7.0 // indirect
	github.com/googleapis/gax-go/v2 v2.23.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-7 // indirect
	github.com/hbollon/go-edlib v1.7.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/klauspost/compress v1.19.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.23 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.45.0 // indirect
	go.opentelemetry.io/otel/log v0.21.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/trace v1.45.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20260813180055-c1d0aacb2297 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/api v0.293.0 // indirect
	google.golang.org/genproto v0.0.0-20260807164820-c8921c73eeea // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260810153831-ec0a7760b754 // indirect
	google.golang.org/grpc v1.83.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	lukechampine.com/uint128 v1.3.0 // indirect
)

replace github.com/mizuchilabs/kagi => ../kagi
