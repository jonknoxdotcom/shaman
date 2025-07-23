APP=shaman

hello:
	@echo "bin/${APP} is a cryptographic decluttering tool"

build:
	go build -o bin/${APP} ${APP}.go

run:
	go run ${APP}.go


compile:
	@echo "Compiling for every OS and Platform"
	GOOS=linux GOARCH=arm go build -o bin/${APP}-linux-arm ${APP}.go
	GOOS=linux GOARCH=arm64 go build -o bin/${APP}-linux-arm64 ${APP}.go
	GOOS=freebsd GOARCH=386 go build -o bin/${APP}-freebsd-386 ${APP}.go

skinny:
	go build -o bin/${APP} -ldflags "-s -w" ${APP}.go

all: hello build
