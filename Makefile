ifndef version
	version = 0.0.5
#	version = dev
endif

build:
	go build -ldflags "-w -s" -trimpath -o bin/

dist:
	go get -d github.com/mitchellh/gox
	go build -mod=readonly -o ./bin/ github.com/mitchellh/gox
	go mod tidy
	go env -w GOFLAGS=-trimpath
	./bin/gox -mod="readonly" -ldflags="-X main.Version=$(version) -w -s" -output="bin/{{.Dir}}_{{.OS}}_{{.Arch}}" -osarch="windows/amd64 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64"
	rm ./bin/gox*