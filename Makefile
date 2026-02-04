ifndef version
	version = 0.0.9
#	version = dev
endif

ifeq ($(OS),Windows_NT)
	GOX_BIN = bin\gox.exe
	RM_CMD = del /Q
	RMDIR_CMD = rmdir /S /Q
	PATH_SEP = \\
else
	GOX_BIN = bin/gox
	RM_CMD = rm -f
	RMDIR_CMD = rm -rf
	PATH_SEP = /
endif

build:
	go build -ldflags "-w -s" -trimpath -o bin/

dist:
	go get -d github.com/mitchellh/gox
	go build -mod=readonly -o ./bin/ github.com/mitchellh/gox
	go mod tidy
	go env -w GOFLAGS=-trimpath
	${GOX_BIN} -mod="readonly" -ldflags="-X main.Version=$(version) -w -s" -output="bin/{{.Dir}}_{{.OS}}_{{.Arch}}" -osarch="windows/amd64 linux/amd64 linux/arm linux/arm64"
	$(RM_CMD) .$(PATH_SEP)bin$(PATH_SEP)gox*

clean:
	$(RMDIR_CMD) bin