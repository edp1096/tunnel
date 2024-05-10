module tunnel

go 1.21.4

require (
	github.com/elliotchance/sshtunnel v1.6.1
	golang.org/x/crypto v0.17.0
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.15.0 // indirect

replace github.com/mitchellh/gox => github.com/edp1096/gox v0.0.0-20240429132002-732d358d175e
