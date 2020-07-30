all: none

none:
	@echo Nothing to see here, go away.

clean:
	rm -rf target
	rm -f rsa_cert.pem
	rm -f rsa_private.pem

build:
	cargo build

build-release:
	cargo build --release

get-root:
	curl -O https://pki.google.com/roots.pem

rsa_private.pem:
	openssl req -x509 -newkey rsa:2048 -keyout rsa_private.pem -nodes  -out rsa_cert.pem -subj "/CN=unused"

# eof
