.PHONY: build clean run demo

build:
	cargo build -p jittersnoop --release

clean:
	cargo clean

run:
	@echo "Usage: sudo ./target/release/jittersnoop --cores 4 --port 8080"
	@echo "       sudo ./target/release/jittersnoop --demo"

demo:
	sudo ./target/release/jittersnoop --demo
