

## 0) Build everything once

```bash
cargo build --release
```

---

## 1) Start the watchtower (Terminal 1)

```bash
cargo run -p watchtower -- --bind 0.0.0.0:7000 --epoch 1 --key-file watchtower_key.json
```


## 2) Start Party 0..4 (each in its own terminal)

### Terminal 2 — Party 0

```bash
cargo run -p party -- run \
  --watchtower http://127.0.0.1:7000 \
  --epoch 1 \
  --party-id 0 \
  --endpoint 127.0.0.1:9000 \
  --interval-secs 2 \
  --connect-timeout-ms 500 \
  --key-file party0_key.json \
  --state-file party0_state.json
```

### Terminal 3 — Party 1

```bash
cargo run -p party -- run \
  --watchtower http://127.0.0.1:7000 \
  --epoch 1 \
  --party-id 1 \
  --endpoint 127.0.0.1:9001 \
  --interval-secs 2 \
  --connect-timeout-ms 500 \
  --key-file party1_key.json \
  --state-file party1_state.json
```

### Terminal 4 — Party 2

```bash
cargo run -p party -- run \
  --watchtower http://127.0.0.1:7000 \
  --epoch 1 \
  --party-id 2 \
  --endpoint 127.0.0.1:9002 \
  --interval-secs 2 \
  --connect-timeout-ms 500 \
  --key-file party2_key.json \
  --state-file party2_state.json
```

### Terminal 5 — Party 3

```bash
cargo run -p party -- run \
  --watchtower http://127.0.0.1:7000 \
  --epoch 1 \
  --party-id 3 \
  --endpoint 127.0.0.1:9003 \
  --interval-secs 2 \
  --connect-timeout-ms 500 \
  --key-file party3_key.json \
  --state-file party3_state.json
```

### Terminal 6 — Party 4

```bash
cargo run -p party -- run \
  --watchtower http://127.0.0.1:7000 \
  --epoch 1 \
  --party-id 4 \
  --endpoint 127.0.0.1:9004 \
  --interval-secs 2 \
  --connect-timeout-ms 500 \
  --key-file party4_key.json \
  --state-file party4_state.json
```