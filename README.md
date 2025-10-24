# JWKS Server

## Screenshots

- [Test Client Results](screenshots/kkw0108_project_2_test_client.jpg)
- [Test Coverage Report](screenshots/kkw0108_project_2_test_overage.jpg)

## Language and Platform

- **Language**: Rust
- **Platform**: Cross-platform (Linux, macOS, Windows)
- **Framework**: Warp v0.4.2
- **Database**: SQLite (rusqlite v0.37.0)
- **Runtime**: Tokio v1.48

## Setup

1. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Build and run:
   ```bash
   cargo run
   ```

Server starts on `http://127.0.0.1:8080`

## Testing Requirements

### 1. JWKS Endpoint (GET)
```bash
curl http://127.0.0.1:8080/.well-known/jwks.json
```

### 2. Authentication (POST)
Valid JWT:
```bash
curl -X POST http://127.0.0.1:8080/auth
```

Expired JWT:
```bash
curl -X POST "http://127.0.0.1:8080/auth?expired"
```

### 3. Database
Database file `totally_not_my_privateKeys.db` is created automatically.

Inspect:
```bash
sqlite3 totally_not_my_privateKeys.db "SELECT kid, exp FROM keys;"
```

### 4. Test Suite
Run tests:
```bash
cargo test
```

Generate coverage report:
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html --output-dir coverage
```

Or faster alternative:
```bash
cargo install cargo-llvm-cov
cargo llvm-cov --html --output-dir coverage
```

Open `coverage/index.html` to view results.
