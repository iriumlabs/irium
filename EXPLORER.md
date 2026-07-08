# Irium Blockchain Explorer

A self-hostable blockchain explorer for the Irium network. Consists of:

- **Rust indexer** — syncs iriumd RPC into PostgreSQL, handles reorgs
- **Rust REST API** (axum) — serves blocks, transactions, addresses, agreements, HTLC swaps
- **React frontend** (Vite + Tailwind CSS 4) — dark-themed explorer UI

## Quick Start (Docker)

**Prerequisites:** Docker 24+, docker-compose 1.29+, a running iriumd node

```bash
git clone https://github.com/iriumlabs/irium.git
cd irium

# Copy and edit configuration
cp .env.example .env
nano .env          # Set DB_PASSWORD and IRIUMD_RPC_URL

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f indexer
docker-compose logs -f api
```

The frontend is served at `http://localhost:3401`.
The API is available at `http://localhost:3400`.

## Configuration (.env)

| Variable | Default | Description |
|---|---|---|
| `DB_PASSWORD` | `changeme` | PostgreSQL password |
| `IRIUMD_RPC_URL` | `http://127.0.0.1:38300` | iriumd RPC endpoint |
| `INDEXER_BATCH_SIZE` | `500` | Blocks indexed per batch |
| `INDEXER_POLL_MS` | `2000` | Poll interval in milliseconds |
| `API_RATE_LIMIT_RPS` | `60` | API rate limit (requests/sec/IP) |

## API Endpoints

```
GET /status                              Indexer sync status
GET /blocks?limit=N&offset=N            Block list (newest first)
GET /blocks/height/:height              Block by height
GET /blocks/hash/:hash                  Block by hash
GET /tx/:txid                           Transaction detail
GET /address/:addr                      Address balance and stats
GET /address/:addr/txs?limit=N         Address transactions
GET /address/:addr/htlcs               Address HTLC outputs
GET /agreements?limit=N                 Settlement agreement list
GET /agreement/:hash                    Agreement detail
GET /htlcs?limit=N                      All HTLC outputs
GET /miners?limit=N                     Mining leaderboard
GET /search?q=<query>                   Search block/tx/address
```

## Production nginx Setup

Add to nginx sites-enabled:

```nginx
server {
    listen 80;
    server_name explorer.example.com;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    server_name explorer.example.com;

    ssl_certificate     /etc/letsencrypt/live/explorer.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/explorer.example.com/privkey.pem;

    location /api/ {
        proxy_pass http://127.0.0.1:3400/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass http://127.0.0.1:3401;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Then: `sudo certbot --nginx -d explorer.example.com`

## Development

```bash
# Backend (from explorer/)
cargo run --bin irium-explorer-indexer
cargo run --bin irium-explorer-api

# Frontend (from frontend/)
npm install
npm run dev      # dev server at http://localhost:3401 with API proxy
npm run build    # production build
```

## Coinbase Tag

Node operators running iriumd can set `IRIUM_COINBASE_TAG` (max 20 ASCII chars)
to identify their blocks in the explorer. The tag appears in the block detail
and the block list under the "Tag" column.

```bash
# In iriumd systemd service or environment:
IRIUM_COINBASE_TAG=MyPool
```

## License

MIT — see LICENSE
