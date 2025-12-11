# Lonkero License Server - Cloudflare Worker

License verification and killswitch server for Lonkero scanner.

## Features

- **Default: Full access** - Everyone gets all features in non-commercial mode
- **Killswitch** - Remotely disable specific users, IPs, or hardware IDs
- **License validation** - Validate commercial licenses
- **Admin API** - Ban/unban users via API

## Deployment

### 1. Install dependencies

```bash
npm install
```

### 2. Create KV namespaces

```bash
wrangler kv:namespace create "LICENSES"
wrangler kv:namespace create "KILLSWITCH"
```

Copy the IDs to `wrangler.toml`.

### 3. Set admin API key

```bash
wrangler secret put ADMIN_API_KEY
# Enter a secure random string
```

### 4. Configure DNS

Add CNAME record in Cloudflare:
- Name: `license`
- Target: `lonkero-license.<your-account>.workers.dev`

Or configure route in `wrangler.toml`.

### 5. Deploy

```bash
npm run deploy
```

## API Endpoints

### Public Endpoints

#### GET /api/v1/killswitch
Check if scanner should be disabled.

Headers:
- `X-Hardware-ID` (optional): Device hardware ID

Response:
```json
{
  "active": false,
  "reason": null,
  "message": null,
  "revoked_keys": []
}
```

#### POST /api/v1/validate
Validate a license key.

Body:
```json
{
  "license_key": "optional-key",
  "hardware_id": "device-id",
  "product": "lonkero",
  "version": "1.0.0"
}
```

Response (default - no license):
```json
{
  "valid": true,
  "license_type": "personal",
  "max_targets": 100,
  "features": ["all_scanners", "all_outputs", ...],
  "killswitch_active": false,
  "message": "Running in non-commercial mode..."
}
```

### Admin Endpoints

All admin endpoints require `Authorization: Bearer <ADMIN_API_KEY>` header.

#### POST /api/v1/admin/ban
Ban a user by hardware ID, license key, or IP.

```bash
curl -X POST https://license.bountyy.fi/api/v1/admin/ban \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "hardware_id",
    "value": "abc123",
    "reason": "Unauthorized commercial use"
  }'
```

Types: `hardware_id`, `license_key`, `ip`

#### POST /api/v1/admin/unban
Remove a ban.

```bash
curl -X POST https://license.bountyy.fi/api/v1/admin/unban \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "hardware_id",
    "value": "abc123"
  }'
```

#### GET /api/v1/admin/list
List all banned entries.

```bash
curl https://license.bountyy.fi/api/v1/admin/list \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

## Usage Examples

### Ban someone using Lonkero for hacking

```bash
# Ban by IP
curl -X POST https://license.bountyy.fi/api/v1/admin/ban \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"type":"ip","value":"1.2.3.4","reason":"Malicious scanning detected"}'

# Ban by hardware ID (if known)
curl -X POST https://license.bountyy.fi/api/v1/admin/ban \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"type":"hardware_id","value":"abc123def456","reason":"Terms of service violation"}'
```

### Global killswitch (emergency)

To disable ALL users:

```bash
wrangler kv:key put --binding KILLSWITCH "global" \
  '{"active":true,"reason":"Emergency maintenance","banned_at":"2025-01-01","banned_by":"admin","type":"global"}'
```

To re-enable:

```bash
wrangler kv:key delete --binding KILLSWITCH "global"
```

## License

Proprietary - Bountyy Oy
