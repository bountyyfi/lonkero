/**
 * Lonkero License Server - Cloudflare Worker
 *
 * Endpoints:
 * - GET  /api/v1/killswitch     - Check global/user killswitch status
 * - POST /api/v1/validate       - Validate a license key
 * - POST /api/v1/admin/ban      - Ban a user/hardware (admin only)
 * - POST /api/v1/admin/unban    - Unban a user/hardware (admin only)
 * - GET  /api/v1/admin/list     - List banned users (admin only)
 * - POST /api/v1/admin/license/create - Create commercial license (admin only)
 * - POST /api/v1/admin/license/revoke - Revoke commercial license (admin only)
 * - GET  /api/v1/admin/license/list   - List all licenses (admin only)
 *
 * (c) 2025 Bountyy Oy
 */

export interface Env {
  LICENSES: KVNamespace;
  KILLSWITCH: KVNamespace;
  ADMIN_API_KEY: string;
  WEBHOOK_SECRET?: string;
  PRODUCT_NAME: string;
}

interface KillswitchEntry {
  active: boolean;
  reason: string;
  banned_at: string;
  banned_by: string;
  type: 'hardware_id' | 'license_key' | 'ip' | 'global';
}

interface LicenseEntry {
  license_key: string;
  license_type: 'personal' | 'professional' | 'team' | 'enterprise';
  licensee: string;
  email: string;
  organization?: string;
  max_targets: number;
  features: string[];
  created_at: string;
  expires_at?: string;
  notes?: string;
}

interface ValidateRequest {
  license_key?: string;
  hardware_id?: string;
  product: string;
  version: string;
}

interface BanRequest {
  type: 'hardware_id' | 'license_key' | 'ip';
  value: string;
  reason: string;
}

interface CreateLicenseRequest {
  license_type: 'professional' | 'team' | 'enterprise';
  licensee: string;
  email: string;
  organization?: string;
  max_targets?: number;
  expires_days?: number;  // Days until expiration (null = never)
  notes?: string;
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Product, X-Version, X-Hardware-ID',
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Route requests
      if (path === '/api/v1/killswitch' && request.method === 'GET') {
        return await handleKillswitch(request, env);
      }

      if (path === '/api/v1/validate' && request.method === 'POST') {
        return await handleValidate(request, env);
      }

      if (path === '/api/v1/admin/ban' && request.method === 'POST') {
        return await handleAdminBan(request, env);
      }

      if (path === '/api/v1/admin/unban' && request.method === 'POST') {
        return await handleAdminUnban(request, env);
      }

      if (path === '/api/v1/admin/list' && request.method === 'GET') {
        return await handleAdminList(request, env);
      }

      // License management endpoints
      if (path === '/api/v1/admin/license/create' && request.method === 'POST') {
        return await handleCreateLicense(request, env);
      }

      if (path === '/api/v1/admin/license/revoke' && request.method === 'POST') {
        return await handleRevokeLicense(request, env);
      }

      if (path === '/api/v1/admin/license/list' && request.method === 'GET') {
        return await handleListLicenses(request, env);
      }

      // Health check
      if (path === '/health' || path === '/') {
        return jsonResponse({ status: 'ok', product: env.PRODUCT_NAME });
      }

      return jsonResponse({ error: 'Not found' }, 404);
    } catch (error) {
      console.error('Error:', error);
      return jsonResponse({ error: 'Internal server error' }, 500);
    }
  },
};

/**
 * Check killswitch status
 * Called by scanner on startup and periodically during scans
 */
async function handleKillswitch(request: Request, env: Env): Promise<Response> {
  const hardwareId = request.headers.get('X-Hardware-ID');
  const clientIP = request.headers.get('CF-Connecting-IP') || '';

  // Check global killswitch first
  const globalKillswitch = await env.KILLSWITCH.get('global', 'json') as KillswitchEntry | null;
  if (globalKillswitch?.active) {
    return jsonResponse({
      active: true,
      reason: globalKillswitch.reason,
      message: 'Lonkero has been temporarily disabled. Please check https://bountyy.fi for updates.',
      revoked_keys: [],
    });
  }

  // Check hardware ID ban
  if (hardwareId) {
    const hwBan = await env.KILLSWITCH.get(`hw:${hardwareId}`, 'json') as KillswitchEntry | null;
    if (hwBan?.active) {
      return jsonResponse({
        active: true,
        reason: hwBan.reason,
        message: 'Your device has been blocked. Contact support@bountyy.fi if you believe this is an error.',
        revoked_keys: [],
      });
    }
  }

  // Check IP ban
  if (clientIP) {
    const ipBan = await env.KILLSWITCH.get(`ip:${clientIP}`, 'json') as KillswitchEntry | null;
    if (ipBan?.active) {
      return jsonResponse({
        active: true,
        reason: ipBan.reason,
        message: 'Your IP has been blocked due to abuse. Contact support@bountyy.fi',
        revoked_keys: [],
      });
    }
  }

  // Get list of revoked license keys (for client-side checking)
  const revokedKeys = await getRevokedKeys(env);

  return jsonResponse({
    active: false,
    reason: null,
    message: null,
    revoked_keys: revokedKeys,
  });
}

/**
 * Validate a license key
 * By default, returns a valid personal license with full features
 */
async function handleValidate(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as ValidateRequest;
  const hardwareId = body.hardware_id || request.headers.get('X-Hardware-ID');
  const clientIP = request.headers.get('CF-Connecting-IP') || '';

  // Check if this hardware/IP is banned
  if (hardwareId) {
    const hwBan = await env.KILLSWITCH.get(`hw:${hardwareId}`, 'json') as KillswitchEntry | null;
    if (hwBan?.active) {
      return jsonResponse({
        valid: false,
        killswitch_active: true,
        killswitch_reason: hwBan.reason,
        message: 'Your device has been blocked.',
      }, 403);
    }
  }

  if (clientIP) {
    const ipBan = await env.KILLSWITCH.get(`ip:${clientIP}`, 'json') as KillswitchEntry | null;
    if (ipBan?.active) {
      return jsonResponse({
        valid: false,
        killswitch_active: true,
        killswitch_reason: ipBan.reason,
        message: 'Your IP has been blocked.',
      }, 403);
    }
  }

  // Check if license key is provided and banned
  if (body.license_key) {
    const keyBan = await env.KILLSWITCH.get(`key:${hashKey(body.license_key)}`, 'json') as KillswitchEntry | null;
    if (keyBan?.active) {
      return jsonResponse({
        valid: false,
        killswitch_active: true,
        killswitch_reason: keyBan.reason,
        message: 'This license key has been revoked.',
      }, 403);
    }

    // Check if it's a registered commercial license
    const license = await env.LICENSES.get(`license:${hashKey(body.license_key)}`, 'json') as LicenseEntry | null;
    if (license) {
      // Check expiration
      if (license.expires_at && new Date(license.expires_at) < new Date()) {
        return jsonResponse({
          valid: false,
          license_type: license.license_type,
          message: 'License has expired. Please renew at https://bountyy.fi/license',
        });
      }

      return jsonResponse({
        valid: true,
        license_type: license.license_type,
        licensee: license.licensee,
        organization: license.organization,
        max_targets: license.max_targets,
        features: license.features,
        expires_at: license.expires_at,
        killswitch_active: false,
        message: 'License validated successfully',
      });
    }
  }

  // DEFAULT: Return valid personal license with FULL functionality
  // This is the key part - everyone gets full features by default
  return jsonResponse({
    valid: true,
    license_type: 'personal',
    licensee: null,
    organization: null,
    max_targets: 100,  // Generous default
    features: [
      'all_scanners',
      'all_outputs',
      'subdomain_enum',
      'crawler',
      'cloud_scanning',
      'api_fuzzing',
    ],
    expires_at: null,
    killswitch_active: false,
    message: 'Running in non-commercial mode. For commercial use, obtain a license at https://bountyy.fi/license',
  });
}

/**
 * Admin: Ban a user/hardware/IP
 */
async function handleAdminBan(request: Request, env: Env): Promise<Response> {
  if (!verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const body = await request.json() as BanRequest;

  if (!body.type || !body.value || !body.reason) {
    return jsonResponse({ error: 'Missing required fields: type, value, reason' }, 400);
  }

  let key: string;
  switch (body.type) {
    case 'hardware_id':
      key = `hw:${body.value}`;
      break;
    case 'license_key':
      key = `key:${hashKey(body.value)}`;
      break;
    case 'ip':
      key = `ip:${body.value}`;
      break;
    default:
      return jsonResponse({ error: 'Invalid type. Must be: hardware_id, license_key, or ip' }, 400);
  }

  const entry: KillswitchEntry = {
    active: true,
    reason: body.reason,
    banned_at: new Date().toISOString(),
    banned_by: 'admin',
    type: body.type,
  };

  await env.KILLSWITCH.put(key, JSON.stringify(entry));

  // Log the action
  console.log(`BANNED: ${body.type} = ${body.value}, reason: ${body.reason}`);

  return jsonResponse({
    success: true,
    message: `Banned ${body.type}: ${body.value}`,
    key,
  });
}

/**
 * Admin: Unban a user/hardware/IP
 */
async function handleAdminUnban(request: Request, env: Env): Promise<Response> {
  if (!verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const body = await request.json() as BanRequest;

  if (!body.type || !body.value) {
    return jsonResponse({ error: 'Missing required fields: type, value' }, 400);
  }

  let key: string;
  switch (body.type) {
    case 'hardware_id':
      key = `hw:${body.value}`;
      break;
    case 'license_key':
      key = `key:${hashKey(body.value)}`;
      break;
    case 'ip':
      key = `ip:${body.value}`;
      break;
    default:
      return jsonResponse({ error: 'Invalid type' }, 400);
  }

  await env.KILLSWITCH.delete(key);

  console.log(`UNBANNED: ${body.type} = ${body.value}`);

  return jsonResponse({
    success: true,
    message: `Unbanned ${body.type}: ${body.value}`,
  });
}

/**
 * Admin: List all banned entries
 */
async function handleAdminList(request: Request, env: Env): Promise<Response> {
  if (!verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const list = await env.KILLSWITCH.list();
  const entries: Array<{ key: string; entry: KillswitchEntry }> = [];

  for (const key of list.keys) {
    const entry = await env.KILLSWITCH.get(key.name, 'json') as KillswitchEntry;
    if (entry) {
      entries.push({ key: key.name, entry });
    }
  }

  return jsonResponse({
    count: entries.length,
    entries,
  });
}

// Helper functions

function verifyAdmin(request: Request, env: Env): boolean {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) return false;

  const token = authHeader.replace('Bearer ', '');
  return token === env.ADMIN_API_KEY;
}

function hashKey(key: string): string {
  // Simple hash for KV keys - in production use crypto.subtle
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    const char = key.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16);
}

async function getRevokedKeys(env: Env): Promise<string[]> {
  const list = await env.KILLSWITCH.list({ prefix: 'key:' });
  return list.keys.map(k => k.name.replace('key:', ''));
}

function jsonResponse(data: object, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
    },
  });
}

/**
 * Generate a license key
 * Format: LONKERO-XXXX-XXXX-XXXX-XXXX
 */
function generateLicenseKey(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No I, O, 0, 1 to avoid confusion
  const segments = [];
  for (let s = 0; s < 4; s++) {
    let segment = '';
    for (let i = 0; i < 4; i++) {
      segment += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    segments.push(segment);
  }
  return `LONKERO-${segments.join('-')}`;
}

/**
 * Admin: Create a commercial license for a paying customer
 */
async function handleCreateLicense(request: Request, env: Env): Promise<Response> {
  if (!verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const body = await request.json() as CreateLicenseRequest;

  if (!body.license_type || !body.licensee || !body.email) {
    return jsonResponse({
      error: 'Missing required fields: license_type, licensee, email',
    }, 400);
  }

  // Generate unique license key
  const licenseKey = generateLicenseKey();

  // Set defaults based on license type
  let maxTargets = body.max_targets;
  let features: string[] = [];

  switch (body.license_type) {
    case 'professional':
      maxTargets = maxTargets || 50;
      features = ['all_scanners', 'all_outputs', 'subdomain_enum', 'crawler', 'priority_support'];
      break;
    case 'team':
      maxTargets = maxTargets || 200;
      features = ['all_scanners', 'all_outputs', 'subdomain_enum', 'crawler', 'cloud_scanning', 'api_fuzzing', 'priority_support', 'team_sharing'];
      break;
    case 'enterprise':
      maxTargets = maxTargets || 10000;
      features = ['all_scanners', 'all_outputs', 'subdomain_enum', 'crawler', 'cloud_scanning', 'api_fuzzing', 'priority_support', 'team_sharing', 'custom_integrations', 'sla_support', 'on_premise'];
      break;
  }

  // Calculate expiration
  let expiresAt: string | undefined;
  if (body.expires_days) {
    const expDate = new Date();
    expDate.setDate(expDate.getDate() + body.expires_days);
    expiresAt = expDate.toISOString();
  }

  const license: LicenseEntry = {
    license_key: licenseKey,
    license_type: body.license_type,
    licensee: body.licensee,
    email: body.email,
    organization: body.organization,
    max_targets: maxTargets!,
    features,
    created_at: new Date().toISOString(),
    expires_at: expiresAt,
    notes: body.notes,
  };

  // Store in KV (key is hash of license key for lookup)
  const keyHash = hashKey(licenseKey);
  await env.LICENSES.put(`license:${keyHash}`, JSON.stringify(license));

  // Also store by email for easy lookup
  await env.LICENSES.put(`email:${body.email}`, JSON.stringify({ license_key: licenseKey, key_hash: keyHash }));

  console.log(`LICENSE CREATED: ${body.license_type} for ${body.licensee} (${body.email})`);

  return jsonResponse({
    success: true,
    license_key: licenseKey,
    license_type: body.license_type,
    licensee: body.licensee,
    organization: body.organization,
    max_targets: maxTargets,
    features,
    expires_at: expiresAt,
    message: `License created! Send this key to the customer: ${licenseKey}`,
  });
}

/**
 * Admin: Revoke a commercial license
 */
async function handleRevokeLicense(request: Request, env: Env): Promise<Response> {
  if (!verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const body = await request.json() as { license_key?: string; email?: string; reason?: string };

  if (!body.license_key && !body.email) {
    return jsonResponse({ error: 'Provide either license_key or email' }, 400);
  }

  let keyHash: string;

  if (body.license_key) {
    keyHash = hashKey(body.license_key);
  } else {
    // Look up by email
    const emailEntry = await env.LICENSES.get(`email:${body.email}`, 'json') as { key_hash: string } | null;
    if (!emailEntry) {
      return jsonResponse({ error: 'No license found for this email' }, 404);
    }
    keyHash = emailEntry.key_hash;
  }

  // Get license details before deleting
  const license = await env.LICENSES.get(`license:${keyHash}`, 'json') as LicenseEntry | null;

  if (!license) {
    return jsonResponse({ error: 'License not found' }, 404);
  }

  // Delete the license
  await env.LICENSES.delete(`license:${keyHash}`);
  await env.LICENSES.delete(`email:${license.email}`);

  // Optionally add to killswitch to block the key
  if (body.reason) {
    const killEntry: KillswitchEntry = {
      active: true,
      reason: body.reason,
      banned_at: new Date().toISOString(),
      banned_by: 'admin',
      type: 'license_key',
    };
    await env.KILLSWITCH.put(`key:${keyHash}`, JSON.stringify(killEntry));
  }

  console.log(`LICENSE REVOKED: ${license.licensee} (${license.email})`);

  return jsonResponse({
    success: true,
    message: `License revoked for ${license.licensee}`,
    revoked_license: {
      licensee: license.licensee,
      email: license.email,
      license_type: license.license_type,
    },
  });
}

/**
 * Admin: List all commercial licenses
 */
async function handleListLicenses(request: Request, env: Env): Promise<Response> {
  if (!verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const list = await env.LICENSES.list({ prefix: 'license:' });
  const licenses: LicenseEntry[] = [];

  for (const key of list.keys) {
    const license = await env.LICENSES.get(key.name, 'json') as LicenseEntry;
    if (license) {
      licenses.push(license);
    }
  }

  // Sort by created date descending
  licenses.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return jsonResponse({
    count: licenses.length,
    licenses: licenses.map(l => ({
      license_key: l.license_key,
      license_type: l.license_type,
      licensee: l.licensee,
      email: l.email,
      organization: l.organization,
      max_targets: l.max_targets,
      created_at: l.created_at,
      expires_at: l.expires_at,
      is_expired: l.expires_at ? new Date(l.expires_at) < new Date() : false,
    })),
  });
}
