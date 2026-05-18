import os
import json
import gzip
import time
import requests
import msgpack
from flask import Flask, request, jsonify, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ==================== CONFIGURATION ====================
REGION_CONFIG = {
    'get_backpack_url': 'https://clientbp.ggpolarbear.com/GetBackpack',
    'client_host': 'clientbp.ggpolarbear.com',
}
BACKPACK_BODY_HEX = "1a725b2c56ec52ba7d09623454c0a003"
BACKPACK_BODY_BYTES = bytes.fromhex(BACKPACK_BODY_HEX)

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

_item_db_cache = None
_db_cache_time = 0
DB_CACHE_TTL = 3600

# ==================== ITEM DATABASE ====================
def get_item_database():
    global _item_db_cache, _db_cache_time
    now = time.time()
    if _item_db_cache and (now - _db_cache_time) < DB_CACHE_TTL:
        return _item_db_cache
    try:
        resp = requests.get("https://ff-item.netlify.app/data.msgpack.gz", timeout=15)
        resp.raise_for_status()
        decompressed = gzip.decompress(resp.content)
        items = msgpack.unpackb(decompressed, raw=False)
        item_map = {item['itemID']: item for item in items if item.get('itemID')}
        _item_db_cache = item_map
        _db_cache_time = now
        print(f"✅ Item database refreshed: {len(item_map)} items")
        return item_map
    except Exception as e:
        print(f"❌ Failed to fetch item database: {e}")
        return _item_db_cache or {}

# ==================== JWT FROM THIRD-PARTY API ====================
def get_jwt_from_api(uid, password):
    url = f"https://spidey-jwt-gen.vercel.app/guest?uid={uid}&password={password}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data.get("token"), None
            else:
                return None, f"API returned: {data.get('status')}"
        else:
            return None, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, str(e)

# ==================== BACKPACK FETCHING ====================
def decrypt_aes_cbc(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    try:
        return unpad(cipher.decrypt(data), AES.block_size)
    except:
        return None

def decode_varint(data, offset):
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("Truncated varint")
        b = data[offset]
        value |= (b & 0x7F) << shift
        offset += 1
        if not (b & 0x80):
            break
        shift += 7
    return value, offset

def parse_protobuf(data, start=0):
    fields = []
    idx = start
    while idx < len(data):
        try:
            key, idx = decode_varint(data, idx)
        except ValueError:
            break
        field_num = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, idx = decode_varint(data, idx)
            fields.append({'num': field_num, 'type': 0, 'value': value, 'nested': None})
        elif wire_type == 1:
            if idx + 8 > len(data):
                raise ValueError("Truncated 64-bit")
            value = int.from_bytes(data[idx:idx+8], 'little')
            idx += 8
            fields.append({'num': field_num, 'type': 1, 'value': value, 'nested': None})
        elif wire_type == 2:
            length, idx = decode_varint(data, idx)
            if idx + length > len(data):
                return fields, idx
            raw = data[idx:idx+length]
            idx += length
            nested = None
            try:
                nested, _ = parse_protobuf(raw, 0)
            except:
                pass
            fields.append({'num': field_num, 'type': 2, 'value': raw, 'nested': nested})
        elif wire_type == 5:
            if idx + 4 > len(data):
                raise ValueError("Truncated 32-bit")
            value = int.from_bytes(data[idx:idx+4], 'little')
            idx += 4
            fields.append({'num': field_num, 'type': 5, 'value': value, 'nested': None})
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
    return fields, idx

def collect_item_ids(fields):
    ids = []
    for f in fields:
        if f['num'] == 3 and f['type'] == 2 and f['nested'] is not None:
            for sub in f['nested']:
                if sub['num'] == 1 and sub['type'] == 0:
                    ids.append(sub['value'])
        if f['nested']:
            ids.extend(collect_item_ids(f['nested']))
    return ids

def fetch_backpack(jwt_token):
    headers = {
        "Host": REGION_CONFIG['client_host'],
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }
    try:
        resp = requests.post(REGION_CONFIG['get_backpack_url'], headers=headers, data=BACKPACK_BODY_BYTES, timeout=15)
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        raw = resp.content
        plain = decrypt_aes_cbc(raw)
        data = plain if plain is not None else raw
        fields, _ = parse_protobuf(data, 0)
        ids = collect_item_ids(fields)
        return ids, None
    except Exception as e:
        return None, str(e)

# ==================== HTML TEMPLATE (same as before) ====================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🇹🇼 Taiwan Free Fire Vault Viewer</title>
    <style>
        /* your existing CSS – keep it exactly as before */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0e1a 0%, #0f1222 100%);
            color: #eef2ff;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, #fff, #ffcc00);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 8px;
        }
        .header p { color: #8b92b0; }
        .card {
            background: rgba(18, 22, 40, 0.9);
            backdrop-filter: blur(10px);
            border-radius: 28px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 204, 0, 0.2);
            box-shadow: 0 20px 35px -10px rgba(0,0,0,0.4);
        }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 500; color: #ffcc00; }
        input {
            width: 100%;
            padding: 14px 18px;
            background: #0c0f1c;
            border: 1px solid #2a2f45;
            border-radius: 16px;
            color: white;
            font-size: 1rem;
            transition: all 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #ffcc00;
            box-shadow: 0 0 0 3px rgba(255,204,0,0.2);
        }
        button {
            background: linear-gradient(90deg, #ffcc00, #ff9900);
            border: none;
            padding: 14px 24px;
            font-weight: bold;
            font-size: 1rem;
            border-radius: 40px;
            cursor: pointer;
            transition: transform 0.1s, box-shadow 0.2s;
            width: 100%;
            color: #0a0e1a;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px -5px rgba(255,204,0,0.4);
        }
        .stats {
            background: #0c0f1c;
            border-radius: 20px;
            padding: 15px 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 15px;
        }
        .stat { font-size: 0.9rem; }
        .stat span { color: #ffcc00; font-weight: bold; font-size: 1.3rem; }
        .search-bar { display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }
        .search-bar input { flex: 2; min-width: 200px; }
        .search-bar select { flex: 1; min-width: 150px; }
        .category { margin-bottom: 40px; }
        .category h2 {
            font-size: 1.6rem;
            border-left: 5px solid #ffcc00;
            padding-left: 15px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .item-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 20px;
        }
        .item-card {
            background: #12172e;
            border-radius: 20px;
            padding: 15px;
            text-align: center;
            transition: all 0.2s;
            border: 1px solid #1e2540;
        }
        .item-card:hover {
            transform: translateY(-5px);
            border-color: #ffcc00;
            box-shadow: 0 10px 20px rgba(0,0,0,0.3);
        }
        .item-icon {
            width: 90px;
            height: 90px;
            margin: 0 auto 10px;
            background: #0a0e1a;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }
        .item-icon img { max-width: 100%; max-height: 100%; object-fit: contain; }
        .item-name { font-weight: 600; font-size: 0.9rem; margin: 8px 0 4px; }
        .item-rarity { font-size: 0.7rem; color: #ffcc00; margin-bottom: 4px; }
        .item-id { font-size: 0.65rem; color: #6c7293; }
        .item-description {
            font-size: 0.7rem;
            color: #a0a5c0;
            margin-top: 6px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
        .error { background: rgba(255,70,70,0.2); border-left: 4px solid #ff4646; padding: 15px; border-radius: 16px; margin-bottom: 20px; }
        .loading { text-align: center; padding: 40px; }
        .footer { text-align: center; margin-top: 50px; font-size: 0.8rem; color: #5a6080; }
        @media (max-width: 700px) {
            .item-grid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
            .item-icon { width: 70px; height: 70px; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Taiwan Free Fire Vault Viewer</h1>
        <p>Professional • Secure • Real-time</p>
    </div>
    <div class="card">
        <form id="vaultForm">
            <div class="form-group">
                <label>📱 UID</label>
                <input type="text" id="uid" placeholder="Enter your UID" required>
            </div>
            <div class="form-group">
                <label>🔒 Password</label>
                <input type="password" id="password" placeholder="Account password" required>
            </div>
            <button type="submit">🚀 Fetch Vault</button>
        </form>
        <div id="formError" class="error" style="display:none;"></div>
    </div>
    <div id="results" style="display:none;">
        <div class="stats" id="stats"></div>
        <div class="search-bar">
            <input type="text" id="searchInput" placeholder="🔍 Search by name or ID...">
            <select id="typeFilter"><option value="all">All Types</option></select>
        </div>
        <div id="categoriesContainer"></div>
    </div>
    <div class="footer"><p>Item information from ff-item.netlify.app • No credentials are stored</p></div>
</div>
<script>
    const form = document.getElementById('vaultForm');
    const formError = document.getElementById('formError');
    const resultsDiv = document.getElementById('results');
    const statsDiv = document.getElementById('stats');
    const searchInput = document.getElementById('searchInput');
    const typeFilter = document.getElementById('typeFilter');
    const categoriesContainer = document.getElementById('categoriesContainer');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        formError.style.display = 'none';
        resultsDiv.style.display = 'none';
        const uid = document.getElementById('uid').value.trim();
        const password = document.getElementById('password').value;
        if (!uid || !password) { showError('Please enter both UID and Password'); return; }
        resultsDiv.style.display = 'block';
        categoriesContainer.innerHTML = '<div class="loading">⏳ Fetching vault data... This may take a few seconds.</div>';
        try {
            const response = await fetch('/api/fetch_vault', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ uid, password })
            });
            const data = await response.json();
            if (!response.ok || data.error) { showError(data.error || 'Unknown error'); resultsDiv.style.display = 'none'; return; }
            renderVault(data);
        } catch (err) { showError('Network error: ' + err.message); resultsDiv.style.display = 'none'; }
    });
    function showError(msg) { formError.textContent = msg; formError.style.display = 'block'; setTimeout(() => formError.style.display = 'none', 5000); }
    let fullVaultData = null;
    function renderVault(data) {
        fullVaultData = data;
        statsDiv.innerHTML = `<div class="stat">📦 Total Items: <span>${data.total_items}</span></div><div class="stat">📂 Categories: <span>${Object.keys(data.grouped).length}</span></div><div class="stat">⭐ Rarest items: <span>${data.rarest_count || 0}</span></div>`;
        typeFilter.innerHTML = '<option value="all">All Types</option>';
        for (const type of Object.keys(data.grouped).sort()) { typeFilter.innerHTML += `<option value="${escapeHtml(type)}">${escapeHtml(type)} (${data.grouped[type].length})</option>`; }
        searchInput.oninput = () => filterAndRender();
        typeFilter.onchange = () => filterAndRender();
        filterAndRender();
    }
    function filterAndRender() {
        if (!fullVaultData) return;
        const searchTerm = searchInput.value.toLowerCase();
        const selectedType = typeFilter.value;
        let filteredGroups = {};
        for (const [type, items] of Object.entries(fullVaultData.grouped)) {
            if (selectedType !== 'all' && type !== selectedType) continue;
            let filteredItems = items.filter(item => item.name.toLowerCase().includes(searchTerm) || item.id.toString().includes(searchTerm));
            if (filteredItems.length) filteredGroups[type] = filteredItems;
        }
        renderCategories(filteredGroups);
    }
    function renderCategories(groups) {
        if (Object.keys(groups).length === 0) { categoriesContainer.innerHTML = '<div class="loading">🔍 No items match your search.</div>'; return; }
        let html = '';
        for (const [type, items] of Object.entries(groups).sort()) {
            html += `<div class="category"><h2>📁 ${escapeHtml(type)} <span style="font-size:0.9rem;">(${items.length})</span></h2><div class="item-grid">`;
            for (const item of items) {
                const iconUrl = `https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/${item.id}.png`;
                const rarityColor = item.rare ? `color: ${getRarityColor(item.rare)}` : '';
                html += `<div class="item-card">
                            <div class="item-icon"><img src="${iconUrl}" alt="icon" onerror="this.src='https://via.placeholder.com/90?text=❓'"></div>
                            <div class="item-name">${escapeHtml(item.name)}</div>
                            <div class="item-rarity" style="${rarityColor}">${escapeHtml(item.rare || 'Common')}</div>
                            <div class="item-id">ID: ${item.id}</div>
                            <div class="item-description">${escapeHtml(item.description || 'No description')}</div>
                         </div>`;
            }
            html += `</div></div>`;
        }
        categoriesContainer.innerHTML = html;
    }
    function getRarityColor(rarity) {
        const r = rarity.toLowerCase();
        if (r.includes('legendary')) return '#ff8000';
        if (r.includes('epic')) return '#aa4eff';
        if (r.includes('rare')) return '#2a9df4';
        if (r.includes('mythic')) return '#ff4444';
        return '#ffcc00';
    }
    function escapeHtml(str) { return str.replace(/[&<>]/g, function(m) { if (m === '&') return '&amp;'; if (m === '<') return '&lt;'; if (m === '>') return '&gt;'; return m; }); }
</script>
</body>
</html>"""

# ==================== FLASK ROUTES ====================
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/fetch_vault', methods=['POST'])
def fetch_vault_api():
    data = request.get_json()
    uid = data.get('uid')
    password = data.get('password')
    if not uid or not password:
        return jsonify({'error': 'Missing UID or password'}), 400

    jwt_token, err = get_jwt_from_api(uid, password)
    if err:
        return jsonify({'error': f'Authentication failed: {err}'}), 401

    item_ids, err = fetch_backpack(jwt_token)
    if err:
        return jsonify({'error': f'Failed to fetch vault: {err}'}), 500

    item_map = get_item_database()
    grouped = defaultdict(list)
    rarest_count = 0
    for iid in item_ids:
        info = item_map.get(iid, {})
        typ = info.get('type', 'Unknown')
        rare = info.get('Rare', '')
        if rare.lower() in ['legendary', 'mythic']:
            rarest_count += 1
        grouped[typ].append({
            'id': iid,
            'name': info.get('name', f'Item {iid}'),
            'rare': rare,
            'description': info.get('description', '')
        })
    for typ in grouped:
        grouped[typ].sort(key=lambda x: x['name'])

    return jsonify({
        'total_items': len(item_ids),
        'rarest_count': rarest_count,
        'grouped': dict(grouped)
    })

# Vercel requires the app to be the handler
app.debug = False