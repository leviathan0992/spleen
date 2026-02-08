package main

/* staticHTML contains the embedded web dashboard HTML. */
const staticHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>内网穿透控制台</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: #475569;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logout-btn {
            background: var(--danger);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
        }
        
        /* Read-only banner */
        .readonly-banner {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .readonly-banner::before {
            content: "!";
        }
        
        /* Cards */
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 30px; }
        .card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border);
        }
        .card-label { color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 8px; }
        .card-value { font-size: 1.5rem; font-weight: 600; }
        .card-value.online { color: var(--success); }
        .card-value.offline { color: var(--danger); }
        
        /* Section */
        .section {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        .section-title { font-size: 1.125rem; font-weight: 600; }
        
        /* Table */
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: var(--text-secondary); font-weight: 500; }
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .status-online { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .status-offline { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        
        /* Login */
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            background: var(--bg-secondary);
            padding: 40px;
            border-radius: 12px;
            border: 1px solid var(--border);
        }
        .login-title { text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 16px; }
        .form-label { display: block; margin-bottom: 6px; color: var(--text-secondary); }
        .form-input {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 1rem;
        }
        .form-input:focus { border-color: var(--accent); outline: none; }
        .btn-primary {
            width: 100%;
            padding: 12px;
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-primary:hover { background: var(--accent-hover); }
        .error-msg { color: var(--danger); text-align: center; margin-top: 16px; display: none; }
        
        /* Hidden */
        .hidden { display: none; }
    </style>
</head>
<body>
    <!-- Login Page -->
    <div id="login-page" class="login-container">
        <h2 class="login-title">内网穿透控制台</h2>
        <form id="login-form">
            <div class="form-group">
                <label class="form-label">用户名</label>
                <input type="text" class="form-input" id="username" value="admin" required>
            </div>
            <div class="form-group">
                <label class="form-label">密码</label>
                <input type="password" class="form-input" id="password" required>
            </div>
            <button type="submit" class="btn-primary">登录</button>
            <p class="error-msg" id="login-error"></p>
        </form>
    </div>

    <!-- Dashboard -->
    <div id="dashboard" class="container hidden">
        <div class="header">
            <h1>内网穿透控制台</h1>
            <button class="logout-btn" onclick="logout()">退出登录</button>
        </div>
        
        <div class="readonly-banner">
            <div>
                <strong>只读模式</strong>：规则管理请编辑配置文件 <code>.spleen-server.json</code> 后重启服务
            </div>
        </div>

        <div class="cards">
            <div class="card">
                <div class="card-label">系统运行时间</div>
                <div class="card-value" id="uptime">-</div>
            </div>
            <div class="card">
                <div class="card-label">映射规则</div>
                <div class="card-value" id="rules-count">-</div>
            </div>
            <div class="card">
                <div class="card-label">在线内网服务器</div>
                <div class="card-value online" id="online-servers">-</div>
            </div>
            <div class="card">
                <div class="card-label">安全状态</div>
                <div class="card-value" id="security-status">-</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <span class="section-title">映射规则</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>编号</th>
                        <th>名称</th>
                        <th>内网服务器</th>
                        <th>公网端口</th>
                        <th>目标端口</th>
                        <th>备注</th>
                    </tr>
                </thead>
                <tbody id="rules-table"></tbody>
            </table>
        </div>

        <div class="section">
            <div class="section-header">
                <span class="section-title">内网服务器状态</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>状态</th>
                        <th>隧道数</th>
                        <th>活动连接</th>
                        <th>最后心跳</th>
                    </tr>
                </thead>
                <tbody id="servers-table"></tbody>
            </table>
        </div>
    </div>

    <script>
    const API = {
        login: '/api/login',
        logout: '/api/logout',
        status: '/api/status',
        servers: '/api/servers',
        rules: '/api/mapping_rules'
    };

    async function req(url, options = {}) {
        const res = await fetch(url, {
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            ...options
        });
        if (res.status === 401) {
            showLogin();
            throw new Error('未授权');
        }
        return res.json();
    }

    function showLogin() {
        document.getElementById('login-page').classList.remove('hidden');
        document.getElementById('dashboard').classList.add('hidden');
    }

    function showDashboard() {
        document.getElementById('login-page').classList.add('hidden');
        document.getElementById('dashboard').classList.remove('hidden');
        loadData();
    }

    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const errorEl = document.getElementById('login-error');
        errorEl.style.display = 'none';
        
        try {
            const res = await fetch(API.login, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            });
            const data = await res.json();
            if (res.ok) {
                showDashboard();
            } else {
                errorEl.textContent = data.error || '登录失败';
                errorEl.style.display = 'block';
            }
        } catch (err) {
            errorEl.textContent = '网络错误';
            errorEl.style.display = 'block';
        }
    });

    async function logout() {
        await fetch(API.logout, {method: 'POST', credentials: 'include'});
        showLogin();
    }

    function formatUptime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return h > 0 ? h + '小时 ' + m + '分钟' : m + '分钟';
    }

    function escapeHTML(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    async function loadData() {
        try {
            // Status
            const status = await req(API.status);
            document.getElementById('uptime').textContent = formatUptime(status.uptime);
            document.getElementById('rules-count').textContent = status.rules_count;
            document.getElementById('online-servers').textContent = status.online_servers;
            document.getElementById('security-status').textContent = status.security_summary;

            // Rules (simplified: name, ports, remark only)
            const rules = await req(API.rules);
            const rulesTable = document.getElementById('rules-table');
            rulesTable.innerHTML = rules.map((r, idx) => '<tr><td>' + (idx + 1) + '</td><td>' + escapeHTML(r.id||'-') + '</td><td>' + escapeHTML(r.client_id||'-') + '</td><td>' + escapeHTML(r.public_port) + '</td><td>' + escapeHTML(r.target_port) + '</td><td>' + escapeHTML(r.remark||'-') + '</td></tr>').join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary)">暂无映射规则</td></tr>';

            // Servers (simplified: status, tunnel count, active conns, last seen)
            const servers = await req(API.servers);
            const serversTable = document.getElementById('servers-table');
            serversTable.innerHTML = (servers.servers || []).map(s => {
                const statusClass = s.online ? 'status-online' : 'status-offline';
                const statusText = s.online ? '在线' : '离线';
                return '<tr><td><span class="status-badge ' + statusClass + '">' + statusText + '</span></td><td>' + escapeHTML(s.tunnel_count) + '</td><td>' + escapeHTML(s.active_conns) + '</td><td>' + escapeHTML(s.last_seen) + '</td></tr>';
            }).join('') || '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">暂无内网服务器连接</td></tr>';
        } catch (err) {
            console.error('加载数据失败:', err);
        }
    }

    // Check auth and auto-refresh
    (async function init() {
        try {
            await req(API.status);
            showDashboard();
        } catch {
            showLogin();
        }
    })();

    setInterval(() => {
        if (!document.getElementById('dashboard').classList.contains('hidden')) {
            loadData();
        }
    }, 5000);
    </script>
</body>
</html>`
