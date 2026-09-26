const http = require('node:http');
const url = require('node:url');
const fs = require('node:fs');
const path = require('node:path');
const {
  db,
  hashPassword,
  withTransaction,
  getProductCompanyStock,
  getLocationStock,
  setOrUpdateLocationStock,
  logLedger,
  resetDatabase,
  executeGuidedDemoStep,
  createSession,
  getUserFromSession,
  deleteSession
} = require('./db.js');

function getAuthToken(req) {
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  return null;
}

function authenticateRequest(req) {
  const token = getAuthToken(req);
  if (!token) return null;
  return getUserFromSession(token);
}

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// MIME types for static assets
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.csv': 'text/csv; charset=utf-8'
};

// Simple helper to send JSON response
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  });
  res.end(JSON.stringify(data));
}

// Simple helper to parse JSON body
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) {
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error('Invalid JSON format'));
      }
    });
    req.on('error', reject);
  });
}

// Generate human-friendly reference codes
function generateReference(prefix) {
  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `${prefix}-${dateStr}-${rand}`;
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const query = parsedUrl.query;
  const method = req.method;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
    });
    return res.end();
  }

  // -------------------------------------------------------------
  // API ROUTER
  // -------------------------------------------------------------
  if (pathname.startsWith('/api/')) {
    try {
      // 1. AUTH: LOGIN
      if (pathname === '/api/auth/login' && method === 'POST') {
        const { email, password, rememberMe } = await parseBody(req);
        if (!email || !password) {
          return sendJson(res, 400, { error: 'Email and password are required' });
        }
        const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email.trim().toLowerCase());
        if (!user || user.password_hash !== hashPassword(password)) {
          return sendJson(res, 401, { error: 'Invalid email or password. Please try again.' });
        }
        const { password_hash, ...safeUser } = user;
        const session = createSession(user.id, rememberMe !== false);
        return sendJson(res, 200, { user: safeUser, token: session.token, expiresAt: session.expiresAt });
      }

      // 2. AUTH: REGISTER
      if (pathname === '/api/auth/register' && method === 'POST') {
        const { name, email, password, role, department } = await parseBody(req);
        if (!name || !email || !password) {
          return sendJson(res, 400, { error: 'Name, email, and password are required' });
        }
        if (password.length < 6) {
          return sendJson(res, 400, { error: 'Password must be at least 6 characters long' });
        }
        const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email.trim().toLowerCase());
        if (existing) {
          return sendJson(res, 400, { error: 'An account with this email already exists' });
        }
        const userRole = role === 'warehouse_staff' ? 'warehouse_staff' : 'inventory_manager';
        const initials = name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2) || 'US';
        const result = db.prepare(`
          INSERT INTO users (name, email, password_hash, role, department, avatar)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(name.trim(), email.trim().toLowerCase(), hashPassword(password), userRole, department || 'Operations', initials);

        const newUser = db.prepare(`SELECT id, name, email, role, department, avatar, created_at FROM users WHERE id = ?`).get(result.lastInsertRowid);
        const session = createSession(newUser.id, true);
        return sendJson(res, 201, { user: newUser, token: session.token, expiresAt: session.expiresAt });
      }

      // 3. AUTH: FORGOT PASSWORD (Demo OTP Generator)
      if (pathname === '/api/auth/forgot-password' && method === 'POST') {
        const { email } = await parseBody(req);
        if (!email) return sendJson(res, 400, { error: 'Email is required' });
        const user = db.prepare(`SELECT id, email, name FROM users WHERE email = ?`).get(email.trim().toLowerCase());
        if (!user) {
          return sendJson(res, 404, { error: 'No account found with this email' });
        }
        // Generate simulated 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
        db.prepare(`DELETE FROM otp_codes WHERE email = ?`).run(user.email);
        db.prepare(`INSERT INTO otp_codes (email, otp, expires_at) VALUES (?, ?, ?)`).run(user.email, otp, expiresAt);
        return sendJson(res, 200, {
          success: true,
          message: 'OTP sent to registered email (Hackathon Demo Mode enabled)',
          demoOtp: otp,
          email: user.email,
          expiresInMinutes: 10
        });
      }

      // 4. AUTH: RESET PASSWORD
      if (pathname === '/api/auth/reset-password' && method === 'POST') {
        const { email, otp, newPassword } = await parseBody(req);
        if (!email || !otp || !newPassword) {
          return sendJson(res, 400, { error: 'Email, OTP code, and new password are required' });
        }
        const record = db.prepare(`SELECT * FROM otp_codes WHERE email = ? AND otp = ?`).get(email.trim().toLowerCase(), otp.trim());
        if (!record || record.expires_at < Date.now()) {
          return sendJson(res, 400, { error: 'Invalid or expired OTP code' });
        }
        db.prepare(`UPDATE users SET password_hash = ? WHERE email = ?`).run(hashPassword(newPassword), email.trim().toLowerCase());
        db.prepare(`DELETE FROM otp_codes WHERE email = ?`).run(email.trim().toLowerCase());
        return sendJson(res, 200, { success: true, message: 'Password has been reset successfully. Please log in.' });
      }

      // Check authentication for all protected endpoints below
      const authenticatedUser = authenticateRequest(req);
      if (!authenticatedUser) {
        return sendJson(res, 401, { error: 'Authentication required. Please sign in to access StockSense.' });
      }

      // 5. AUTH: GET CURRENT PROFILE
      if (pathname === '/api/auth/me' && method === 'GET') {
        return sendJson(res, 200, { user: authenticatedUser });
      }

      // 5b. AUTH: LOGOUT
      if (pathname === '/api/auth/logout' && method === 'POST') {
        const token = getAuthToken(req);
        if (token) deleteSession(token);
        return sendJson(res, 200, { success: true, message: 'Successfully logged out' });
      }

      // 6. DASHBOARD: DYNAMIC STATS & CHARTS
      if (pathname === '/api/dashboard/stats' && method === 'GET') {
        // Dynamic KPIs
        const totalStockRow = db.prepare(`SELECT COALESCE(SUM(quantity), 0) AS total_units FROM product_stocks`).get();
        const totalStock = totalStockRow.total_units;

        const allProducts = db.prepare(`
          SELECT p.id, p.name, p.sku, p.reorder_level, p.target_stock, p.unit_cost,
                 c.name as category_name, c.color as category_color,
                 COALESCE(SUM(ps.quantity), 0) as current_stock
          FROM products p
          LEFT JOIN categories c ON p.category_id = c.id
          LEFT JOIN product_stocks ps ON p.id = ps.product_id
          GROUP BY p.id
        `).all();

        const lowStockItems = allProducts.filter(p => p.current_stock > 0 && p.current_stock <= p.reorder_level);
        const outOfStockItems = allProducts.filter(p => p.current_stock === 0);
        const healthyItems = allProducts.filter(p => p.current_stock > p.reorder_level);

        const pendingReceipts = db.prepare(`SELECT COUNT(*) as count FROM receipts WHERE status IN ('draft', 'waiting', 'ready')`).get().count;
        const pendingDeliveries = db.prepare(`SELECT COUNT(*) as count FROM delivery_orders WHERE status IN ('draft', 'waiting', 'ready')`).get().count;
        const scheduledTransfers = db.prepare(`SELECT COUNT(*) as count FROM internal_transfers WHERE status IN ('draft', 'waiting', 'ready')`).get().count;

        // Inventory value
        const totalInventoryValue = allProducts.reduce((sum, p) => sum + (p.current_stock * p.unit_cost), 0);

        // Category breakdown
        const categoryStats = db.prepare(`
          SELECT c.id, c.name, c.color, c.icon,
                 COUNT(DISTINCT p.id) as product_count,
                 COALESCE(SUM(ps.quantity), 0) as total_units,
                 COALESCE(SUM(ps.quantity * p.unit_cost), 0) as total_value
          FROM categories c
          LEFT JOIN products p ON c.id = p.category_id
          LEFT JOIN product_stocks ps ON p.id = ps.product_id
          GROUP BY c.id
        `).all();

        // Warehouse summaries
        const warehouseSummaries = db.prepare(`
          SELECT w.id, w.code, w.name, w.manager_name,
                 COALESCE(SUM(ps.quantity), 0) as total_stock,
                 COUNT(DISTINCT ps.product_id) as active_products
          FROM warehouses w
          LEFT JOIN product_stocks ps ON w.id = ps.warehouse_id
          GROUP BY w.id
        `).all();

        // Add low stock count & pending operations per warehouse
        warehouseSummaries.forEach(wh => {
          const lowWh = db.prepare(`
            SELECT COUNT(DISTINCT p.id) as low_count
            FROM products p
            JOIN product_stocks ps ON p.id = ps.product_id
            WHERE ps.warehouse_id = ? AND ps.quantity <= p.reorder_level AND ps.quantity > 0
          `).get(wh.id);
          wh.low_stock_count = lowWh ? lowWh.low_count : 0;

          const pendingOps = db.prepare(`
            SELECT (
              (SELECT COUNT(*) FROM receipts WHERE warehouse_id = ? AND status IN ('draft', 'waiting', 'ready')) +
              (SELECT COUNT(*) FROM delivery_orders WHERE warehouse_id = ? AND status IN ('draft', 'waiting', 'ready')) +
              (SELECT COUNT(*) FROM internal_transfers WHERE (source_warehouse_id = ? OR dest_warehouse_id = ?) AND status IN ('draft', 'waiting', 'ready'))
            ) AS pending_count
          `).get(wh.id, wh.id, wh.id, wh.id);
          wh.pending_operations = pendingOps ? pendingOps.pending_count : 0;
        });

        // Stock movement overview: Receipts (incoming) vs Deliveries (outgoing)
        const incomingMoves = db.prepare(`
          SELECT strftime('%Y-%m-%d', created_at) as day, SUM(quantity_change) as total
          FROM stock_ledger
          WHERE transaction_type = 'RECEIPT'
          GROUP BY day
          ORDER BY day DESC
          LIMIT 7
        `).all();

        const outgoingMoves = db.prepare(`
          SELECT strftime('%Y-%m-%d', created_at) as day, ABS(SUM(quantity_change)) as total
          FROM stock_ledger
          WHERE transaction_type = 'DELIVERY'
          GROUP BY day
          ORDER BY day DESC
          LIMIT 7
        `).all();

        // Recent transactions (latest 8)
        const recentLedger = db.prepare(`
          SELECT sl.*, p.name as product_name, p.sku as product_sku, p.uom,
                 u.name as user_name, u.role as user_role,
                 sw.name as source_warehouse_name, sloc.name as source_location_name,
                 dw.name as dest_warehouse_name, dloc.name as dest_location_name
          FROM stock_ledger sl
          JOIN products p ON sl.product_id = p.id
          LEFT JOIN users u ON sl.user_id = u.id
          LEFT JOIN warehouses sw ON sl.source_warehouse_id = sw.id
          LEFT JOIN locations sloc ON sl.source_location_id = sloc.id
          LEFT JOIN warehouses dw ON sl.dest_warehouse_id = dw.id
          LEFT JOIN locations dloc ON sl.dest_location_id = dloc.id
          ORDER BY sl.id DESC
          LIMIT 8
        `).all();

        // Smart reorder suggestions (products <= reorder_level)
        const smartReorderAlerts = lowStockItems.concat(outOfStockItems).map(item => ({
          productId: item.id,
          name: item.name,
          sku: item.sku,
          categoryName: item.category_name,
          currentStock: item.current_stock,
          reorderLevel: item.reorder_level,
          targetStock: item.target_stock,
          suggestedRestock: Math.max(0, item.target_stock - item.current_stock),
          urgency: item.current_stock === 0 ? 'CRITICAL' : 'WARNING'
        }));

        // Health Score (ratio of healthy products to total products)
        const healthScore = allProducts.length > 0
          ? Math.round((healthyItems.length / allProducts.length) * 100)
          : 100;

        return sendJson(res, 200, {
          kpi: {
            totalProductsInStock: Math.round(totalStock * 100) / 100,
            lowStockCount: lowStockItems.length,
            outOfStockCount: outOfStockItems.length,
            pendingReceipts,
            pendingDeliveries,
            scheduledTransfers,
            totalInventoryValue: Math.round(totalInventoryValue * 100) / 100,
            healthScore
          },
          categoryStats,
          warehouseSummaries,
          movementOverview: {
            incoming: incomingMoves,
            outgoing: outgoingMoves
          },
          recentTransactions: recentLedger,
          smartReorderAlerts
        });
      }

      // 7. DASHBOARD FILTERED OPERATIONS
      if (pathname === '/api/dashboard/filtered' && method === 'GET') {
        const docType = query.type || 'all'; // all, receipts, delivery, transfers, adjustments
        const status = query.status || 'all';
        const warehouseId = query.warehouse_id || 'all';
        const categoryId = query.category_id || 'all';

        let results = [];

        // Receipts
        if (docType === 'all' || docType === 'receipts') {
          let recSql = `
            SELECT 'Receipt' as doc_type, r.id, r.reference, r.status, r.created_at,
                   s.name as party_name, w.name as warehouse_name, loc.name as location_name,
                   (SELECT COUNT(*) FROM receipt_lines WHERE receipt_id = r.id) as line_count,
                   (SELECT COALESCE(SUM(quantity_expected), 0) FROM receipt_lines WHERE receipt_id = r.id) as total_quantity
            FROM receipts r
            LEFT JOIN suppliers s ON r.supplier_id = s.id
            LEFT JOIN warehouses w ON r.warehouse_id = w.id
            LEFT JOIN locations loc ON r.location_id = loc.id
            WHERE 1=1
          `;
          const params = [];
          if (status !== 'all') { recSql += ` AND r.status = ?`; params.push(status); }
          if (warehouseId !== 'all') { recSql += ` AND r.warehouse_id = ?`; params.push(warehouseId); }
          recSql += ` ORDER BY r.id DESC LIMIT 15`;
          results.push(...db.prepare(recSql).all(...params));
        }

        // Deliveries
        if (docType === 'all' || docType === 'delivery') {
          let delSql = `
            SELECT 'Delivery' as doc_type, d.id, d.reference, d.status, d.created_at,
                   c.name as party_name, w.name as warehouse_name, loc.name as location_name,
                   (SELECT COUNT(*) FROM delivery_lines WHERE delivery_id = d.id) as line_count,
                   (SELECT COALESCE(SUM(quantity_demanded), 0) FROM delivery_lines WHERE delivery_id = d.id) as total_quantity
            FROM delivery_orders d
            LEFT JOIN customers c ON d.customer_id = c.id
            LEFT JOIN warehouses w ON d.warehouse_id = w.id
            LEFT JOIN locations loc ON d.location_id = loc.id
            WHERE 1=1
          `;
          const params = [];
          if (status !== 'all') { delSql += ` AND d.status = ?`; params.push(status); }
          if (warehouseId !== 'all') { delSql += ` AND d.warehouse_id = ?`; params.push(warehouseId); }
          delSql += ` ORDER BY d.id DESC LIMIT 15`;
          results.push(...db.prepare(delSql).all(...params));
        }

        // Internal Transfers
        if (docType === 'all' || docType === 'transfers') {
          let trfSql = `
            SELECT 'Transfer' as doc_type, t.id, t.reference, t.status, t.created_at,
                   (sw.name || ' -> ' || dw.name) as party_name,
                   sw.name as warehouse_name,
                   (sloc.name || ' -> ' || dloc.name) as location_name,
                   (SELECT COUNT(*) FROM transfer_lines WHERE transfer_id = t.id) as line_count,
                   (SELECT COALESCE(SUM(quantity), 0) FROM transfer_lines WHERE transfer_id = t.id) as total_quantity
            FROM internal_transfers t
            LEFT JOIN warehouses sw ON t.source_warehouse_id = sw.id
            LEFT JOIN locations sloc ON t.source_location_id = sloc.id
            LEFT JOIN warehouses dw ON t.dest_warehouse_id = dw.id
            LEFT JOIN locations dloc ON t.dest_location_id = dloc.id
            WHERE 1=1
          `;
          const params = [];
          if (status !== 'all') { trfSql += ` AND t.status = ?`; params.push(status); }
          if (warehouseId !== 'all') { trfSql += ` AND (t.source_warehouse_id = ? OR t.dest_warehouse_id = ?)`; params.push(warehouseId, warehouseId); }
          trfSql += ` ORDER BY t.id DESC LIMIT 15`;
          results.push(...db.prepare(trfSql).all(...params));
        }

        // Adjustments
        if (docType === 'all' || docType === 'adjustments') {
          let adjSql = `
            SELECT 'Adjustment' as doc_type, a.id, a.reference, a.status, a.created_at,
                   p.name as party_name, w.name as warehouse_name, loc.name as location_name,
                   1 as line_count, a.difference as total_quantity
            FROM inventory_adjustments a
            LEFT JOIN products p ON a.product_id = p.id
            LEFT JOIN warehouses w ON a.warehouse_id = w.id
            LEFT JOIN locations loc ON a.location_id = loc.id
            WHERE 1=1
          `;
          const params = [];
          if (warehouseId !== 'all') { adjSql += ` AND a.warehouse_id = ?`; params.push(warehouseId); }
          adjSql += ` ORDER BY a.id DESC LIMIT 15`;
          results.push(...db.prepare(adjSql).all(...params));
        }

        // Sort by created_at desc
        results.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        return sendJson(res, 200, { documents: results.slice(0, 20) });
      }

      // 8. PRODUCTS: LIST
      if (pathname === '/api/products' && method === 'GET') {
        const { search, category_id, status, warehouse_id } = query;
        let sql = `
          SELECT p.*, c.name as category_name, c.color as category_color,
                 COALESCE(SUM(ps.quantity), 0) as current_stock
          FROM products p
          LEFT JOIN categories c ON p.category_id = c.id
          LEFT JOIN product_stocks ps ON p.id = ps.product_id
          WHERE 1=1
        `;
        const params = [];

        if (search) {
          sql += ` AND (p.name LIKE ? OR p.sku LIKE ? OR p.barcode LIKE ?)`;
          const term = `%${search}%`;
          params.push(term, term, term);
        }

        if (category_id && category_id !== 'all') {
          sql += ` AND p.category_id = ?`;
          params.push(category_id);
        }

        if (warehouse_id && warehouse_id !== 'all') {
          sql += ` AND ps.warehouse_id = ?`;
          params.push(warehouse_id);
        }

        sql += ` GROUP BY p.id ORDER BY p.name ASC`;
        let products = db.prepare(sql).all(...params);

        // Filter by stock status if requested
        if (status === 'low') {
          products = products.filter(p => p.current_stock > 0 && p.current_stock <= p.reorder_level);
        } else if (status === 'out') {
          products = products.filter(p => p.current_stock === 0);
        } else if (status === 'in') {
          products = products.filter(p => p.current_stock > p.reorder_level);
        }

        // Enrich with warehouse breakdowns
        const stockStmt = db.prepare(`
          SELECT ps.warehouse_id, w.name as warehouse_name, w.code as warehouse_code,
                 ps.location_id, loc.name as location_name, loc.code as location_code,
                 ps.quantity
          FROM product_stocks ps
          JOIN warehouses w ON ps.warehouse_id = w.id
          JOIN locations loc ON ps.location_id = loc.id
          WHERE ps.product_id = ? AND ps.quantity > 0
        `);

        products.forEach(p => {
          p.warehouses = stockStmt.all(p.id);
          p.status_badge = p.current_stock === 0
            ? 'out_of_stock'
            : (p.current_stock <= p.reorder_level ? 'low_stock' : 'in_stock');
        });

        return sendJson(res, 200, { products });
      }

      // 9. PRODUCTS: CREATE
      if (pathname === '/api/products' && method === 'POST') {
        const body = await parseBody(req);
        const { name, sku, barcode, category_id, uom, description, unit_cost, reorder_level, target_stock, initial_stock, initial_warehouse_id, initial_location_id } = body;

        if (!name || !sku) {
          return sendJson(res, 400, { error: 'Product name and SKU are required' });
        }

        // Check duplicate SKU
        const existing = db.prepare(`SELECT id FROM products WHERE sku = ?`).get(sku.trim().toUpperCase());
        if (existing) {
          return sendJson(res, 400, { error: `SKU "${sku}" already exists. SKUs must be unique.` });
        }

        let newProdId;
        withTransaction(() => {
          const insert = db.prepare(`
            INSERT INTO products (name, sku, barcode, category_id, uom, description, unit_cost, reorder_level, target_stock)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          const result = insert.run(
            name.trim(),
            sku.trim().toUpperCase(),
            barcode ? barcode.trim() : null,
            category_id ? Number(category_id) : null,
            uom || 'Units',
            description || '',
            parseFloat(unit_cost) || 0.0,
            parseFloat(reorder_level) || 10.0,
            parseFloat(target_stock) || 50.0
          );
          newProdId = Number(result.lastInsertRowid);

          // If initial stock provided
          const initQty = parseFloat(initial_stock);
          if (initQty > 0 && initial_warehouse_id && initial_location_id) {
            setOrUpdateLocationStock(newProdId, Number(initial_warehouse_id), Number(initial_location_id), initQty);
            logLedger({
              reference: `INIT-${sku.trim().toUpperCase()}`,
              transactionType: 'INITIAL_STOCK',
              productId: newProdId,
              destWarehouseId: Number(initial_warehouse_id),
              destLocationId: Number(initial_location_id),
              quantityChange: initQty,
              previousBalance: 0,
              newBalance: initQty,
              userId: 1,
              notes: 'Initial stock intake on product creation'
            });
          }
        });

        const created = db.prepare(`SELECT * FROM products WHERE id = ?`).get(newProdId);
        return sendJson(res, 201, { success: true, product: created });
      }

      // 10. PRODUCTS: UPDATE
      if (pathname.match(/^\/api\/products\/(\d+)$/) && method === 'PUT') {
        const id = Number(pathname.match(/^\/api\/products\/(\d+)$/)[1]);
        const body = await parseBody(req);
        const { name, category_id, uom, description, unit_cost, reorder_level, target_stock, barcode } = body;

        if (!name) return sendJson(res, 400, { error: 'Product name cannot be empty' });

        db.prepare(`
          UPDATE products
          SET name = ?, category_id = ?, uom = ?, description = ?, unit_cost = ?, reorder_level = ?, target_stock = ?, barcode = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(
          name.trim(),
          category_id ? Number(category_id) : null,
          uom || 'Units',
          description || '',
          parseFloat(unit_cost) || 0.0,
          parseFloat(reorder_level) || 10.0,
          parseFloat(target_stock) || 50.0,
          barcode ? barcode.trim() : null,
          id
        );

        const updated = db.prepare(`SELECT * FROM products WHERE id = ?`).get(id);
        return sendJson(res, 200, { success: true, product: updated });
      }

      // 11. PRODUCTS: DELETE
      if (pathname.match(/^\/api\/products\/(\d+)$/) && method === 'DELETE') {
        const id = Number(pathname.match(/^\/api\/products\/(\d+)$/)[1]);
        const ledgerCount = db.prepare(`SELECT COUNT(*) as count FROM stock_ledger WHERE product_id = ?`).get(id).count;
        if (ledgerCount > 0) {
          return sendJson(res, 400, { error: 'Cannot delete product with existing stock movements in the audit ledger.' });
        }
        db.prepare(`DELETE FROM products WHERE id = ?`).run(id);
        return sendJson(res, 200, { success: true, message: 'Product deleted' });
      }

      // 12. CATEGORIES: LIST & CREATE
      if (pathname === '/api/categories') {
        if (method === 'GET') {
          const categories = db.prepare(`
            SELECT c.*, COUNT(p.id) as product_count
            FROM categories c
            LEFT JOIN products p ON c.id = p.category_id
            GROUP BY c.id
            ORDER BY c.name ASC
          `).all();
          return sendJson(res, 200, { categories });
        }
        if (method === 'POST') {
          const { name, description, color, icon } = await parseBody(req);
          if (!name) return sendJson(res, 400, { error: 'Category name is required' });
          const result = db.prepare(`
            INSERT INTO categories (name, description, color, icon) VALUES (?, ?, ?, ?)
          `).run(name.trim(), description || '', color || '#10B981', icon || 'layers');
          return sendJson(res, 201, { success: true, id: result.lastInsertRowid });
        }
      }

      // 13. REORDERING RULES
      if (pathname === '/api/reordering-rules' && method === 'GET') {
        const rules = db.prepare(`
          SELECT p.id, p.name, p.sku, p.uom, p.unit_cost, p.reorder_level, p.target_stock,
                 c.name as category_name, c.color as category_color,
                 COALESCE(SUM(ps.quantity), 0) as current_stock
          FROM products p
          LEFT JOIN categories c ON p.category_id = c.id
          LEFT JOIN product_stocks ps ON p.id = ps.product_id
          GROUP BY p.id
          ORDER BY (p.reorder_level - COALESCE(SUM(ps.quantity), 0)) DESC
        `).all();

        rules.forEach(r => {
          r.deficit = Math.max(0, r.target_stock - r.current_stock);
          r.status = r.current_stock === 0 ? 'CRITICAL_OUT' : (r.current_stock <= r.reorder_level ? 'LOW_STOCK' : 'HEALTHY');
          r.restock_cost = Math.round(r.deficit * r.unit_cost * 100) / 100;
        });

        return sendJson(res, 200, { rules });
      }

      // 14. 1-CLICK DRAFT RECEIPT FROM REORDER ALERT
      if (pathname === '/api/reordering-rules/create-draft-receipt' && method === 'POST') {
        const { product_id } = await parseBody(req);
        const prod = db.prepare(`SELECT * FROM products WHERE id = ?`).get(Number(product_id));
        if (!prod) return sendJson(res, 404, { error: 'Product not found' });

        const currentStock = getProductCompanyStock(prod.id);
        const neededQty = Math.max(10, prod.target_stock - currentStock);

        const defaultWh = db.prepare(`SELECT id FROM warehouses LIMIT 1`).get();
        const defaultLoc = db.prepare(`SELECT id FROM locations WHERE warehouse_id = ? LIMIT 1`).get(defaultWh.id);
        const defaultSup = db.prepare(`SELECT id FROM suppliers LIMIT 1`).get();

        const ref = generateReference('REC-AUTO');

        let receiptId;
        withTransaction(() => {
          const rec = db.prepare(`
            INSERT INTO receipts (reference, supplier_id, warehouse_id, location_id, status, notes, created_by)
            VALUES (?, ?, ?, ?, 'draft', ?, 1)
          `).run(ref, defaultSup.id, defaultWh.id, defaultLoc.id, `Auto-generated restock draft for SKU: ${prod.sku}. Target: ${prod.target_stock} ${prod.uom}`);

          receiptId = Number(rec.lastInsertRowid);

          db.prepare(`
            INSERT INTO receipt_lines (receipt_id, product_id, quantity_expected, quantity_received, unit_cost)
            VALUES (?, ?, ?, ?, ?)
          `).run(receiptId, prod.id, neededQty, 0, prod.unit_cost);
        });

        return sendJson(res, 201, {
          success: true,
          message: `Created draft receipt ${ref} for ${neededQty} ${prod.uom} of ${prod.name}`,
          receiptId,
          reference: ref
        });
      }

      // 15. RECEIPTS: LIST
      if (pathname === '/api/receipts' && method === 'GET') {
        const { status, warehouse_id, search } = query;
        let sql = `
          SELECT r.*, s.name as supplier_name, s.contact_email as supplier_email,
                 w.name as warehouse_name, w.code as warehouse_code,
                 loc.name as location_name, loc.code as location_code,
                 u.name as creator_name,
                 (SELECT COUNT(*) FROM receipt_lines WHERE receipt_id = r.id) as line_count,
                 (SELECT COALESCE(SUM(quantity_expected), 0) FROM receipt_lines WHERE receipt_id = r.id) as total_quantity
          FROM receipts r
          LEFT JOIN suppliers s ON r.supplier_id = s.id
          LEFT JOIN warehouses w ON r.warehouse_id = w.id
          LEFT JOIN locations loc ON r.location_id = loc.id
          LEFT JOIN users u ON r.created_by = u.id
          WHERE 1=1
        `;
        const params = [];

        if (status && status !== 'all') {
          sql += ` AND r.status = ?`;
          params.push(status);
        }

        if (warehouse_id && warehouse_id !== 'all') {
          sql += ` AND r.warehouse_id = ?`;
          params.push(warehouse_id);
        }

        if (search) {
          sql += ` AND (r.reference LIKE ? OR s.name LIKE ?)`;
          const term = `%${search}%`;
          params.push(term, term);
        }

        sql += ` ORDER BY r.id DESC`;
        const receipts = db.prepare(sql).all(...params);

        // Fetch lines for each receipt
        const lineStmt = db.prepare(`
          SELECT rl.*, p.name as product_name, p.sku, p.uom
          FROM receipt_lines rl
          JOIN products p ON rl.product_id = p.id
          WHERE rl.receipt_id = ?
        `);

        receipts.forEach(r => {
          r.lines = lineStmt.all(r.id);
        });

        return sendJson(res, 200, { receipts });
      }

      // 16. RECEIPTS: CREATE
      if (pathname === '/api/receipts' && method === 'POST') {
        const { supplier_id, warehouse_id, location_id, notes, lines, status } = await parseBody(req);
        if (!warehouse_id || !location_id) {
          return sendJson(res, 400, { error: 'Destination warehouse and location are required' });
        }
        if (!lines || !Array.isArray(lines) || lines.length === 0) {
          return sendJson(res, 400, { error: 'At least one product line is required' });
        }

        const reference = generateReference('REC');
        const initialStatus = status === 'ready' ? 'ready' : 'draft';

        let receiptId;
        withTransaction(() => {
          const rec = db.prepare(`
            INSERT INTO receipts (reference, supplier_id, warehouse_id, location_id, status, notes, created_by)
            VALUES (?, ?, ?, ?, ?, ?, 1)
          `).run(reference, supplier_id ? Number(supplier_id) : null, Number(warehouse_id), Number(location_id), initialStatus, notes || '');

          receiptId = Number(rec.lastInsertRowid);

          const insertLine = db.prepare(`
            INSERT INTO receipt_lines (receipt_id, product_id, quantity_expected, quantity_received, unit_cost)
            VALUES (?, ?, ?, ?, ?)
          `);

          for (const line of lines) {
            const qty = parseFloat(line.quantity);
            if (qty <= 0) throw new Error('Quantity must be greater than 0');
            insertLine.run(receiptId, Number(line.product_id), qty, qty, parseFloat(line.unit_cost) || 0);
          }
        });

        return sendJson(res, 201, { success: true, receiptId, reference });
      }

      // 17. RECEIPTS: VALIDATE (INCREASE STOCK & LOG LEDGER)
      if (pathname.match(/^\/api\/receipts\/(\d+)\/validate$/) && method === 'POST') {
        const id = Number(pathname.match(/^\/api\/receipts\/(\d+)\/validate$/)[1]);
        const receipt = db.prepare(`SELECT * FROM receipts WHERE id = ?`).get(id);

        if (!receipt) return sendJson(res, 404, { error: 'Receipt not found' });
        if (receipt.status === 'done') {
          return sendJson(res, 400, { error: 'Receipt is already validated! Duplicate validation prevented.' });
        }
        if (receipt.status === 'canceled') {
          return sendJson(res, 400, { error: 'Cannot validate a canceled receipt.' });
        }

        const lines = db.prepare(`
          SELECT rl.*, p.name as product_name, p.sku, p.uom
          FROM receipt_lines rl
          JOIN products p ON rl.product_id = p.id
          WHERE rl.receipt_id = ?
        `).all(id);

        if (lines.length === 0) {
          return sendJson(res, 400, { error: 'Cannot validate receipt with no product lines.' });
        }

        withTransaction(() => {
          for (const line of lines) {
            const qty = line.quantity_expected;
            if (qty <= 0) throw new Error(`Invalid quantity ${qty} for product ${line.product_name}`);

            const prevCompanyBalance = getProductCompanyStock(line.product_id);
            const newLocStock = setOrUpdateLocationStock(line.product_id, receipt.warehouse_id, receipt.location_id, qty);
            const newCompanyBalance = getProductCompanyStock(line.product_id);

            // Update line received qty
            db.prepare(`UPDATE receipt_lines SET quantity_received = ? WHERE id = ?`).run(qty, line.id);

            // Audit in Ledger
            logLedger({
              reference: receipt.reference,
              transactionType: 'RECEIPT',
              productId: line.product_id,
              destWarehouseId: receipt.warehouse_id,
              destLocationId: receipt.location_id,
              quantityChange: qty,
              previousBalance: prevCompanyBalance,
              newBalance: newCompanyBalance,
              userId: 1,
              notes: `Vendor Receipt Validated (${line.sku}: +${qty} ${line.uom})`
            });
          }

          db.prepare(`UPDATE receipts SET status = 'done', validated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(id);
        });

        return sendJson(res, 200, { success: true, message: `Receipt ${receipt.reference} successfully validated. Stock updated.` });
      }

      // 18. RECEIPTS: CANCEL / STATUS UPDATE
      if (pathname.match(/^\/api\/receipts\/(\d+)\/status$/) && method === 'PUT') {
        const id = Number(pathname.match(/^\/api\/receipts\/(\d+)\/status$/)[1]);
        const { status } = await parseBody(req);
        const receipt = db.prepare(`SELECT status FROM receipts WHERE id = ?`).get(id);
        if (!receipt) return sendJson(res, 404, { error: 'Receipt not found' });
        if (receipt.status === 'done') return sendJson(res, 400, { error: 'Validated receipts cannot be modified' });

        db.prepare(`UPDATE receipts SET status = ? WHERE id = ?`).run(status, id);
        return sendJson(res, 200, { success: true });
      }

      // 19. DELIVERIES: LIST
      if (pathname === '/api/deliveries' && method === 'GET') {
        const { status, warehouse_id, search } = query;
        let sql = `
          SELECT d.*, c.name as customer_name, c.contact_email as customer_email,
                 w.name as warehouse_name, w.code as warehouse_code,
                 loc.name as location_name, loc.code as location_code,
                 u.name as creator_name,
                 (SELECT COUNT(*) FROM delivery_lines WHERE delivery_id = d.id) as line_count,
                 (SELECT COALESCE(SUM(quantity_demanded), 0) FROM delivery_lines WHERE delivery_id = d.id) as total_quantity
          FROM delivery_orders d
          LEFT JOIN customers c ON d.customer_id = c.id
          LEFT JOIN warehouses w ON d.warehouse_id = w.id
          LEFT JOIN locations loc ON d.location_id = loc.id
          LEFT JOIN users u ON d.created_by = u.id
          WHERE 1=1
        `;
        const params = [];

        if (status && status !== 'all') {
          sql += ` AND d.status = ?`;
          params.push(status);
        }

        if (warehouse_id && warehouse_id !== 'all') {
          sql += ` AND d.warehouse_id = ?`;
          params.push(warehouse_id);
        }

        if (search) {
          sql += ` AND (d.reference LIKE ? OR c.name LIKE ?)`;
          const term = `%${search}%`;
          params.push(term, term);
        }

        sql += ` ORDER BY d.id DESC`;
        const deliveries = db.prepare(sql).all(...params);

        const lineStmt = db.prepare(`
          SELECT dl.*, p.name as product_name, p.sku, p.uom,
                 COALESCE(ps.quantity, 0) as available_stock
          FROM delivery_lines dl
          JOIN products p ON dl.product_id = p.id
          LEFT JOIN product_stocks ps ON p.id = ps.product_id AND ps.location_id = ?
          WHERE dl.delivery_id = ?
        `);

        deliveries.forEach(d => {
          d.lines = lineStmt.all(d.location_id, d.id);
        });

        return sendJson(res, 200, { deliveries });
      }

      // 20. DELIVERIES: CREATE
      if (pathname === '/api/deliveries' && method === 'POST') {
        const { customer_id, warehouse_id, location_id, notes, lines, status } = await parseBody(req);
        if (!warehouse_id || !location_id) {
          return sendJson(res, 400, { error: 'Source warehouse and location are required' });
        }
        if (!lines || !Array.isArray(lines) || lines.length === 0) {
          return sendJson(res, 400, { error: 'At least one delivery line is required' });
        }

        // Validate stock availability up front
        for (const line of lines) {
          const qty = parseFloat(line.quantity);
          if (qty <= 0) return sendJson(res, 400, { error: 'Quantity must be greater than 0' });
          const available = getLocationStock(Number(line.product_id), Number(location_id));
          if (available < qty) {
            const prod = db.prepare(`SELECT name, sku, uom FROM products WHERE id = ?`).get(Number(line.product_id));
            return sendJson(res, 400, {
              error: `Insufficient stock for ${prod.name} (${prod.sku}). Requested: ${qty} ${prod.uom}, Available at location: ${available} ${prod.uom}. Delivery cannot exceed available stock.`
            });
          }
        }

        const reference = generateReference('DEL');
        const initialStatus = status === 'ready' ? 'ready' : (status === 'waiting' ? 'waiting' : 'draft');

        let deliveryId;
        withTransaction(() => {
          const del = db.prepare(`
            INSERT INTO delivery_orders (reference, customer_id, warehouse_id, location_id, status, notes, created_by)
            VALUES (?, ?, ?, ?, ?, ?, 1)
          `).run(reference, customer_id ? Number(customer_id) : null, Number(warehouse_id), Number(location_id), initialStatus, notes || '');

          deliveryId = Number(del.lastInsertRowid);

          const insertLine = db.prepare(`
            INSERT INTO delivery_lines (delivery_id, product_id, quantity_demanded, quantity_done, unit_price)
            VALUES (?, ?, ?, ?, ?)
          `);

          for (const line of lines) {
            insertLine.run(deliveryId, Number(line.product_id), parseFloat(line.quantity), 0, parseFloat(line.unit_price) || 0);
          }
        });

        return sendJson(res, 201, { success: true, deliveryId, reference });
      }

      // 21. DELIVERIES: VALIDATE (DECREASE STOCK & LOG LEDGER)
      if (pathname.match(/^\/api\/deliveries\/(\d+)\/validate$/) && method === 'POST') {
        const id = Number(pathname.match(/^\/api\/deliveries\/(\d+)\/validate$/)[1]);
        const delivery = db.prepare(`SELECT * FROM delivery_orders WHERE id = ?`).get(id);

        if (!delivery) return sendJson(res, 404, { error: 'Delivery order not found' });
        if (delivery.status === 'done') {
          return sendJson(res, 400, { error: 'Delivery order is already validated! Duplicate validation prevented.' });
        }
        if (delivery.status === 'canceled') {
          return sendJson(res, 400, { error: 'Cannot validate a canceled delivery order.' });
        }

        const lines = db.prepare(`
          SELECT dl.*, p.name as product_name, p.sku, p.uom
          FROM delivery_lines dl
          JOIN products p ON dl.product_id = p.id
          WHERE dl.delivery_id = ?
        `).all(id);

        if (lines.length === 0) {
          return sendJson(res, 400, { error: 'Cannot validate delivery order with no items.' });
        }

        withTransaction(() => {
          // Check stock again in transaction
          for (const line of lines) {
            const avail = getLocationStock(line.product_id, delivery.location_id);
            if (avail < line.quantity_demanded) {
              throw new Error(`Insufficient stock for ${line.product_name} (${line.sku}). Required: ${line.quantity_demanded} ${line.uom}, Available: ${avail} ${line.uom}`);
            }
          }

          // Deduct stock and log ledger
          for (const line of lines) {
            const qty = line.quantity_demanded;
            const prevCompanyBalance = getProductCompanyStock(line.product_id);
            setOrUpdateLocationStock(line.product_id, delivery.warehouse_id, delivery.location_id, -qty);
            const newCompanyBalance = getProductCompanyStock(line.product_id);

            db.prepare(`UPDATE delivery_lines SET quantity_done = ? WHERE id = ?`).run(qty, line.id);

            logLedger({
              reference: delivery.reference,
              transactionType: 'DELIVERY',
              productId: line.product_id,
              sourceWarehouseId: delivery.warehouse_id,
              sourceLocationId: delivery.location_id,
              quantityChange: -qty,
              previousBalance: prevCompanyBalance,
              newBalance: newCompanyBalance,
              userId: 1,
              notes: `Customer Shipment Dispatched (${line.sku}: -${qty} ${line.uom})`
            });
          }

          db.prepare(`UPDATE delivery_orders SET status = 'done', validated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(id);
        });

        return sendJson(res, 200, { success: true, message: `Delivery order ${delivery.reference} validated. Stock updated.` });
      }

      // 22. DELIVERIES: STATUS UPDATE (e.g. mark Ready / Pick & Pack)
      if (pathname.match(/^\/api\/deliveries\/(\d+)\/status$/) && method === 'PUT') {
        const id = Number(pathname.match(/^\/api\/deliveries\/(\d+)\/status$/)[1]);
        const { status } = await parseBody(req);
        const del = db.prepare(`SELECT status FROM delivery_orders WHERE id = ?`).get(id);
        if (!del) return sendJson(res, 404, { error: 'Delivery order not found' });
        if (del.status === 'done') return sendJson(res, 400, { error: 'Validated delivery orders cannot be modified' });

        db.prepare(`UPDATE delivery_orders SET status = ? WHERE id = ?`).run(status, id);
        return sendJson(res, 200, { success: true });
      }

      // 23. TRANSFERS: LIST
      if (pathname === '/api/transfers' && method === 'GET') {
        const { status, search } = query;
        let sql = `
          SELECT t.*,
                 sw.name as source_warehouse_name, sw.code as source_warehouse_code,
                 sloc.name as source_location_name, sloc.code as source_location_code,
                 dw.name as dest_warehouse_name, dw.code as dest_warehouse_code,
                 dloc.name as dest_location_name, dloc.code as dest_location_code,
                 u.name as creator_name,
                 (SELECT COUNT(*) FROM transfer_lines WHERE transfer_id = t.id) as line_count,
                 (SELECT COALESCE(SUM(quantity), 0) FROM transfer_lines WHERE transfer_id = t.id) as total_quantity
          FROM internal_transfers t
          LEFT JOIN warehouses sw ON t.source_warehouse_id = sw.id
          LEFT JOIN locations sloc ON t.source_location_id = sloc.id
          LEFT JOIN warehouses dw ON t.dest_warehouse_id = dw.id
          LEFT JOIN locations dloc ON t.dest_location_id = dloc.id
          LEFT JOIN users u ON t.created_by = u.id
          WHERE 1=1
        `;
        const params = [];

        if (status && status !== 'all') {
          sql += ` AND t.status = ?`;
          params.push(status);
        }

        if (search) {
          sql += ` AND (t.reference LIKE ? OR sw.name LIKE ? OR dw.name LIKE ?)`;
          const term = `%${search}%`;
          params.push(term, term, term);
        }

        sql += ` ORDER BY t.id DESC`;
        const transfers = db.prepare(sql).all(...params);

        const lineStmt = db.prepare(`
          SELECT tl.*, p.name as product_name, p.sku, p.uom,
                 COALESCE(ps.quantity, 0) as available_stock
          FROM transfer_lines tl
          JOIN products p ON tl.product_id = p.id
          LEFT JOIN product_stocks ps ON p.id = ps.product_id AND ps.location_id = ?
          WHERE tl.transfer_id = ?
        `);

        transfers.forEach(t => {
          t.lines = lineStmt.all(t.source_location_id, t.id);
        });

        return sendJson(res, 200, { transfers });
      }

      // 24. TRANSFERS: CREATE
      if (pathname === '/api/transfers' && method === 'POST') {
        const { source_warehouse_id, source_location_id, dest_warehouse_id, dest_location_id, notes, lines, status } = await parseBody(req);

        if (!source_warehouse_id || !source_location_id || !dest_warehouse_id || !dest_location_id) {
          return sendJson(res, 400, { error: 'Source and destination warehouses and locations are required' });
        }

        if (Number(source_location_id) === Number(dest_location_id)) {
          return sendJson(res, 400, { error: 'Source and destination locations cannot be identical.' });
        }

        if (!lines || !Array.isArray(lines) || lines.length === 0) {
          return sendJson(res, 400, { error: 'At least one product line is required' });
        }

        // Validate source stock
        for (const line of lines) {
          const qty = parseFloat(line.quantity);
          if (qty <= 0) return sendJson(res, 400, { error: 'Quantity must be greater than 0' });
          const avail = getLocationStock(Number(line.product_id), Number(source_location_id));
          if (avail < qty) {
            const prod = db.prepare(`SELECT name, sku, uom FROM products WHERE id = ?`).get(Number(line.product_id));
            return sendJson(res, 400, {
              error: `Insufficient stock for ${prod.name} (${prod.sku}) at source location. Required: ${qty} ${prod.uom}, Available: ${avail} ${prod.uom}`
            });
          }
        }

        const reference = generateReference('TRF');
        const initialStatus = status === 'ready' ? 'ready' : 'draft';

        let transferId;
        withTransaction(() => {
          const trf = db.prepare(`
            INSERT INTO internal_transfers (
              reference, source_warehouse_id, source_location_id,
              dest_warehouse_id, dest_location_id, status, notes, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
          `).run(
            reference,
            Number(source_warehouse_id),
            Number(source_location_id),
            Number(dest_warehouse_id),
            Number(dest_location_id),
            initialStatus,
            notes || ''
          );

          transferId = Number(trf.lastInsertRowid);

          const insertLine = db.prepare(`
            INSERT INTO transfer_lines (transfer_id, product_id, quantity)
            VALUES (?, ?, ?)
          `);

          for (const line of lines) {
            insertLine.run(transferId, Number(line.product_id), parseFloat(line.quantity));
          }
        });

        return sendJson(res, 201, { success: true, transferId, reference });
      }

      // 25. TRANSFERS: VALIDATE (ATOMIC RELOCATION & COMPANY STOCK INVARIANT)
      if (pathname.match(/^\/api\/transfers\/(\d+)\/validate$/) && method === 'POST') {
        const id = Number(pathname.match(/^\/api\/transfers\/(\d+)\/validate$/)[1]);
        const transfer = db.prepare(`SELECT * FROM internal_transfers WHERE id = ?`).get(id);

        if (!transfer) return sendJson(res, 404, { error: 'Transfer not found' });
        if (transfer.status === 'done') {
          return sendJson(res, 400, { error: 'Transfer is already validated! Duplicate validation prevented.' });
        }
        if (transfer.status === 'canceled') {
          return sendJson(res, 400, { error: 'Cannot validate a canceled transfer.' });
        }

        const lines = db.prepare(`
          SELECT tl.*, p.name as product_name, p.sku, p.uom
          FROM transfer_lines tl
          JOIN products p ON tl.product_id = p.id
          WHERE tl.transfer_id = ?
        `).all(id);

        if (lines.length === 0) {
          return sendJson(res, 400, { error: 'Cannot validate transfer with no product lines.' });
        }

        withTransaction(() => {
          for (const line of lines) {
            const avail = getLocationStock(line.product_id, transfer.source_location_id);
            if (avail < line.quantity) {
              throw new Error(`Insufficient stock for ${line.product_name} at source. Available: ${avail}, required: ${line.quantity}`);
            }

            const initialCompanyTotal = getProductCompanyStock(line.product_id);

            // Deduct from source
            setOrUpdateLocationStock(line.product_id, transfer.source_warehouse_id, transfer.source_location_id, -line.quantity);
            // Add to destination
            setOrUpdateLocationStock(line.product_id, transfer.dest_warehouse_id, transfer.dest_location_id, line.quantity);

            const finalCompanyTotal = getProductCompanyStock(line.product_id);

            // Invariant check: Company total stock must remain 100% unchanged!
            if (initialCompanyTotal !== finalCompanyTotal) {
              throw new Error(`Data integrity violation: Company total changed during internal transfer! Aborting.`);
            }

            logLedger({
              reference: transfer.reference,
              transactionType: 'INTERNAL_TRANSFER',
              productId: line.product_id,
              sourceWarehouseId: transfer.source_warehouse_id,
              sourceLocationId: transfer.source_location_id,
              destWarehouseId: transfer.dest_warehouse_id,
              destLocationId: transfer.dest_location_id,
              quantityChange: line.quantity,
              previousBalance: initialCompanyTotal,
              newBalance: finalCompanyTotal,
              userId: 1,
              notes: `Internal relocation: ${line.quantity} ${line.uom} moved between locations. Company total invariant preserved.`
            });
          }

          db.prepare(`UPDATE internal_transfers SET status = 'done', validated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(id);
        });

        return sendJson(res, 200, { success: true, message: `Transfer ${transfer.reference} successfully validated.` });
      }

      // 26. ADJUSTMENTS: LIST
      if (pathname === '/api/adjustments' && method === 'GET') {
        const adjustments = db.prepare(`
          SELECT a.*, p.name as product_name, p.sku, p.uom,
                 w.name as warehouse_name, w.code as warehouse_code,
                 loc.name as location_name, loc.code as location_code,
                 u.name as creator_name
          FROM inventory_adjustments a
          JOIN products p ON a.product_id = p.id
          JOIN warehouses w ON a.warehouse_id = w.id
          JOIN locations loc ON a.location_id = loc.id
          LEFT JOIN users u ON a.created_by = u.id
          ORDER BY a.id DESC
        `).all();

        return sendJson(res, 200, { adjustments });
      }

      // 27. ADJUSTMENTS: CREATE & VALIDATE
      if (pathname === '/api/adjustments' && method === 'POST') {
        const { product_id, warehouse_id, location_id, counted_quantity, reason } = await parseBody(req);

        if (!product_id || !warehouse_id || !location_id) {
          return sendJson(res, 400, { error: 'Product, warehouse, and location are required' });
        }
        if (counted_quantity === undefined || counted_quantity === null || parseFloat(counted_quantity) < 0) {
          return sendJson(res, 400, { error: 'Physically counted quantity must be 0 or greater' });
        }
        if (!reason || reason.trim().length < 3) {
          return sendJson(res, 400, { error: 'A valid reason for the inventory adjustment is required' });
        }

        const prodId = Number(product_id);
        const whId = Number(warehouse_id);
        const locId = Number(location_id);
        const counted = parseFloat(counted_quantity);

        const currentRecorded = getLocationStock(prodId, locId);
        const diff = counted - currentRecorded;

        if (diff === 0) {
          return sendJson(res, 400, { error: 'Counted quantity equals system recorded quantity. No adjustment needed.' });
        }

        const reference = generateReference('ADJ');

        withTransaction(() => {
          const prevCompanyStock = getProductCompanyStock(prodId);

          // Update location stock directly to counted
          setOrUpdateLocationStock(prodId, whId, locId, diff);

          const newCompanyStock = getProductCompanyStock(prodId);

          db.prepare(`
            INSERT INTO inventory_adjustments (
              reference, product_id, warehouse_id, location_id,
              previous_quantity, counted_quantity, difference, reason, status, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'done', 1)
          `).run(
            reference, prodId, whId, locId,
            currentRecorded, counted, diff, reason.trim()
          );

          logLedger({
            reference,
            transactionType: 'ADJUSTMENT',
            productId: prodId,
            sourceWarehouseId: whId,
            sourceLocationId: locId,
            quantityChange: diff,
            previousBalance: prevCompanyStock,
            newBalance: newCompanyStock,
            userId: 1,
            notes: `Physical Audit Adjustment: ${diff > 0 ? '+' : ''}${diff}. Reason: ${reason.trim()}`
          });
        });

        return sendJson(res, 201, {
          success: true,
          reference,
          previousQuantity: currentRecorded,
          countedQuantity: counted,
          difference: diff
        });
      }

      // 28. STOCK LEDGER: LIST, FILTER, SEARCH
      if (pathname === '/api/ledger' && method === 'GET') {
        const { search, transaction_type, product_id, warehouse_id, limit, offset } = query;
        let sql = `
          SELECT sl.*, p.name as product_name, p.sku as product_sku, p.uom,
                 u.name as user_name, u.role as user_role,
                 sw.name as source_warehouse_name, sloc.name as source_location_name,
                 dw.name as dest_warehouse_name, dloc.name as dest_location_name
          FROM stock_ledger sl
          JOIN products p ON sl.product_id = p.id
          LEFT JOIN users u ON sl.user_id = u.id
          LEFT JOIN warehouses sw ON sl.source_warehouse_id = sw.id
          LEFT JOIN locations sloc ON sl.source_location_id = sloc.id
          LEFT JOIN warehouses dw ON sl.dest_warehouse_id = dw.id
          LEFT JOIN locations dloc ON sl.dest_location_id = dloc.id
          WHERE 1=1
        `;
        const params = [];

        if (transaction_type && transaction_type !== 'all') {
          sql += ` AND sl.transaction_type = ?`;
          params.push(transaction_type);
        }

        if (product_id && product_id !== 'all') {
          sql += ` AND sl.product_id = ?`;
          params.push(product_id);
        }

        if (warehouse_id && warehouse_id !== 'all') {
          sql += ` AND (sl.source_warehouse_id = ? OR sl.dest_warehouse_id = ?)`;
          params.push(warehouse_id, warehouse_id);
        }

        if (search) {
          sql += ` AND (sl.reference LIKE ? OR p.name LIKE ? OR p.sku LIKE ? OR sl.notes LIKE ?)`;
          const term = `%${search}%`;
          params.push(term, term, term, term);
        }

        sql += ` ORDER BY sl.id DESC`;

        const maxLimit = parseInt(limit) || 100;
        const startOffset = parseInt(offset) || 0;
        sql += ` LIMIT ? OFFSET ?`;
        params.push(maxLimit, startOffset);

        const records = db.prepare(sql).all(...params);

        const countSql = `SELECT COUNT(*) as count FROM stock_ledger`;
        const totalCount = db.prepare(countSql).get().count;

        return sendJson(res, 200, { records, total: totalCount });
      }

      // 29. STOCK LEDGER: CSV EXPORT
      if (pathname === '/api/ledger/export' && method === 'GET') {
        const records = db.prepare(`
          SELECT sl.reference, sl.created_at, sl.transaction_type,
                 p.name as product_name, p.sku as product_sku, p.uom,
                 COALESCE(sw.name || ' (' || sloc.name || ')', 'EXTERNAL / VENDOR') as source_location,
                 COALESCE(dw.name || ' (' || dloc.name || ')', 'EXTERNAL / CUSTOMER') as destination_location,
                 sl.quantity_change, sl.previous_balance, sl.new_balance,
                 COALESCE(u.name, 'System') as user_name, sl.notes
          FROM stock_ledger sl
          JOIN products p ON sl.product_id = p.id
          LEFT JOIN users u ON sl.user_id = u.id
          LEFT JOIN warehouses sw ON sl.source_warehouse_id = sw.id
          LEFT JOIN locations sloc ON sl.source_location_id = sloc.id
          LEFT JOIN warehouses dw ON sl.dest_warehouse_id = dw.id
          LEFT JOIN locations dloc ON sl.dest_location_id = dloc.id
          ORDER BY sl.id DESC
        `).all();

        // Build CSV string RFC4180
        const headers = [
          'Transaction Reference',
          'Date & Time (UTC)',
          'Movement Type',
          'Product Name',
          'SKU',
          'Unit',
          'Source Location',
          'Destination Location',
          'Quantity Moved',
          'Previous Company Balance',
          'New Company Balance',
          'Responsible User',
          'Audit Notes'
        ];

        function escapeCsv(val) {
          if (val === null || val === undefined) return '""';
          const str = String(val).replace(/"/g, '""');
          return `"${str}"`;
        }

        const lines = [headers.map(escapeCsv).join(',')];
        for (const r of records) {
          lines.push([
            escapeCsv(r.reference),
            escapeCsv(r.created_at),
            escapeCsv(r.transaction_type),
            escapeCsv(r.product_name),
            escapeCsv(r.product_sku),
            escapeCsv(r.uom),
            escapeCsv(r.source_location),
            escapeCsv(r.destination_location),
            escapeCsv(r.quantity_change),
            escapeCsv(r.previous_balance),
            escapeCsv(r.new_balance),
            escapeCsv(r.user_name),
            escapeCsv(r.notes)
          ].join(','));
        }

        const csvContent = lines.join('\r\n');
        const filename = `StockSense_Ledger_Export_${new Date().toISOString().slice(0, 10)}.csv`;

        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Content-Length': Buffer.byteLength(csvContent)
        });
        return res.end(csvContent);
      }

      // 30. WAREHOUSES & LOCATIONS
      if (pathname === '/api/warehouses') {
        if (method === 'GET') {
          const warehouses = db.prepare(`
            SELECT w.*,
                   (SELECT COUNT(*) FROM locations WHERE warehouse_id = w.id) as location_count,
                   (SELECT COALESCE(SUM(quantity), 0) FROM product_stocks WHERE warehouse_id = w.id) as total_stock,
                   (SELECT COUNT(DISTINCT product_id) FROM product_stocks WHERE warehouse_id = w.id AND quantity > 0) as unique_products
            FROM warehouses w
            ORDER BY w.id ASC
          `).all();

          const locStmt = db.prepare(`
            SELECT loc.*,
                   (SELECT COALESCE(SUM(quantity), 0) FROM product_stocks WHERE location_id = loc.id) as location_stock
            FROM locations loc
            WHERE loc.warehouse_id = ?
            ORDER BY loc.code ASC
          `);

          warehouses.forEach(w => {
            w.locations = locStmt.all(w.id);
          });

          return sendJson(res, 200, { warehouses });
        }

        if (method === 'POST') {
          const { code, name, address, manager_name } = await parseBody(req);
          if (!code || !name) return sendJson(res, 400, { error: 'Warehouse code and name are required' });
          const existing = db.prepare(`SELECT id FROM warehouses WHERE code = ?`).get(code.trim().toUpperCase());
          if (existing) return sendJson(res, 400, { error: `Warehouse code ${code} already exists` });

          const result = db.prepare(`
            INSERT INTO warehouses (code, name, address, manager_name) VALUES (?, ?, ?, ?)
          `).run(code.trim().toUpperCase(), name.trim(), address || '', manager_name || '');

          return sendJson(res, 201, { success: true, id: result.lastInsertRowid });
        }
      }

      // 31. LOCATIONS
      if (pathname === '/api/locations') {
        if (method === 'GET') {
          const { warehouse_id } = query;
          let sql = `
            SELECT loc.*, w.name as warehouse_name, w.code as warehouse_code,
                   (SELECT COALESCE(SUM(quantity), 0) FROM product_stocks WHERE location_id = loc.id) as total_stock
            FROM locations loc
            JOIN warehouses w ON loc.warehouse_id = w.id
            WHERE 1=1
          `;
          const params = [];
          if (warehouse_id && warehouse_id !== 'all') {
            sql += ` AND loc.warehouse_id = ?`;
            params.push(warehouse_id);
          }
          sql += ` ORDER BY w.name ASC, loc.code ASC`;
          const locations = db.prepare(sql).all(...params);
          return sendJson(res, 200, { locations });
        }

        if (method === 'POST') {
          const { warehouse_id, code, name, type } = await parseBody(req);
          if (!warehouse_id || !code || !name) {
            return sendJson(res, 400, { error: 'Warehouse, location code, and location name are required' });
          }
          const result = db.prepare(`
            INSERT INTO locations (warehouse_id, code, name, type) VALUES (?, ?, ?, ?)
          `).run(Number(warehouse_id), code.trim().toUpperCase(), name.trim(), type || 'rack');
          return sendJson(res, 201, { success: true, id: result.lastInsertRowid });
        }
      }

      // 32. SUPPLIERS & CUSTOMERS
      if (pathname === '/api/suppliers' && method === 'GET') {
        const suppliers = db.prepare(`SELECT * FROM suppliers ORDER BY name ASC`).all();
        return sendJson(res, 200, { suppliers });
      }

      if (pathname === '/api/customers' && method === 'GET') {
        const customers = db.prepare(`SELECT * FROM customers ORDER BY name ASC`).all();
        return sendJson(res, 200, { customers });
      }

      // 33. GLOBAL SEARCH
      if (pathname === '/api/search' && method === 'GET') {
        const q = (query.q || '').trim();
        if (!q || q.length < 2) {
          return sendJson(res, 200, { products: [], documents: [], warehouses: [] });
        }

        const term = `%${q}%`;

        // Search products
        const products = db.prepare(`
          SELECT p.id, p.name, p.sku, p.uom, c.name as category_name,
                 COALESCE((SELECT SUM(quantity) FROM product_stocks WHERE product_id = p.id), 0) as current_stock
          FROM products p
          LEFT JOIN categories c ON p.category_id = c.id
          WHERE p.name LIKE ? OR p.sku LIKE ? OR p.barcode LIKE ?
          LIMIT 6
        `).all(term, term, term);

        // Search documents across receipts, deliveries, transfers, adjustments
        const receipts = db.prepare(`SELECT 'receipt' as type, id, reference, status, created_at FROM receipts WHERE reference LIKE ? LIMIT 4`).all(term);
        const deliveries = db.prepare(`SELECT 'delivery' as type, id, reference, status, created_at FROM delivery_orders WHERE reference LIKE ? LIMIT 4`).all(term);
        const transfers = db.prepare(`SELECT 'transfer' as type, id, reference, status, created_at FROM internal_transfers WHERE reference LIKE ? LIMIT 4`).all(term);
        const adjustments = db.prepare(`SELECT 'adjustment' as type, id, reference, status, created_at FROM inventory_adjustments WHERE reference LIKE ? LIMIT 4`).all(term);

        const documents = [...receipts, ...deliveries, ...transfers, ...adjustments];

        // Search warehouses
        const warehouses = db.prepare(`SELECT id, code, name, manager_name FROM warehouses WHERE name LIKE ? OR code LIKE ? LIMIT 4`).all(term, term);

        return sendJson(res, 200, { products, documents, warehouses });
      }

      // 34. DEMO: RESET DATABASE
      if (pathname === '/api/demo/reset' && method === 'POST') {
        const result = resetDatabase();
        return sendJson(res, 200, result);
      }

      // 35. DEMO: GUIDED SCENARIO STEP
      if (pathname === '/api/demo/guided-step' && method === 'POST') {
        const { step } = await parseBody(req);
        const stepNum = parseInt(step);
        if (!stepNum || stepNum < 1 || stepNum > 4) {
          return sendJson(res, 400, { error: 'Invalid step number. Step must be 1, 2, 3, or 4.' });
        }
        try {
          const result = executeGuidedDemoStep(stepNum);
          return sendJson(res, 200, { success: true, result });
        } catch (err) {
          return sendJson(res, 400, { error: err.message });
        }
      }

      // If no API matched
      return sendJson(res, 404, { error: `Endpoint ${method} ${pathname} not found` });
    } catch (err) {
      console.error('[API Error]', err);
      return sendJson(res, 500, { error: err.message || 'Internal Server Error' });
    }
  }

  // -------------------------------------------------------------
  // STATIC FILE HANDLER
  // -------------------------------------------------------------
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);

  // If path doesn't have an extension, try index.html (SPA Fallback)
  if (!path.extname(filePath)) {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // SPA Fallback: serve index.html
      const fallback = path.join(PUBLIC_DIR, 'index.html');
      fs.readFile(fallback, (err2, content) => {
        if (err2) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          return res.end('StockSense: File Not Found');
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(content);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err2, content) => {
      if (err2) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end('Internal Server Error');
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    });
  });
});

server.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` StockSense - Smart Inventory Management System`);
  console.log(` Running on: http://localhost:${PORT}`);
  console.log(` "Every Item. Every Movement. In Control."`);
  console.log(`=======================================================`);
});

module.exports = server;
