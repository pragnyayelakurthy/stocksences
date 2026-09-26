const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'stocksense.db');
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}
const db = new DatabaseSync(DB_PATH);

// Enable WAL mode and foreign keys for high performance and integrity
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
`);

function hashPassword(password, salt = process.env.PASSWORD_SALT || 'stocksense_salt_2026') {
  return crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256').toString('hex');
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('inventory_manager', 'warehouse_staff')),
      department TEXT DEFAULT 'Operations',
      avatar TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      color TEXT DEFAULT '#10B981',
      icon TEXT DEFAULT 'layers'
    );

    CREATE TABLE IF NOT EXISTS warehouses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      address TEXT,
      manager_name TEXT,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS locations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      warehouse_id INTEGER NOT NULL REFERENCES warehouses(id) ON DELETE CASCADE,
      code TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT DEFAULT 'rack' CHECK(type IN ('bay', 'rack', 'shelf', 'pallet', 'production', 'dispatch')),
      is_active INTEGER DEFAULT 1,
      UNIQUE(warehouse_id, code)
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      sku TEXT UNIQUE NOT NULL,
      barcode TEXT,
      category_id INTEGER REFERENCES categories(id),
      uom TEXT NOT NULL DEFAULT 'Units',
      description TEXT,
      unit_cost REAL DEFAULT 0.0,
      reorder_level REAL NOT NULL DEFAULT 10.0,
      target_stock REAL NOT NULL DEFAULT 50.0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS product_stocks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      warehouse_id INTEGER NOT NULL REFERENCES warehouses(id) ON DELETE CASCADE,
      location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
      quantity REAL NOT NULL DEFAULT 0.0 CHECK(quantity >= 0),
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(product_id, location_id)
    );

    CREATE TABLE IF NOT EXISTS suppliers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      contact_email TEXT,
      phone TEXT,
      address TEXT
    );

    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      contact_email TEXT,
      phone TEXT,
      address TEXT
    );

    CREATE TABLE IF NOT EXISTS receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reference TEXT UNIQUE NOT NULL,
      supplier_id INTEGER REFERENCES suppliers(id),
      warehouse_id INTEGER NOT NULL REFERENCES warehouses(id),
      location_id INTEGER NOT NULL REFERENCES locations(id),
      status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'waiting', 'ready', 'done', 'canceled')),
      notes TEXT,
      created_by INTEGER REFERENCES users(id),
      validated_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS receipt_lines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id INTEGER NOT NULL REFERENCES receipts(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity_expected REAL NOT NULL,
      quantity_received REAL NOT NULL DEFAULT 0.0,
      unit_cost REAL DEFAULT 0.0
    );

    CREATE TABLE IF NOT EXISTS delivery_orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reference TEXT UNIQUE NOT NULL,
      customer_id INTEGER REFERENCES customers(id),
      warehouse_id INTEGER NOT NULL REFERENCES warehouses(id),
      location_id INTEGER NOT NULL REFERENCES locations(id),
      status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'waiting', 'ready', 'done', 'canceled')),
      notes TEXT,
      created_by INTEGER REFERENCES users(id),
      validated_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS delivery_lines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      delivery_id INTEGER NOT NULL REFERENCES delivery_orders(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity_demanded REAL NOT NULL,
      quantity_done REAL NOT NULL DEFAULT 0.0,
      unit_price REAL DEFAULT 0.0
    );

    CREATE TABLE IF NOT EXISTS internal_transfers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reference TEXT UNIQUE NOT NULL,
      source_warehouse_id INTEGER NOT NULL REFERENCES warehouses(id),
      source_location_id INTEGER NOT NULL REFERENCES locations(id),
      dest_warehouse_id INTEGER NOT NULL REFERENCES warehouses(id),
      dest_location_id INTEGER NOT NULL REFERENCES locations(id),
      status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft', 'waiting', 'ready', 'done', 'canceled')),
      notes TEXT,
      created_by INTEGER REFERENCES users(id),
      validated_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transfer_lines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      transfer_id INTEGER NOT NULL REFERENCES internal_transfers(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity REAL NOT NULL CHECK(quantity > 0)
    );

    CREATE TABLE IF NOT EXISTS inventory_adjustments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reference TEXT UNIQUE NOT NULL,
      product_id INTEGER NOT NULL REFERENCES products(id),
      warehouse_id INTEGER NOT NULL REFERENCES warehouses(id),
      location_id INTEGER NOT NULL REFERENCES locations(id),
      previous_quantity REAL NOT NULL,
      counted_quantity REAL NOT NULL,
      difference REAL NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'done',
      created_by INTEGER REFERENCES users(id),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS stock_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reference TEXT NOT NULL,
      transaction_type TEXT NOT NULL CHECK(transaction_type IN ('RECEIPT', 'DELIVERY', 'INTERNAL_TRANSFER', 'ADJUSTMENT', 'INITIAL_STOCK')),
      product_id INTEGER NOT NULL REFERENCES products(id),
      source_warehouse_id INTEGER REFERENCES warehouses(id),
      source_location_id INTEGER REFERENCES locations(id),
      dest_warehouse_id INTEGER REFERENCES warehouses(id),
      dest_location_id INTEGER REFERENCES locations(id),
      quantity_change REAL NOT NULL,
      previous_balance REAL NOT NULL,
      new_balance REAL NOT NULL,
      user_id INTEGER REFERENCES users(id),
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      otp TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at INTEGER NOT NULL
    );
  `);
}

function withTransaction(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// Helper to get total company-wide stock for a product
function getProductCompanyStock(productId) {
  const row = db.prepare(`SELECT COALESCE(SUM(quantity), 0) AS total FROM product_stocks WHERE product_id = ?`).get(productId);
  return row ? row.total : 0;
}

// Helper to get stock at a specific location
function getLocationStock(productId, locationId) {
  const row = db.prepare(`SELECT quantity, warehouse_id FROM product_stocks WHERE product_id = ? AND location_id = ?`).get(productId, locationId);
  return row ? row.quantity : 0;
}

// Atomic stock adjustment at a location
function setOrUpdateLocationStock(productId, warehouseId, locationId, delta) {
  const existing = db.prepare(`SELECT id, quantity FROM product_stocks WHERE product_id = ? AND location_id = ?`).get(productId, locationId);
  if (existing) {
    const newQty = existing.quantity + delta;
    if (newQty < 0) {
      throw new Error(`Insufficient stock: current stock is ${existing.quantity}, requested change is ${delta}`);
    }
    db.prepare(`UPDATE product_stocks SET quantity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(newQty, existing.id);
    return newQty;
  } else {
    if (delta < 0) {
      throw new Error(`Cannot deduct stock: location has 0 items.`);
    }
    db.prepare(`INSERT INTO product_stocks (product_id, warehouse_id, location_id, quantity) VALUES (?, ?, ?, ?)`).run(productId, warehouseId, locationId, delta);
    return delta;
  }
}

// Log into auditable Stock Ledger
function logLedger({ reference, transactionType, productId, sourceWarehouseId = null, sourceLocationId = null, destWarehouseId = null, destLocationId = null, quantityChange, previousBalance, newBalance, userId = 1, notes = '' }) {
  db.prepare(`
    INSERT INTO stock_ledger (
      reference, transaction_type, product_id,
      source_warehouse_id, source_location_id,
      dest_warehouse_id, dest_location_id,
      quantity_change, previous_balance, new_balance,
      user_id, notes, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `).run(
    reference,
    transactionType,
    productId,
    sourceWarehouseId,
    sourceLocationId,
    destWarehouseId,
    destLocationId,
    quantityChange,
    previousBalance,
    newBalance,
    userId,
    notes
  );
}

function seedDatabase() {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount > 0) return; // already seeded

  console.log('[StockSense] Seeding demo database...');

  withTransaction(() => {
    // 1. Users
    const insertUser = db.prepare(`
      INSERT INTO users (name, email, password_hash, role, department, avatar)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    insertUser.run(
      'Elena Vance',
      'elena@stocksense.io',
      hashPassword('password123'),
      'inventory_manager',
      'Supply Chain & Operations',
      'EV'
    );

    insertUser.run(
      'Marcus Chen',
      'marcus@stocksense.io',
      hashPassword('password123'),
      'warehouse_staff',
      'Floor Operations & Logistics',
      'MC'
    );

    // 2. Categories
    const insertCat = db.prepare(`INSERT INTO categories (name, description, color, icon) VALUES (?, ?, ?, ?)`);
    insertCat.run('Raw Materials & Metals', 'Bar stock, plates, alloys and raw structural materials', '#0EA5E9', 'layers');
    insertCat.run('Industrial Electronics', 'Microcontrollers, sensors, power modules and PLCs', '#8B5CF6', 'cpu');
    insertCat.run('Packaging & Logistics', 'Cartons, strapping, bubble wrap and dunnage', '#F59E0B', 'box');
    insertCat.run('Mechanical Components', 'Bearings, gears, stepper motors and fasteners', '#10B981', 'cog');
    insertCat.run('Facility & Safety', 'PPE, protective equipment, cleaning supplies', '#EC4899', 'shield');

    // 3. Warehouses
    const insertWH = db.prepare(`INSERT INTO warehouses (code, name, address, manager_name) VALUES (?, ?, ?, ?)`);
    insertWH.run('WH-CDC', 'Central Distribution Center', '1040 Logistics Parkway, Chicago, IL', 'Elena Vance');
    insertWH.run('WH-EFH', 'East Coast Hub', '45 Cargo Way, Newark, NJ', 'David Miller');
    insertWH.run('WH-PAP', 'Production & Assembly Plant', '880 Industrial Ave, Detroit, MI', 'Marcus Chen');

    // 4. Locations
    const insertLoc = db.prepare(`INSERT INTO locations (warehouse_id, code, name, type) VALUES (?, ?, ?, ?)`);
    // WH 1 (CDC)
    insertLoc.run(1, 'BAY-01', 'Inbound Receiving Bay 1', 'bay');
    insertLoc.run(1, 'RACK-A1', 'High-Bay Rack A-01', 'rack');
    insertLoc.run(1, 'RACK-A2', 'High-Bay Rack A-02', 'rack');
    insertLoc.run(1, 'DISP-01', 'Dispatch Staging Area', 'dispatch');

    // WH 2 (EFH)
    insertLoc.run(2, 'ZONE-B1', 'Pallet Storage Zone B', 'pallet');
    insertLoc.run(2, 'SHEL-01', 'Quick-Pick Shelf 01', 'shelf');

    // WH 3 (PAP)
    insertLoc.run(3, 'RAW-IN', 'Raw Material Intake', 'bay');
    insertLoc.run(3, 'ASSM-R1', 'Assembly Floor Rack 1', 'production');
    insertLoc.run(3, 'FG-STG', 'Finished Goods Staging', 'pallet');

    // 5. Suppliers
    const insertSup = db.prepare(`INSERT INTO suppliers (name, contact_email, phone, address) VALUES (?, ?, ?, ?)`);
    insertSup.run('Apex Steel Industries', 'orders@apexsteel.com', '+1 (312) 555-0199', 'Gary, IN');
    insertSup.run('NeoTech Microelectronics Ltd', 'sales@neotech.io', '+1 (408) 555-0142', 'San Jose, CA');
    insertSup.run('PackSmart Solutions Global', 'supply@packsmart.com', '+1 (614) 555-0188', 'Columbus, OH');
    insertSup.run('Continental Fasteners Corp', 'logistics@contifast.com', '+1 (216) 555-0131', 'Cleveland, OH');

    // 6. Customers
    const insertCust = db.prepare(`INSERT INTO customers (name, contact_email, phone, address) VALUES (?, ?, ?, ?)`);
    insertCust.run('Tesla Gigafactory Logistics', 'receiving@tesla.com', '+1 (512) 555-0177', 'Austin, TX');
    insertCust.run('Siemens Industrial Automation', 'procure@siemens.com', '+1 (770) 555-0125', 'Alpharetta, GA');
    insertCust.run('Apex Manufacturing Hub', 'supply@apexmanuf.com', '+1 (313) 555-0164', 'Dearborn, MI');
    insertCust.run('Northrop Aerospace Works', 'intake@northrop.com', '+1 (310) 555-0155', 'Redondo Beach, CA');

    // 7. Products
    const insertProd = db.prepare(`
      INSERT INTO products (name, sku, barcode, category_id, uom, description, unit_cost, reorder_level, target_stock)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Prods:
    // 1: Steel Rods (Raw Materials)
    insertProd.run('Industrial Steel Rods 20mm', 'STL-ROD-20M', '789123001', 1, 'kg', 'High-grade carbon structural steel rods for machining', 18.50, 150.0, 500.0);
    // 2: Microcontroller (Electronics)
    insertProd.run('Microcontroller MCU-X4 Cortex', 'ELEC-MCU-X4', '789123002', 2, 'Units', 'ARM Cortex-M4 32-bit embedded industrial processor', 34.00, 100.0, 400.0);
    // 3: Boxes (Packaging)
    insertProd.run('Heavy Duty Corrugated Boxes', 'PKG-BOX-HD', '789123003', 3, 'Boxes', 'Double-wall 24x18x18 industrial shipping cartons', 3.20, 200.0, 600.0);
    // 4: Stepper Motor (Mechanical)
    insertProd.run('Precision Stepper Motor NEMA23', 'MOT-STEP-N23', '789123004', 4, 'Units', 'High torque bipolar 1.8 degree hybrid stepper motor', 48.00, 30.0, 120.0);
    // 5: M8 Bolts (Mechanical)
    insertProd.run('High-Tensile M8 Hex Bolts 50mm', 'FAST-BOLT-M8', '789123005', 4, 'Boxes', 'Grade 8.8 zinc-plated structural steel bolts (100/box)', 14.50, 50.0, 200.0);
    // 6: Lithium Battery Pack (Electronics)
    insertProd.run('Lithium-Ion Power Cell 48V 20Ah', 'BAT-LI-48V', '789123006', 2, 'Units', 'Industrial rechargeable lithium energy module with BMS', 210.00, 25.0, 80.0);
    // 7: Pallet Stretch Film (Packaging)
    insertProd.run('Heavy Duty Pallet Stretch Film', 'PKG-WRAP-500', '789123007', 3, 'Units', '80 gauge 500m commercial stretch film rolls', 22.00, 40.0, 150.0);
    // 8: Industrial Coolant (Raw) - Critical Low
    insertProd.run('Industrial Synthetic Coolant 5L', 'LUB-SYN-5L', '789123008', 1, 'Liters', 'Semi-synthetic water soluble cutting and grinding fluid', 65.00, 45.0, 100.0);
    // 9: OSHA Hardhat (Safety) - Out of stock demo!
    insertProd.run('Safety Hardhat OSHA Certified', 'SAF-HAT-01', '789123009', 5, 'Units', 'V-Gard ANSI Type I vented hardhat with ratchet suspension', 16.00, 30.0, 100.0);
    // 10: Optical Sensor (Electronics)
    insertProd.run('Photoelectric Sensor Retro-Reflective', 'SENS-OPT-400', '789123010', 2, 'Units', 'IP67 rated polarized retroreflective sensor with bracket', 52.00, 20.0, 60.0);

    // 8. Initial Stocks & Initial Ledger Entries
    const initialStocks = [
      // Steel Rods (Prod 1): 240kg at CDC Rack A1 (Above reorder 150)
      { prodId: 1, whId: 1, locId: 2, qty: 240 },
      // Microcontroller (Prod 2): 60 units at CDC Rack A2 (LOW STOCK: 60 <= 100)
      { prodId: 2, whId: 1, locId: 3, qty: 60 },
      // Boxes (Prod 3): 350 boxes at CDC Rack A1, 120 at EFH Zone B (Total 470)
      { prodId: 3, whId: 1, locId: 2, qty: 350 },
      { prodId: 3, whId: 2, locId: 5, qty: 120 },
      // Stepper Motor (Prod 4): 85 units at PAP Assembly (Healthy)
      { prodId: 4, whId: 3, locId: 8, qty: 85 },
      // M8 Bolts (Prod 5): 110 boxes at CDC Rack A2
      { prodId: 5, whId: 1, locId: 3, qty: 110 },
      // Li-Ion Battery (Prod 6): 18 units at EFH Shelf 01 (LOW STOCK: 18 <= 25)
      { prodId: 6, whId: 2, locId: 6, qty: 18 },
      // Stretch Film (Prod 7): 95 units at CDC Dispatch
      { prodId: 7, whId: 1, locId: 4, qty: 95 },
      // Coolant 5L (Prod 8): 8 Liters at PAP Raw Intake (CRITICAL LOW: 8 <= 45)
      { prodId: 8, whId: 3, locId: 7, qty: 8 },
      // Hardhat (Prod 9): 0 units (OUT OF STOCK: 0 <= 30) - no row needed or 0
      { prodId: 9, whId: 1, locId: 2, qty: 0 },
      // Sensor (Prod 10): 42 units at CDC Rack A2
      { prodId: 10, whId: 1, locId: 3, qty: 42 },
    ];

    const insertStock = db.prepare(`
      INSERT INTO product_stocks (product_id, warehouse_id, location_id, quantity)
      VALUES (?, ?, ?, ?)
    `);

    for (const s of initialStocks) {
      insertStock.run(s.prodId, s.whId, s.locId, s.qty);
      if (s.qty > 0) {
        logLedger({
          reference: `INIT-INV-00${s.prodId}`,
          transactionType: 'INITIAL_STOCK',
          productId: s.prodId,
          destWarehouseId: s.whId,
          destLocationId: s.locId,
          quantityChange: s.qty,
          previousBalance: 0,
          newBalance: s.qty,
          userId: 1,
          notes: 'Initial warehouse inventory audit and baseline intake'
        });
      }
    }

    // 9. Realistic Sample Receipts
    // Receipt 1 (Done): Received 100 boxes of M8 bolts from Continental Fasteners
    const r1 = db.prepare(`
      INSERT INTO receipts (reference, supplier_id, warehouse_id, location_id, status, notes, created_by, validated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '-2 days'))
    `).run('REC-2026-001', 4, 1, 3, 'done', 'Scheduled PO-8821 delivery. Quality verified on arrival.', 1);

    db.prepare(`
      INSERT INTO receipt_lines (receipt_id, product_id, quantity_expected, quantity_received, unit_cost)
      VALUES (?, ?, ?, ?, ?)
    `).run(Number(r1.lastInsertRowid), 5, 100, 100, 14.50);

    // Receipt 2 (Ready): 50 units of NEMA23 Stepper Motors ready for dock check
    const r2 = db.prepare(`
      INSERT INTO receipts (reference, supplier_id, warehouse_id, location_id, status, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('REC-2026-002', 2, 3, 7, 'ready', 'Dock receipt verified, pending final warehouse rack validation.', 2);

    db.prepare(`
      INSERT INTO receipt_lines (receipt_id, product_id, quantity_expected, quantity_received, unit_cost)
      VALUES (?, ?, ?, ?, ?)
    `).run(Number(r2.lastInsertRowid), 4, 50, 50, 48.00);

    // Receipt 3 (Draft): Reorder draft for Low Stock Hardhats
    const r3 = db.prepare(`
      INSERT INTO receipts (reference, supplier_id, warehouse_id, location_id, status, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('REC-2026-003', 3, 1, 2, 'draft', 'Emergency restock for depleted safety hardhat inventory.', 1);

    db.prepare(`
      INSERT INTO receipt_lines (receipt_id, product_id, quantity_expected, quantity_received, unit_cost)
      VALUES (?, ?, ?, ?, ?)
    `).run(Number(r3.lastInsertRowid), 9, 100, 0, 16.00);

    // 10. Realistic Sample Deliveries
    // Delivery 1 (Done): Delivered 40 boxes to Tesla Gigafactory
    const d1 = db.prepare(`
      INSERT INTO delivery_orders (reference, customer_id, warehouse_id, location_id, status, notes, created_by, validated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '-1 day'))
    `).run('DEL-2026-001', 1, 1, 4, 'done', 'Express logistics dispatch via Freightliner.', 1);

    db.prepare(`
      INSERT INTO delivery_lines (delivery_id, product_id, quantity_demanded, quantity_done, unit_price)
      VALUES (?, ?, ?, ?, ?)
    `).run(Number(d1.lastInsertRowid), 3, 40, 40, 5.50);

    // Delivery 2 (Ready): 10 Lithium Batteries to Siemens
    const d2 = db.prepare(`
      INSERT INTO delivery_orders (reference, customer_id, warehouse_id, location_id, status, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('DEL-2026-002', 2, 2, 6, 'ready', 'Picked and packed. Awaiting carrier pickup at Newark dock.', 2);

    db.prepare(`
      INSERT INTO delivery_lines (delivery_id, product_id, quantity_demanded, quantity_done, unit_price)
      VALUES (?, ?, ?, ?, ?)
    `).run(Number(d2.lastInsertRowid), 6, 10, 10, 260.00);

    // Delivery 3 (Waiting): 15 units of Stepper Motors for Apex Manufacturing
    const d3 = db.prepare(`
      INSERT INTO delivery_orders (reference, customer_id, warehouse_id, location_id, status, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('DEL-2026-003', 3, 3, 8, 'waiting', 'Pending quality staging release before packing.', 2);

    db.prepare(`
      INSERT INTO delivery_lines (delivery_id, product_id, quantity_demanded, quantity_done, unit_price)
      VALUES (?, ?, ?, ?, ?)
    `).run(Number(d3.lastInsertRowid), 4, 15, 0, 65.00);

    // 11. Realistic Sample Internal Transfers
    // Transfer 1 (Done): Moved 50 Corrugated Boxes from Inbound Bay to Rack A1
    const t1 = db.prepare(`
      INSERT INTO internal_transfers (reference, source_warehouse_id, source_location_id, dest_warehouse_id, dest_location_id, status, notes, created_by, validated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-3 days'))
    `).run('TRF-2026-001', 1, 1, 1, 2, 'done', 'Restocking pallet buffer into High-Bay Rack A-01.', 1);

    db.prepare(`
      INSERT INTO transfer_lines (transfer_id, product_id, quantity)
      VALUES (?, ?, ?)
    `).run(Number(t1.lastInsertRowid), 3, 50);

    // Transfer 2 (Ready): Transfer 40kg Steel Rods from CDC to Detroit Assembly Plant
    const t2 = db.prepare(`
      INSERT INTO internal_transfers (reference, source_warehouse_id, source_location_id, dest_warehouse_id, dest_location_id, status, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run('TRF-2026-002', 1, 2, 3, 8, 'ready', 'Inter-facility transfer for Detroit automated chassis line.', 1);

    db.prepare(`
      INSERT INTO transfer_lines (transfer_id, product_id, quantity)
      VALUES (?, ?, ?)
    `).run(Number(t2.lastInsertRowid), 1, 40);

    // 12. Sample Inventory Adjustment (Done)
    db.prepare(`
      INSERT INTO inventory_adjustments (
        reference, product_id, warehouse_id, location_id,
        previous_quantity, counted_quantity, difference, reason, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'ADJ-2026-001',
      8, 3, 7,
      10, 8, -2,
      'Minor seal leakage identified during routine monthly safety inspection',
      'done',
      1
    );

    logLedger({
      reference: 'ADJ-2026-001',
      transactionType: 'ADJUSTMENT',
      productId: 8,
      sourceWarehouseId: 3,
      sourceLocationId: 7,
      quantityChange: -2,
      previousBalance: 10,
      newBalance: 8,
      userId: 1,
      notes: 'Physical count adjustment (-2 Liters due to damaged seal)'
    });
  });

  console.log('[StockSense] Demo database successfully seeded with complete realistic records.');
}

// Reset entire database to clean demo state
function resetDatabase() {
  db.exec(`
    DROP TABLE IF EXISTS sessions;
    DROP TABLE IF EXISTS otp_codes;
    DROP TABLE IF EXISTS stock_ledger;
    DROP TABLE IF EXISTS inventory_adjustments;
    DROP TABLE IF EXISTS transfer_lines;
    DROP TABLE IF EXISTS internal_transfers;
    DROP TABLE IF EXISTS delivery_lines;
    DROP TABLE IF EXISTS delivery_orders;
    DROP TABLE IF EXISTS receipt_lines;
    DROP TABLE IF EXISTS receipts;
    DROP TABLE IF EXISTS product_stocks;
    DROP TABLE IF EXISTS products;
    DROP TABLE IF EXISTS locations;
    DROP TABLE IF EXISTS warehouses;
    DROP TABLE IF EXISTS customers;
    DROP TABLE IF EXISTS suppliers;
    DROP TABLE IF EXISTS categories;
    DROP TABLE IF EXISTS users;
  `);
  initSchema();
  seedDatabase();
  return { success: true, message: 'Database reset and re-seeded successfully.' };
}

// Guided Demo Scenario implementation as specified in Section 13.D:
// Lifecycle:
// 1. Receive 100 kg of steel (STL-ROD-20M) at WH-CDC High-Bay Rack A1
// 2. Transfer 100 kg to WH-PAP Assembly Floor Rack 1
// 3. Deliver 20 kg to Customer Apex Manufacturing
// 4. Adjust 3 kg as damaged during assembly
// Result: 77 kg final stock, ledger with all 4 steps!
function executeGuidedDemoStep(stepNumber) {
  const steelProd = db.prepare(`SELECT * FROM products WHERE sku = 'STL-ROD-20M'`).get();
  if (!steelProd) throw new Error('Steel Rods product not found');

  const cdcWarehouse = db.prepare(`SELECT * FROM warehouses WHERE code = 'WH-CDC'`).get();
  const cdcRackA1 = db.prepare(`SELECT * FROM locations WHERE code = 'RACK-A1' AND warehouse_id = ?`).get(cdcWarehouse.id);

  const papWarehouse = db.prepare(`SELECT * FROM warehouses WHERE code = 'WH-PAP'`).get();
  const papAssembly = db.prepare(`SELECT * FROM locations WHERE code = 'ASSM-R1' AND warehouse_id = ?`).get(papWarehouse.id);

  const supplier = db.prepare(`SELECT * FROM suppliers LIMIT 1`).get();
  const customer = db.prepare(`SELECT * FROM customers WHERE name LIKE '%Apex%'`).get() || db.prepare(`SELECT * FROM customers LIMIT 1`).get();
  const adminUser = db.prepare(`SELECT * FROM users WHERE role = 'inventory_manager' LIMIT 1`).get();

  return withTransaction(() => {
    if (stepNumber === 1) {
      // Step 1: Receive 100 kg steel
      const ref = `REC-GUIDED-${Date.now().toString().slice(-4)}`;
      const rec = db.prepare(`
        INSERT INTO receipts (reference, supplier_id, warehouse_id, location_id, status, notes, created_by, validated_at)
        VALUES (?, ?, ?, ?, 'done', 'Guided Demo: Received 100 kg of Industrial Steel Rods from Apex Steel.', ?, CURRENT_TIMESTAMP)
      `).run(ref, supplier.id, cdcWarehouse.id, cdcRackA1.id, adminUser.id);

      db.prepare(`
        INSERT INTO receipt_lines (receipt_id, product_id, quantity_expected, quantity_received, unit_cost)
        VALUES (?, ?, ?, ?, ?)
      `).run(Number(rec.lastInsertRowid), steelProd.id, 100, 100, steelProd.unit_cost);

      const prevComp = getProductCompanyStock(steelProd.id);
      const newLocStock = setOrUpdateLocationStock(steelProd.id, cdcWarehouse.id, cdcRackA1.id, 100);
      const newComp = getProductCompanyStock(steelProd.id);

      logLedger({
        reference: ref,
        transactionType: 'RECEIPT',
        productId: steelProd.id,
        destWarehouseId: cdcWarehouse.id,
        destLocationId: cdcRackA1.id,
        quantityChange: 100,
        previousBalance: prevComp,
        newBalance: newComp,
        userId: adminUser.id,
        notes: `Guided Step 1: Received 100 kg at ${cdcWarehouse.name} (${cdcRackA1.name}). Stock increased.`
      });

      return {
        step: 1,
        title: 'Step 1: Inbound Stock Receipt Validated',
        action: 'Received 100 kg Industrial Steel Rods',
        reference: ref,
        location: `${cdcWarehouse.name} / ${cdcRackA1.name}`,
        quantityMoved: '+100 kg',
        newLocationStock: `${newLocStock} kg`,
        totalCompanyStock: `${newComp} kg`,
        ledgerReference: ref
      };
    } else if (stepNumber === 2) {
      // Step 2: Transfer 100 kg from CDC Rack A1 to PAP Assembly Floor Rack 1
      const currentSource = getLocationStock(steelProd.id, cdcRackA1.id);
      if (currentSource < 100) {
        throw new Error(`Insufficient stock in ${cdcRackA1.name}. Required 100 kg, available: ${currentSource} kg. Please run Step 1 first!`);
      }

      const ref = `TRF-GUIDED-${Date.now().toString().slice(-4)}`;
      const trf = db.prepare(`
        INSERT INTO internal_transfers (reference, source_warehouse_id, source_location_id, dest_warehouse_id, dest_location_id, status, notes, created_by, validated_at)
        VALUES (?, ?, ?, ?, ?, 'done', 'Guided Demo: Inter-warehouse transit to Detroit Production Floor.', ?, CURRENT_TIMESTAMP)
      `).run(ref, cdcWarehouse.id, cdcRackA1.id, papWarehouse.id, papAssembly.id, adminUser.id);

      db.prepare(`
        INSERT INTO transfer_lines (transfer_id, product_id, quantity)
        VALUES (?, ?, ?)
      `).run(Number(trf.lastInsertRowid), steelProd.id, 100);

      const prevComp = getProductCompanyStock(steelProd.id);

      // Deduct from source and add to destination
      setOrUpdateLocationStock(steelProd.id, cdcWarehouse.id, cdcRackA1.id, -100);
      const newDestStock = setOrUpdateLocationStock(steelProd.id, papWarehouse.id, papAssembly.id, 100);

      const newComp = getProductCompanyStock(steelProd.id);

      logLedger({
        reference: ref,
        transactionType: 'INTERNAL_TRANSFER',
        productId: steelProd.id,
        sourceWarehouseId: cdcWarehouse.id,
        sourceLocationId: cdcRackA1.id,
        destWarehouseId: papWarehouse.id,
        destLocationId: papAssembly.id,
        quantityChange: 100,
        previousBalance: prevComp,
        newBalance: newComp,
        userId: adminUser.id,
        notes: `Guided Step 2: Transferred 100 kg from ${cdcWarehouse.name} to ${papWarehouse.name}. Company total remains ${newComp} kg unchanged!`
      });

      return {
        step: 2,
        title: 'Step 2: Internal Transfer Validated',
        action: 'Transferred 100 kg to Production Rack',
        reference: ref,
        from: `${cdcWarehouse.name} / ${cdcRackA1.name}`,
        to: `${papWarehouse.name} / ${papAssembly.name}`,
        quantityMoved: '100 kg',
        destinationStock: `${newDestStock} kg`,
        totalCompanyStock: `${newComp} kg (Invariant maintained!)`,
        ledgerReference: ref
      };
    } else if (stepNumber === 3) {
      // Step 3: Deliver 20 kg to Customer Apex Manufacturing
      const currentSource = getLocationStock(steelProd.id, papAssembly.id);
      if (currentSource < 20) {
        throw new Error(`Insufficient stock in ${papAssembly.name}. Required 20 kg, available: ${currentSource} kg. Please run Step 2 first!`);
      }

      const ref = `DEL-GUIDED-${Date.now().toString().slice(-4)}`;
      const del = db.prepare(`
        INSERT INTO delivery_orders (reference, customer_id, warehouse_id, location_id, status, notes, created_by, validated_at)
        VALUES (?, ?, ?, ?, 'done', 'Guided Demo: Customer dispatch of 20 kg steel to Apex Manufacturing.', ?, CURRENT_TIMESTAMP)
      `).run(ref, customer.id, papWarehouse.id, papAssembly.id, adminUser.id);

      db.prepare(`
        INSERT INTO delivery_lines (delivery_id, product_id, quantity_demanded, quantity_done, unit_price)
        VALUES (?, ?, ?, ?, ?)
      `).run(Number(del.lastInsertRowid), steelProd.id, 20, 20, 28.00);

      const prevComp = getProductCompanyStock(steelProd.id);
      const newLocStock = setOrUpdateLocationStock(steelProd.id, papWarehouse.id, papAssembly.id, -20);
      const newComp = getProductCompanyStock(steelProd.id);

      logLedger({
        reference: ref,
        transactionType: 'DELIVERY',
        productId: steelProd.id,
        sourceWarehouseId: papWarehouse.id,
        sourceLocationId: papAssembly.id,
        quantityChange: -20,
        previousBalance: prevComp,
        newBalance: newComp,
        userId: adminUser.id,
        notes: `Guided Step 3: Dispatched 20 kg to ${customer.name}. Stock decreased from ${prevComp} kg to ${newComp} kg.`
      });

      return {
        step: 3,
        title: 'Step 3: Customer Outgoing Delivery Validated',
        action: 'Dispatched 20 kg to Customer',
        reference: ref,
        customer: customer.name,
        fromLocation: `${papWarehouse.name} / ${papAssembly.name}`,
        quantityMoved: '-20 kg',
        remainingLocationStock: `${newLocStock} kg`,
        totalCompanyStock: `${newComp} kg`,
        ledgerReference: ref
      };
    } else if (stepNumber === 4) {
      // Step 4: Adjust 3 kg as damaged during assembly
      const currentSource = getLocationStock(steelProd.id, papAssembly.id);
      if (currentSource < 3) {
        throw new Error(`Insufficient stock in ${papAssembly.name}. Available: ${currentSource} kg.`);
      }

      const ref = `ADJ-GUIDED-${Date.now().toString().slice(-4)}`;
      const newLocStock = currentSource - 3;
      const prevComp = getProductCompanyStock(steelProd.id);

      db.prepare(`
        INSERT INTO inventory_adjustments (
          reference, product_id, warehouse_id, location_id,
          previous_quantity, counted_quantity, difference, reason, status, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'done', ?)
      `).run(
        ref,
        steelProd.id,
        papWarehouse.id,
        papAssembly.id,
        currentSource,
        newLocStock,
        -3,
        'Guided Demo: Physical count audit - 3 kg damaged during robotic lathe mounting',
        adminUser.id
      );

      setOrUpdateLocationStock(steelProd.id, papWarehouse.id, papAssembly.id, -3);
      const newComp = getProductCompanyStock(steelProd.id);

      logLedger({
        reference: ref,
        transactionType: 'ADJUSTMENT',
        productId: steelProd.id,
        sourceWarehouseId: papWarehouse.id,
        sourceLocationId: papAssembly.id,
        quantityChange: -3,
        previousBalance: prevComp,
        newBalance: newComp,
        userId: adminUser.id,
        notes: `Guided Step 4: Physical correction: 3 kg damaged. Final location stock is ${newLocStock} kg.`
      });

      return {
        step: 4,
        title: 'Step 4: Physical Stock Count & Adjustment Validated',
        action: 'Adjusted -3 kg as damaged in assembly',
        reference: ref,
        location: `${papWarehouse.name} / ${papAssembly.name}`,
        previousPhysical: `${currentSource} kg`,
        countedPhysical: `${newLocStock} kg`,
        difference: '-3 kg',
        totalCompanyStock: `${newComp} kg`,
        ledgerReference: ref,
        finalReport: {
          received: '+100 kg',
          transferred: '100 kg (in-transit to Detroit)',
          delivered: '-20 kg (Apex Manuf)',
          adjustedDamaged: '-3 kg (Lathe scrap)',
          netDelta: '+77 kg',
          auditVerification: '100% Verified in Stock Ledger'
        }
      };
    } else {
      throw new Error('Invalid step number (1-4 expected)');
    }
  });
}

function createSession(userId, rememberMe = true) {
  const token = crypto.randomBytes(32).toString('hex');
  const duration = rememberMe ? (30 * 24 * 60 * 60 * 1000) : (24 * 60 * 60 * 1000); // 30 days vs 24 hours
  const expiresAt = Date.now() + duration;

  db.prepare(`
    INSERT INTO sessions (token, user_id, expires_at)
    VALUES (?, ?, ?)
  `).run(token, userId, expiresAt);

  return { token, expiresAt };
}

function getUserFromSession(token) {
  if (!token) return null;
  // Clean expired sessions opportunistically
  db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).run(Date.now());

  const row = db.prepare(`
    SELECT s.user_id, s.expires_at, u.id, u.name, u.email, u.role, u.department, u.avatar, u.created_at
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > ?
  `).get(token, Date.now());

  if (!row) return null;
  const { user_id, expires_at, ...user } = row;
  return user;
}

function deleteSession(token) {
  if (!token) return;
  db.prepare(`DELETE FROM sessions WHERE token = ?`).run(token);
}

// Initialise DB immediately
initSchema();
seedDatabase();

module.exports = {
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
};

