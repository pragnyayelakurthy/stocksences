# StockSense – Smart Inventory Management System
> *"Every Item. Every Movement. In Control."*

A centralized, real-time SaaS Inventory Management System that replaces manual registers, Excel spreadsheets, and scattered tracking methods with an auditable, multi-facility inventory operating platform.

Built for national-level hackathon presentation with persistent data storage, ACID inventory transactions, dynamic telemetry, and realistic end-to-end supply chain workflows.

---

## 🚀 Live Demo & Quick Start

The application server is running locally on:
```
https://stocksense-1-une7.onrender.com
```

### Pre-Configured Hackathon Demo Accounts:
| Role | Persona | Email | Password |
|---|---|---|---|
| **Inventory Manager** | Elena Vance | `elena@stocksense.io` | `password123` |
| **Warehouse Staff** | Marcus Chen | `marcus@stocksense.io` | `password123` |

*(A 1-click role switcher is also available directly in the top navigation bar and login screen).*

---

## 🎯 Key Architectural Pillars

### 1. Robust Persistent Database Engine (`node:sqlite`)
- Embedded SQLite engine running via Node.js v24 `DatabaseSync` (`stocksense.db`).
- Full WAL mode (`PRAGMA journal_mode = WAL;`) and enforced Foreign Key constraints.
- **ACID Transactions**: Every stock movement (Receipt, Delivery, Transfer, Adjustment) runs inside an isolated atomic transaction (`BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`).
- **Stock Integrity Safeguards**:
  - Stock levels cannot become negative through normal operations.
  - Deliveries verify available stock before decrementing.
  - Relocations verify that source location has sufficient quantity and maintain company-wide inventory balance invariants.
  - Duplicate validations on already processed documents are strictly blocked.

### 2. Premium SaaS Design System
- **Dark Navy Sidebar** (`#0B132B` / `#1E293B`) with collapsible state, active indicators, and operator badges.
- **Clean Workspace Canvas** (`#F8FAFC` / `#FFFFFF`) with subtle elevation, rounded corners, and consistent typography.
- **Emerald Green Primary Accent** (`#10B981`) paired with sapphire blue (`#3B82F6`), amber warning (`#F59E0B`), and rose critical alert (`#EF4444`).
- **Crisp Lucide SVG Icons** embedded natively to ensure offline reliability and instantaneous rendering.

---

## 📋 Comprehensive Module Guide

### 1. Main Dashboard
- **6 Dynamic KPI Telemetry Cards**:
  1. *Total Products in Stock* (company-wide sum with total inventory valuation)
  2. *Low Stock Items* (items at or below reorder threshold)
  3. *Out of Stock Items* (critical zero-stock SKUs)
  4. *Pending Receipts* (vendor shipments in draft/ready state)
  5. *Pending Deliveries* (customer orders in draft/waiting/ready state)
  6. *Scheduled Transfers* (inter-facility movements in transit)
- **Product Category Distribution**: Pure SVG donut chart with hover slice scaling, center telemetry, and interactive category breakdown.
- **Stock Movement Overview**: Grouped SVG bar chart tracking incoming vendor receipts against outgoing customer deliveries.
- **Smart Reorder Alerts Panel**: Lists depleted items with suggested replenishment quantities and a 1-click **Draft PO** generator.
- **Warehouse Health Summary**: Facility breakdown showing total units, unique SKUs, low-stock density, and active pending operations.
- **Multi-Document Filter Toolbar**: Instant filtering across Receipts, Deliveries, Transfers, and Adjustments by status, warehouse, and date.

### 2. Product Management
- Full CRUD: Create, Edit, Search, and Delete products with duplicate SKU validation.
- Fields: Name, SKU, Barcode, Category, Unit of Measure (UOM), Unit Cost, Reorder Alert Threshold, Target Restock Level.
- Multi-Warehouse stock modal showing availability per warehouse, rack, shelf, or pallet.
- Color-coded status pills: `IN STOCK`, `LOW STOCK`, and `OUT OF STOCK`.

### 3. Inbound Receipts (Vendor Stock Intake)
- Workflow: `Draft` &rarr; `Ready` &rarr; `Validate`.
- Only successful validation increases location physical stock balances.
- Generates auditable ledger entries tracking vendor and receiving location.

### 4. Outbound Delivery Orders (Customer Shipments)
- Workflow: `Draft` &rarr; `Waiting` &rarr; `Ready (Pick & Pack)` &rarr; `Validate`.
- **Availability Enforcement**: Rejects any order or validation where requested quantity exceeds available location stock.
- Decrements stock only upon dispatch validation.

### 5. Internal Stock Transfers
- Moves inventory between warehouses (e.g., CDC &rarr; Detroit Assembly) or internal racks (e.g., Receiving Bay &rarr; High-Bay Rack).
- Enforces source &ne; destination validation and source availability.
- **Mathematical Invariant**: Atomically moves inventory so that company-wide stock remains 100% unchanged.

### 6. Inventory Adjustments (Physical Cycle Counts)
- Select product and location &rarr; inspect system-recorded quantity.
- Enter physically counted on-shelf quantity &rarr; system computes variance (+ or -).
- Mandatory audit rationale / reason required.
- Corrects stock immediately and records previous vs new balance in the ledger.

### 7. Auditable Stock Movement Ledger
- Immutable event log for every receipt, delivery, transfer, and adjustment.
- Records reference code, timestamp, product SKU, source location, destination location, quantity change, previous balance, new balance, and responsible user.
- Search and filter by transaction type, facility, or SKU.
- **CSV Export**: Real one-click CSV download formatted to RFC4180 standards.

### 8. Multi-Warehouse & Location Management
- Supports multi-facility hierarchies: Central Distribution Center (WH-CDC), East Coast Hub (WH-EFH), and Detroit Production Plant (WH-PAP).
- Configurable storage nodes: High-bay racks, shelves, pallets, receiving bays, and production buffers.

### 9. Smart Features & Hackathon Innovations
- **Global Search (`Ctrl+K`)**: Live debounced search across all SKUs, product names, document references, and warehouse codes.
- **Smart Reorder Alerts**: Suggests replenishment deficit: `Target Stock - Current Stock`.
- **OTP Password Reset Simulation**: Fully functional interface with simulated demo code display for realistic presentation.
- **1-Click Demo Reset**: Instantly restores baseline realistic sample data anytime judges want to re-run scenarios.

---

## 🏆 Interactive Guided Hackathon Demo Scenario (Section 13.D)

A dedicated guided walkthrough is built directly into the UI (via the **Guided Demo** button in the header or sidebar):

1. **Step 1 • Inbound Receipt**: Receive 100 kg of Industrial Steel Rods (`STL-ROD-20M`) at CDC Rack A-01. Stock increases by 100 kg.
2. **Step 2 • Internal Transfer**: Relocate 100 kg from CDC to Detroit Production Floor Rack 1. Company total stock remains invariant!
3. **Step 3 • Customer Delivery**: Dispatch 20 kg to customer Apex Manufacturing. Available stock at Detroit plant decrements by 20 kg.
4. **Step 4 • Count Adjustment**: Physical cycle count flags 3 kg damaged during machining. Stock adjusted by -3 kg.
5. **Final Audit Verification**: Total net stock change across the 4 steps is exactly **+77 kg**, with all movements visible in the Stock Ledger!

---

## 🛠️ Verification & Testing

To run the automated end-to-end test suite:
```powershell
agy-node test_endpoints.js
```

All tests verify endpoint status codes, database transactions, stock calculations, and CSV export.
