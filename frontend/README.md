# Civic & Financial Transparency Web Interface (`frontend/`)

A standalone, bilingual (`es-CR` / `en`) civic accountability interface using the project's civic trust palette:
- **Deep Navy (`#17324D`):** Governance header, trust badges, and primary controls
- **Emerald Green (`#16866A`):** Verified/completed milestones, released payouts, and 0%-capped fee badges
- **Warm White (`#F8FAFC`):** Clean surface background
- **Slate Gray (`#64748B`):** Supporting metadata and audit captions
- **Amber (`#D99A24`):** Pending inspector verification, active Subasta settlements, and configuration notices

## Key Features
1. **Dynamic Organization Setup GUI (Zero Hardcoded Names):**
   - If the backend starts without a configuration file (`go run ./cmd/server -config=""`), the UI displays an actionable warning and opens the **Organization Setup Panel** so the administrator can configure the organization name, tenant ID, and committee account directly in the browser or load [`config/organization.json`](../config/organization.json).
2. **All Three Collection Avenues:**
   - **Avenue 1 (Project Crowdfunding via SINPE Móvil / Card On-Ramp):** Contribute in `CRC` or `USD` with optional anonymous donor redaction (`"Anónimo"`).
   - **Avenue 2 (Donated-Item Subasta Marketplace):** Simulate 10 bidders locking `$50` in a Blind Subasta, settle the auction (locking the 1 winner into an Item Delivery Escrow and refunding the 9 losers 100%), and verify item delivery to release proceeds into the Committee Public Fund.
   - **Avenue 3 (Committee Public Fund):** Donate directly to the organization pool and allocate pool funds strictly into posted Project Milestone Escrows.
3. **End-to-End Milestone Verification & SINPE Contractor Settlement:**
   - Walk through `1. Contractor Submit Evidence` $\rightarrow$ `2. Inspector Verify` $\rightarrow$ `3. Committee Approve` $\rightarrow$ `4. Anchor SINPE Bank Comprobante Hash`.

## Running Locally

```bash
cd backend
go run ./cmd/server
```
Then open `http://127.0.0.1:8080` in your browser.
