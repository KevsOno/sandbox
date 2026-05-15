import streamlit as st
import pandas as pd
from supabase import create_client, Client
from datetime import date, datetime, timedelta
import numpy as np
import smtplib
from email.message import EmailMessage
from collections import defaultdict

# ---------- CONFIG ----------
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------- AUTH ----------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user_role = None

if not st.session_state.authenticated:
    pwd = st.text_input("Enter access password", type="password")
    if pwd == st.secrets.get("APP_PASSWORD", "changeme"):
        st.session_state.authenticated = True
        st.session_state.user_role = "admin"
        st.rerun()
    elif pwd == st.secrets.get("VIEWER_PASSWORD", ""):
        st.session_state.authenticated = True
        st.session_state.user_role = "viewer"
        st.rerun()
    elif pwd:
        st.error("Incorrect password")
    st.stop()

# ---------- HELPER FUNCTIONS ----------
def get_sales_velocity(product_id, days_back=30):
    """Return average daily demand (units) for a product."""
    # First check stock_limits table
    res = supabase.table("stock_limits").select("avg_daily_demand") \
        .eq("product_id", product_id).execute()
    if res.data and res.data[0].get("avg_daily_demand") is not None:
        return float(res.data[0]["avg_daily_demand"])
    # Fallback: compute from stock_movements (sales)
    start_date = (date.today() - timedelta(days=days_back)).isoformat()
    mov = supabase.table("stock_movements").select("quantity_change") \
        .eq("product_id", product_id) \
        .eq("movement_type", "sale") \
        .gte("movement_date", start_date).execute()
    total_sold = sum(abs(m["quantity_change"]) for m in mov.data) if mov.data else 0
    return total_sold / days_back

def get_reorder_point(product_id):
    """Return (reorder_point, safety_stock) from stock_limits or compute dynamic."""
    lim = supabase.table("stock_limits").select("reorder_point, safety_stock") \
        .eq("product_id", product_id).execute()
    if lim.data and lim.data[0].get("reorder_point") is not None:
        return lim.data[0]["reorder_point"], lim.data[0]["safety_stock"]
    demand = get_sales_velocity(product_id)
    lead_time = get_product_lead_time(product_id)
    reorder = max(5, int(demand * lead_time * 1.5))
    safety = max(3, int(demand * 3))
    return reorder, safety

def get_product_lead_time(product_id):
    res = supabase.table("products").select("lead_time_days").eq("id", product_id).execute()
    if res.data:
        return res.data[0].get("lead_time_days", 7)
    return 7

def get_current_stock(product_id):
    """Total quantity across all batches."""
    inv = supabase.table("inventory").select("quantity").eq("product_id", product_id).execute()
    return sum(i["quantity"] for i in inv.data) if inv.data else 0

def record_sale(product_id, quantity_sold, selling_price_per_unit, sale_date=None):
    """
    Deduct stock using FEFO (earliest expiry first), record sale and stock movement.
    Returns (success, message).
    """
    if sale_date is None:
        sale_date = date.today().isoformat()
    # Get all batches with quantity > 0, sorted by expiry
    batches = supabase.table("inventory").select("id, quantity, unit_cost, expiry_date") \
        .eq("product_id", product_id).gt("quantity", 0).order("expiry_date").execute().data
    if not batches:
        return False, "No stock available for this product."
    remaining = quantity_sold
    cogs_total = 0.0
    used_batches = []
    for batch in batches:
        if remaining <= 0:
            break
        deduct = min(remaining, batch["quantity"])
        new_qty = batch["quantity"] - deduct
        # Update inventory
        supabase.table("inventory").update({"quantity": new_qty}).eq("id", batch["id"]).execute()
        cogs_total += deduct * batch["unit_cost"]
        remaining -= deduct
        used_batches.append((batch["id"], deduct, batch["unit_cost"]))
    if remaining > 0:
        return False, f"Insufficient stock. Only {quantity_sold - remaining} units available."
    # Insert sales record
    avg_cogs = cogs_total / quantity_sold
    sale_record = {
        "sale_date": sale_date,
        "product_id": product_id,
        "quantity": quantity_sold,
        "selling_price_per_unit": selling_price_per_unit,
        "cogs_per_unit": avg_cogs,
        "notes": f"Auto FEFO: {len(used_batches)} batches"
    }
    supabase.table("sales").insert(sale_record).execute()
    # Insert stock movement
    supabase.table("stock_movements").insert({
        "product_id": product_id,
        "quantity_change": -quantity_sold,
        "movement_date": sale_date,
        "movement_type": "sale",
        "notes": f"Sale of {quantity_sold} units @ ₦{selling_price_per_unit}"
    }).execute()
    return True, f"Sale recorded. Profit: ₦{quantity_sold * (selling_price_per_unit - avg_cogs):,.2f}"

def send_monthly_report(month_offset=1):
    """Email monthly sales & profit summary for the previous month."""
    today = date.today()
    first_of_current = date(today.year, today.month, 1)
    last_month_end = first_of_current - timedelta(days=1)
    last_month_start = date(last_month_end.year, last_month_end.month, 1)
    # Fetch sales in range
    sales = supabase.table("sales").select("*, products(name)") \
        .gte("sale_date", last_month_start.isoformat()) \
        .lte("sale_date", last_month_end.isoformat()).execute().data
    if not sales:
        body = f"No sales recorded in {last_month_start.strftime('%B %Y')}."
    else:
        df = pd.DataFrame(sales)
        total_rev = df["total_revenue"].sum()
        total_cogs = df["total_cogs"].sum()
        total_profit = df["profit"].sum()
        margin = (total_profit / total_rev * 100) if total_rev else 0
        # Product breakdown
        prod_summary = df.groupby("products")["quantity"].sum().to_string()
        body = f"""
        Monthly Report – {last_month_start.strftime('%B %Y')}
        ============================================
        Total Revenue: ₦{total_rev:,.2f}
        Total COGS:    ₦{total_cogs:,.2f}
        Net Profit:    ₦{total_profit:,.2f}
        Margin:        {margin:.1f}%

        Top selling products (units):
        {prod_summary}
        """
    # Send email
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = f"Muzoscents Monthly Report - {last_month_start.strftime('%B %Y')}"
    msg["From"] = st.secrets["email"]["sender"]
    msg["To"] = st.secrets["email"]["to_email"]
    try:
        with smtplib.SMTP(st.secrets["email"]["smtp_server"], st.secrets["email"]["smtp_port"]) as server:
            server.starttls()
            server.login(st.secrets["email"]["sender"], st.secrets["email"]["password"])
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Email failed: {e}")
        return False

def get_purchasing_advice():
    """Return list of products needing reorder with suggested quantity."""
    advice = []
    products = supabase.table("products").select("id, name, sku, lead_time_days, reorder_point, safety_stock").execute().data
    for p in products:
        pid = p["id"]
        stock = get_current_stock(pid)
        velocity = get_sales_velocity(pid)
        lead = p.get("lead_time_days", 7)
        # Use stored reorder_point if exists, else compute
        rp, ss = get_reorder_point(pid)
        days_of_stock = stock / velocity if velocity > 0 else 999
        suggested_qty = 0
        reason = ""
        if stock <= rp:
            suggested_qty = max(int(velocity * lead * 2), 10)  # cover 2 lead times
            reason = f"Stock ({stock}) below reorder point ({rp})"
        elif days_of_stock < 14:
            suggested_qty = max(int(velocity * lead * 1.5), 5)
            reason = f"Only {days_of_stock:.0f} days of stock left"
        if suggested_qty > 0:
            advice.append({
                "product": p["name"],
                "sku": p["sku"],
                "current_stock": stock,
                "daily_demand": round(velocity, 2),
                "days_of_stock": round(days_of_stock, 1),
                "suggested_order_qty": suggested_qty,
                "reason": reason,
                "lead_time_days": lead
            })
    return advice

# ---------- GLOBAL NAVIGATION ----------
pages = ["Dashboard", "Products", "Inventory", "Sales Ledger", "Purchasing Advice",
         "Risk & FEFO", "Alerts & Advisories", "AI Stock Limits", "CSV Upload", "Monthly Report"]
if st.session_state.user_role == "viewer":
    pages = [p for p in pages if p not in ["Products", "CSV Upload"]]  # viewers cannot edit master data

page = st.sidebar.radio("Go to", pages)

# ========== PAGE: DASHBOARD ==========
if page == "Dashboard":
    st.header("📊 Muzoscents Dashboard")
    # Sales KPIs
    sales = supabase.table("sales").select("total_revenue, total_cogs, profit").execute().data
    if sales:
        df_s = pd.DataFrame(sales)
        total_rev = df_s["total_revenue"].sum()
        total_cogs = df_s["total_cogs"].sum()
        total_profit = df_s["profit"].sum()
        margin = (total_profit / total_rev * 100) if total_rev else 0
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Revenue", f"₦{total_rev:,.0f}")
        col2.metric("Total COGS", f"₦{total_cogs:,.0f}")
        col3.metric("Net Profit", f"₦{total_profit:,.0f}")
        col4.metric("Margin", f"{margin:.1f}%")
    else:
        st.info("No sales data yet. Add sales in 'Sales Ledger'.")
    # Stock overview
    inv_total = supabase.table("inventory").select("quantity, product_id").execute().data
    if inv_total:
        total_units = sum(i["quantity"] for i in inv_total)
        st.metric("Total Inventory Units", total_units)
    # Alerts summary
    alerts = supabase.table("alert_log").select("alert_type, action_taken").execute().data
    if alerts:
        df_a = pd.DataFrame(alerts)
        open_alerts = len(df_a[df_a["action_taken"].isna()])
        st.metric("Open Alerts", open_alerts)

# ========== PAGE: PRODUCTS ==========
elif page == "Products":
    st.header("📦 Products Master")
    if st.session_state.user_role != "admin":
        st.error("Admin only.")
        st.stop()
    # Show products table
    prods = supabase.table("products").select("*").execute().data
    if prods:
        df_p = pd.DataFrame(prods)
        st.dataframe(df_p[["sku","name","category","selling_price","lead_time_days","shelf_life_days"]])
    else:
        st.info("No products.")
    with st.form("add_product"):
        sku = st.text_input("SKU")
        name = st.text_input("Name")
        cat = st.text_input("Category")
        sp = st.number_input("Selling Price (₦)", min_value=0.0, step=0.5)
        lead = st.number_input("Lead Time (days)", min_value=1, value=7)
        shelf = st.number_input("Shelf Life (days)", min_value=1, value=90)
        if st.form_submit_button("Add Product"):
            if sku and name:
                supabase.table("products").insert({
                    "sku": sku, "name": name, "category": cat, "selling_price": sp,
                    "lead_time_days": lead, "shelf_life_days": shelf
                }).execute()
                st.success("Added")
                st.rerun()

# ========== PAGE: INVENTORY ==========
elif page == "Inventory":
    st.header("📦 Current Stock (Batch Level)")
    inv = supabase.table("inventory").select("*, products(name, sku)").execute().data
    if inv:
        df_i = pd.DataFrame(inv)
        df_i["product"] = df_i["products"].apply(lambda x: x["name"] if x else "")
        st.dataframe(df_i[["product","batch","quantity","unit_cost","expiry_date","storage_location"]])
    else:
        st.info("No inventory records.")
    with st.form("add_inventory"):
        prod_sku = st.text_input("Product SKU")
        batch = st.text_input("Batch")
        qty = st.number_input("Quantity", min_value=0)
        unit_cost = st.number_input("Unit Cost (₦)", min_value=0.0)
        exp_date = st.date_input("Expiry Date", min_value=date.today())
        loc = st.selectbox("Storage", ["warehouse","shelf","cold_room"])
        if st.form_submit_button("Add Stock"):
            prod = supabase.table("products").select("id").eq("sku", prod_sku).execute()
            if not prod.data:
                st.error("Product not found")
            else:
                supabase.table("inventory").insert({
                    "product_id": prod.data[0]["id"],
                    "batch": batch,
                    "quantity": qty,
                    "unit_cost": unit_cost,
                    "expiry_date": exp_date.isoformat(),
                    "storage_location": loc
                }).execute()
                # Record movement
                supabase.table("stock_movements").insert({
                    "product_id": prod.data[0]["id"],
                    "quantity_change": qty,
                    "movement_date": date.today().isoformat(),
                    "movement_type": "purchase",
                    "notes": f"Batch {batch}"
                }).execute()
                st.success("Stock added")
                st.rerun()

# ========== PAGE: SALES LEDGER ==========
elif page == "Sales Ledger":
    st.header("🧾 Sales Ledger & Profit Tracking")
    # Manual sale entry
    with st.form("record_sale"):
        prod_sku = st.text_input("Product SKU")
        qty = st.number_input("Quantity sold", min_value=1)
        selling_price = st.number_input("Selling price per unit (₦)", min_value=0.0, step=0.5)
        sale_date = st.date_input("Sale Date", value=date.today())
        if st.form_submit_button("Record Sale"):
            prod = supabase.table("products").select("id, name").eq("sku", prod_sku).execute()
            if not prod.data:
                st.error("Product not found")
            else:
                ok, msg = record_sale(prod.data[0]["id"], qty, selling_price, sale_date.isoformat())
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
    st.subheader("Sales History")
    sales = supabase.table("sales").select("*, products(name, sku)").order("sale_date", desc=True).execute().data
    if sales:
        df_s = pd.DataFrame(sales)
        df_s["product"] = df_s["products"].apply(lambda x: x["name"])
        df_s["profit"] = df_s["profit"].apply(lambda x: f"₦{x:,.0f}")
        st.dataframe(df_s[["sale_date","product","quantity","selling_price_per_unit","cogs_per_unit","profit"]])
        total_profit = df_s["profit"].astype(str).str.replace("₦","").str.replace(",","").astype(float).sum()
        st.metric("Total Profit (all time)", f"₦{total_profit:,.0f}")
    else:
        st.info("No sales yet.")

# ========== PAGE: PURCHASING ADVICE ==========
elif page == "Purchasing Advice":
    st.header("🛒 Intelligent Purchasing Recommendations")
    st.caption("Based on sales velocity, current stock, lead times, and reorder points.")
    advice = get_purchasing_advice()
    if advice:
        df_adv = pd.DataFrame(advice)
        st.dataframe(df_adv)
        st.subheader("Action Items")
        for _, row in df_adv.iterrows():
            st.info(f"**{row['product']}** – {row['reason']} → Order {row['suggested_order_qty']} units (lead time {row['lead_time_days']} days).")
    else:
        st.success("All products have healthy stock levels. No urgent reorder needed.")

# ========== PAGE: RISK & FEFO ==========
elif page == "Risk & FEFO":
    st.header("⚠️ Expiry Risk & FEFO Recommendations")
    # Similar logic as original but without branches
    inv = supabase.table("inventory").select("*, products(name, sku, selling_price)").execute().data
    if not inv:
        st.info("No inventory data.")
        st.stop()
    risk_data = []
    today = date.today()
    for item in inv:
        product = item.get("products") or {}
        days_to_expiry = (datetime.strptime(item["expiry_date"], "%Y-%m-%d").date() - today).days
        if days_to_expiry <= 0:
            expiry_score = 100
        elif days_to_expiry <= 7:
            expiry_score = 95
        elif days_to_expiry <= 30:
            expiry_score = 80
        elif days_to_expiry <= 90:
            expiry_score = 50
        else:
            expiry_score = 20
        financial = item["quantity"] * item["unit_cost"]
        risk_data.append({
            "Product": product.get("name"),
            "Batch": item["batch"],
            "Quantity": item["quantity"],
            "Expiry": item["expiry_date"],
            "Days Left": days_to_expiry,
            "Risk Score": expiry_score * 0.7 + (financial / 10000) * 0.3
        })
    df_risk = pd.DataFrame(risk_data)
    df_risk = df_risk.sort_values("Days Left")
    st.dataframe(df_risk)
    st.subheader("FEFO Order")
    st.markdown("Consume in this order (earliest expiry first):")
    for _, row in df_risk.iterrows():
        st.write(f"- {row['Product']} (Batch `{row['Batch']}`) – expires {row['Expiry']}")

# ========== PAGE: ALERTS & ADVISORIES ==========
elif page == "Alerts & Advisories":
    st.header("🚨 Alerts")
    alerts = supabase.table("alert_log").select("*, products(name)").order("created_at", desc=True).execute().data
    if alerts:
        df_al = pd.DataFrame(alerts)
        df_al["product"] = df_al["products"].apply(lambda x: x["name"] if x else "")
        st.dataframe(df_al[["product","batch","alert_type","details","action_taken","created_at"]])
        # Manual action update
        unactioned = [a for a in alerts if not a.get("action_taken")]
        if unactioned:
            alert_id = st.selectbox("Select Alert ID", [a["id"] for a in unactioned])
            action = st.text_input("Action description")
            if st.button("Mark Done"):
                supabase.table("alert_log").update({"action_taken": action, "action_date": "now()"}).eq("id", alert_id).execute()
                st.rerun()
    else:
        st.info("No alerts")

# ========== PAGE: AI STOCK LIMITS ==========
elif page == "AI Stock Limits":
    st.header("📊 AI‑Computed Stock Limits")
    limits = supabase.table("stock_limits").select("*, products(name)").execute().data
    if limits:
        df_lim = pd.DataFrame(limits)
        df_lim["product"] = df_lim["products"].apply(lambda x: x["name"])
        st.dataframe(df_lim[["product","avg_daily_demand","safety_stock","reorder_point","max_stock","calculated_at"]])
    else:
        st.info("Run the daily Edge Function to compute limits.")

# ========== PAGE: CSV UPLOAD ==========
elif page == "CSV Upload":
    st.header("📁 Bulk Upload (Products / Inventory / Sales)")
    entity = st.selectbox("Entity", ["Products", "Inventory", "Sales"])
    file = st.file_uploader("Upload CSV", type="csv")
    if file:
        df = pd.read_csv(file)
        st.dataframe(df.head())
        if st.button("Upload"):
            try:
                if entity == "Products":
                    required = {"sku","name","selling_price"}
                    if not all(c in df.columns for c in required):
                        st.error(f"Missing columns: {required}")
                    else:
                        df["lead_time_days"] = df.get("lead_time_days", 7)
                        supabase.table("products").insert(df.to_dict(orient="records")).execute()
                        st.success("Products uploaded")
                elif entity == "Inventory":
                    required = {"product_sku","batch","quantity","unit_cost","expiry_date"}
                    # Map SKU to product_id
                    skus = df["product_sku"].unique()
                    prods = {p["sku"]:p["id"] for p in supabase.table("products").select("id,sku").in_("sku", skus).execute().data}
                    df["product_id"] = df["product_sku"].map(prods)
                    if df["product_id"].isna().any():
                        st.error("Some SKUs not found")
                    else:
                        df = df[["product_id","batch","quantity","unit_cost","expiry_date"]]
                        supabase.table("inventory").insert(df.to_dict(orient="records")).execute()
                        st.success("Inventory uploaded")
                elif entity == "Sales":
                    required = {"product_sku","quantity","selling_price_per_unit","sale_date"}
                    # For each sale, call record_sale to handle FEFO
                    for _, row in df.iterrows():
                        prod = supabase.table("products").select("id").eq("sku", row["product_sku"]).execute()
                        if prod.data:
                            record_sale(prod.data[0]["id"], row["quantity"], row["selling_price_per_unit"], row["sale_date"])
                    st.success("Sales processed")
            except Exception as e:
                st.error(f"Upload error: {e}")

# ========== PAGE: MONTHLY REPORT ==========
elif page == "Monthly Report":
    st.header("📧 Monthly Report")
    st.markdown("Generate and email a summary of the previous month's sales and profit.")
    if st.button("Send Monthly Report by Email"):
        with st.spinner("Sending report..."):
            success = send_monthly_report()
            if success:
                st.success("Report sent successfully!")
            else:
                st.error("Failed to send email. Check secrets and network.")
    st.caption("Report is automatically based on last month's data. Configure recipient in secrets.")
