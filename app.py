import streamlit as st
import pandas as pd
from supabase import create_client, Client
from datetime import date, datetime, timedelta
import numpy as np
from collections import defaultdict

# ---------- CONFIG ----------
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------- AUTH (two passwords) ----------
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
    elif pwd:  # only show error if something was entered
        st.error("Incorrect password")
    st.stop()

# ---------- EMAIL LINK AUTO-MARK (One-Click Done from Email) ----------
params = st.query_params
if "alert_id" in params and "action" in params:
    alert_id = params["alert_id"][0] if isinstance(params["alert_id"], list) else params["alert_id"]
    supabase.table("alert_log").update({
        "action_taken": "Marked done via email link",
        "action_date": "now()"
    }).eq("id", alert_id).execute()
    st.success(f"✅ Alert #{alert_id} marked as done!")
    st.query_params.clear()
    st.rerun()

# ---------- GLOBAL BRANCH SELECTOR ----------
branches_data = supabase.table("branches").select("*").execute().data
branch_options = {b['code']: b['id'] for b in branches_data}
branch_names = [b['name'] for b in branches_data]

selected_branch_name = st.sidebar.selectbox("Select Branch", ["All Branches"] + branch_names)
if selected_branch_name == "All Branches":
    branch_id = None
else:
    branch_id = next(b['id'] for b in branches_data if b['name'] == selected_branch_name)

# ---------- NAVIGATION (role‑based) ----------
if st.session_state.user_role == "admin":
    pages = [
        "Dashboard",
        "Branches",
        "Products",
        "Inventory",
        "CSV Upload",
        "Alerts & Advisories",
        "AI Limits",
        "Risk & FEFO",
        "Transfer Suggestions"
    ]
else:  # viewer
    pages = [
        "Dashboard",
        "Products",
        "Inventory",
        "CSV Upload",
        "Alerts & Advisories",
        "AI Limits",
        "Risk & FEFO",
        "Transfer Suggestions"
    ]

page = st.sidebar.radio("Go to", pages)

# ---------- HELPERS ----------
def validate_csv_columns(df, required_cols, label="CSV"):
    missing = required_cols - set(df.columns)
    if missing:
        return False, f"❌ Missing columns in {label}: {', '.join(missing)}\n\n📋 Required: {', '.join(required_cols)}"
    return True, ""

def upload_csv_to_table(table_name, df, extra_columns={}):
    for col, val in extra_columns.items():
        df[col] = val
    records = df.to_dict(orient="records")
    try:
        res = supabase.table(table_name).insert(records).execute()
        return res
    except Exception as e:
        st.error(f"Error inserting into {table_name}: {e}")
        return None

def get_sales_velocity(branch_id, product_id, days_back=30):
    limit_res = supabase.table("stock_limits").select("avg_daily_demand") \
        .eq("branch_id", branch_id).eq("product_id", product_id).execute()
    if limit_res.data and limit_res.data[0].get("avg_daily_demand") is not None:
        return float(limit_res.data[0]["avg_daily_demand"])
    
    start_date = (date.today() - timedelta(days=days_back)).isoformat()
    mov_res = supabase.table("stock_movements").select("quantity_change") \
        .eq("branch_id", branch_id).eq("product_id", product_id) \
        .gte("movement_date", start_date).execute()
    if mov_res.data:
        total_sold = abs(sum(m["quantity_change"] for m in mov_res.data if m["quantity_change"] < 0))
        return total_sold / days_back
    return 0.0

def get_reorder_point(branch_id, product_id):
    lim = supabase.table("stock_limits").select("reorder_point, safety_stock") \
        .eq("branch_id", branch_id).eq("product_id", product_id).execute()
    if lim.data:
        return lim.data[0].get("reorder_point", 0), lim.data[0].get("safety_stock", 0)
    demand = get_sales_velocity(branch_id, product_id)
    reorder = max(5, int(demand * 7))
    safety = max(3, int(demand * 3))
    return reorder, safety

# ============================================================
# PAGE: DASHBOARD
# ============================================================
if page == "Dashboard":
    st.header("📊 Executive Summary")
    inv_query = supabase.table("inventory").select("product_id, quantity, products(cost)")
    alert_query = supabase.table("alert_log").select("*, products(cost)")
    if branch_id:
        inv_query = inv_query.eq("branch_id", branch_id)
        alert_query = alert_query.eq("branch_id", branch_id)
    inv = inv_query.execute().data
    alerts = alert_query.execute().data
    if alerts:
        df_a = pd.DataFrame(alerts)
        total_alerts = len(df_a)
        expiring = df_a[df_a['alert_type'] == 'EXPIRY']
        inv_df = pd.DataFrame(inv) if inv else pd.DataFrame()
        wastage_val = 0
        if not inv_df.empty:
            for _, row in expiring.iterrows():
                qty = inv_df[inv_df['product_id'] == row['product_id']]['quantity'].sum()
                cost = row['products']['cost'] if row['products'] else 0
                wastage_val += qty * cost
        stockout = len(df_a[df_a['alert_type'] == 'RESTOCK'])
        dead_stock = len(df_a[df_a['alert_type'] == 'DEAD_STOCK'])
        actioned = len(df_a[df_a['action_taken'].notna()])
        compliance = round((actioned / total_alerts * 100), 1) if total_alerts else 0
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Waste Risk", f"₦{wastage_val:,.0f}")
        c2.metric("Stock‑out Risks", stockout)
        c3.metric("Dead Stock", dead_stock)
        c4.metric("Actions Done", f"{compliance}%")
        st.subheader("Alert Type Breakdown")
        st.bar_chart(df_a['alert_type'].value_counts())
    else:
        st.info("No alert data available yet. Run the daily Edge Function to generate alerts.")

# ============================================================
# PAGE: BRANCHES (with admin‑only guard)
# ============================================================
elif page == "Branches":
    # Extra hardening: stop viewers even if they manually navigate here
    if st.session_state.user_role != "admin":
        st.error("You do not have permission to manage branches.")
        st.stop()

    st.header("🏢 Branch Management")
    st.subheader("Current Branches")
    all_branches = supabase.table("branches").select("*").execute().data
    if all_branches:
        df_b = pd.DataFrame(all_branches)
        display_cols = ['name','code','storekeeper_email','procurement_email','inventory_email','auditor_email','manager_email']
        st.dataframe(df_b[display_cols].rename(columns={
            'name':'Name', 'code':'Code', 'storekeeper_email':'Storekeeper', 'procurement_email':'Procurement',
            'inventory_email':'Inventory', 'auditor_email':'Auditor', 'manager_email':'Manager'
        }))
    else:
        st.info("No branches yet.")
    st.markdown("---")
    st.subheader("➕ Add Single Branch")
    with st.form("add_branch_form"):
        col1, col2 = st.columns(2)
        with col1:
            name = st.text_input("Branch Name*")
            code = st.text_input("Branch Code* (e.g., LG01)")
        with col2:
            storekeeper_email = st.text_input("Storekeeper Email")
            procurement_email = st.text_input("Procurement Email")
            inventory_email = st.text_input("Inventory Email")
            auditor_email = st.text_input("Auditor Email")
        submitted = st.form_submit_button("Add Branch")
        if submitted:
            if not name or not code:
                st.error("Name and code are required.")
            else:
                try:
                    supabase.table("branches").insert({
                        "name": name,
                        "code": code,
                        "storekeeper_email": storekeeper_email or None,
                        "procurement_email": procurement_email or None,
                        "inventory_email": inventory_email or None,
                        "auditor_email": auditor_email or None
                    }).execute()
                    st.success(f"Branch '{name}' added.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")
    st.markdown("---")
    st.subheader("📁 Upload Branches CSV")
    st.markdown("**CSV columns:** `name`, `code`, `storekeeper_email`, `procurement_email`, `inventory_email`, `auditor_email`")
    template_df = pd.DataFrame(columns=['name','code','storekeeper_email','procurement_email','inventory_email','auditor_email'])
    csv = template_df.to_csv(index=False)
    st.download_button("📥 Download Branch Template", csv, "branches_template.csv", "text/csv")
    uploaded_file = st.file_uploader("Choose branches CSV", type="csv", key="branches_csv")
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.dataframe(df.head())
        required = {'name','code'}
        is_valid, msg = validate_csv_columns(df, required, "branches CSV")
        if not is_valid:
            st.error(msg)
            st.stop()
        for col in ['storekeeper_email','procurement_email','inventory_email','auditor_email']:
            if col not in df.columns:
                df[col] = None
        if st.button("Upload Branches"):
            records = df[['name','code','storekeeper_email','procurement_email','inventory_email','auditor_email']].to_dict(orient="records")
            try:
                supabase.table("branches").insert(records).execute()
                st.success("Branches uploaded!")
                st.rerun()
            except Exception as e:
                st.error(f"Upload failed: {e}")

# ============================================================
# PAGE: PRODUCTS
# ============================================================
elif page == "Products":
    st.header("📦 Products Master")
    st.subheader("Current Products")
    prods = supabase.table("products").select("*").execute().data
    if prods:
        df_p = pd.DataFrame(prods)
        st.dataframe(df_p[['sku','name','category','shelf_life_days','cost']].rename(columns={
            'sku':'SKU','name':'Name','category':'Category','shelf_life_days':'Shelf Life (days)','cost':'Unit Cost (₦)'
        }))
    else:
        st.info("No products yet.")
    st.markdown("---")
    st.subheader("➕ Add Single Product")
    with st.form("add_product_form"):
        col1, col2 = st.columns(2)
        with col1:
            sku = st.text_input("SKU*")
            name = st.text_input("Product Name*")
            category = st.text_input("Category")
        with col2:
            shelf_life = st.number_input("Shelf Life (days)", min_value=1, value=90)
            cost = st.number_input("Unit Cost (₦)", min_value=0.0, value=0.0, format="%.2f")
        submitted = st.form_submit_button("Add Product")
        if submitted:
            if not sku or not name:
                st.error("SKU and name are required.")
            else:
                try:
                    supabase.table("products").insert({
                        "sku": sku,
                        "name": name,
                        "category": category or None,
                        "shelf_life_days": shelf_life,
                        "cost": cost
                    }).execute()
                    st.success(f"Product '{name}' added.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")
    st.markdown("---")
    st.subheader("📁 Upload Products CSV")
    st.markdown("**CSV columns:** `sku`, `name`, `category`, `shelf_life_days`, `cost`")
    template_p = pd.DataFrame(columns=['sku','name','category','shelf_life_days','cost'])
    csv_p = template_p.to_csv(index=False)
    st.download_button("📥 Download Product Template", csv_p, "products_template.csv", "text/csv")
    uploaded_file = st.file_uploader("Choose products CSV", type="csv", key="products_csv")
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.dataframe(df.head())
        required = {'sku','name'}
        is_valid, msg = validate_csv_columns(df, required, "products CSV")
        if not is_valid:
            st.error(msg)
            st.stop()
        if 'category' not in df.columns:
            df['category'] = None
        if 'shelf_life_days' not in df.columns:
            df['shelf_life_days'] = 90
        if 'cost' not in df.columns:
            df['cost'] = 0.0
        if st.button("Upload Products"):
            records = df[['sku','name','category','shelf_life_days','cost']].to_dict(orient="records")
            try:
                supabase.table("products").insert(records).execute()
                st.success("Products uploaded!")
                st.rerun()
            except Exception as e:
                st.error(f"Upload failed: {e}")

# ============================================================
# PAGE: INVENTORY
# ============================================================
elif page == "Inventory":
    st.header("📦 Current Inventory")
    query = supabase.table("inventory").select("*, products(name, sku, cost), branches(name)")
    if branch_id:
        query = query.eq("branch_id", branch_id)
    inv_data = query.execute().data
    if inv_data:
        df_i = pd.DataFrame(inv_data)
        df_i['product'] = df_i['products'].apply(lambda x: x['name'] if x else '')
        df_i['branch'] = df_i['branches'].apply(lambda x: x['name'] if x else '')
        st.dataframe(df_i[['branch','product','batch','quantity','expiry_date','storage_location']])
    else:
        st.info("No inventory records found.")
    st.subheader("➕ Quick Manual Entry (one item)")
    with st.form("manual_inv"):
        prod_sku = st.text_input("Product SKU")
        batch = st.text_input("Batch")
        qty = st.number_input("Quantity", min_value=0)
        exp_date = st.date_input("Expiry Date", min_value=date.today())
        location = st.selectbox("Storage Location", ["warehouse", "shelf", "cold_room"])
        if st.form_submit_button("Add Item"):
            if not prod_sku:
                st.error("SKU required.")
            else:
                prod_res = supabase.table("products").select("id").eq("sku", prod_sku).execute()
                if not prod_res.data:
                    st.error("Product not found.")
                else:
                    br_id = branch_id if branch_id else st.selectbox("Branch", branch_names)
                    if not br_id:
                        br_id = branch_options[[b['code'] for b in branches_data if b['name'] == br_id][0]]
                    supabase.table("inventory").insert({
                        "branch_id": br_id,
                        "product_id": prod_res.data[0]['id'],
                        "batch": batch,
                        "quantity": qty,
                        "expiry_date": exp_date.isoformat() if exp_date else None,
                        "storage_location": location
                    }).execute()
                    st.success("Item added!")
                    st.rerun()

# ============================================================
# PAGE: CSV UPLOAD
# ============================================================
elif page == "CSV Upload":
    st.header("📁 Upload Inventory or Movement Data")
    upload_type = st.selectbox("Data Type", ["Inventory (current stock)", "Stock Movements (sales/restock)"])
    if branch_id:
        selected_branch_id = branch_id
        selected_branch_label = selected_branch_name
    else:
        branch_list = supabase.table("branches").select("id,name").execute().data
        branch_map = {b['name']: b['id'] for b in branch_list}
        selected_branch_label = st.selectbox("Select branch for data", list(branch_map.keys()))
        selected_branch_id = branch_map[selected_branch_label]
    uploaded_file = st.file_uploader("Choose CSV", type="csv", key="data_csv")
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.dataframe(df.head())
        if upload_type == "Inventory (current stock)":
            required_cols = {'product_sku','batch','quantity','expiry_date','storage_location'}
            is_valid, msg = validate_csv_columns(df, required_cols, "inventory CSV")
            if not is_valid:
                st.error(msg)
                st.stop()
            skus = df['product_sku'].unique().tolist()
            products_data = supabase.table("products").select("id, sku").in_("sku", skus).execute().data
            sku_to_id = {p['sku']: p['id'] for p in products_data}
            df['product_id'] = df['product_sku'].map(sku_to_id)
            missing = df[df['product_id'].isna()]['product_sku'].unique()
            if len(missing) > 0:
                st.error(f"❌ These SKUs not found in products: {missing}. Add them first.")
                st.stop()
            df['branch_id'] = selected_branch_id
            df['expiry_date'] = pd.to_datetime(df['expiry_date']).dt.date
            df = df[['branch_id','product_id','batch','quantity','expiry_date','storage_location']]
            if st.button("Upload Inventory"):
                res = upload_csv_to_table("inventory", df)
                if res:
                    st.success(f"Inventory uploaded for {selected_branch_label}!")
        else:
            required_cols = {'product_sku','quantity_change','movement_date'}
            is_valid, msg = validate_csv_columns(df, required_cols, "movements CSV")
            if not is_valid:
                st.error(msg)
                st.stop()
            skus = df['product_sku'].unique().tolist()
            products_data = supabase.table("products").select("id, sku").in_("sku", skus).execute().data
            sku_to_id = {p['sku']: p['id'] for p in products_data}
            df['product_id'] = df['product_sku'].map(sku_to_id)
            missing = df[df['product_id'].isna()]['product_sku'].unique()
            if len(missing) > 0:
                st.error(f"❌ These SKUs not found: {missing}")
                st.stop()
            df['branch_id'] = selected_branch_id
            df['movement_date'] = pd.to_datetime(df['movement_date']).dt.date
            if 'notes' not in df.columns:
                df['notes'] = ""
            df = df[['branch_id','product_id','quantity_change','movement_date','notes']]
            if st.button("Upload Movements"):
                res = upload_csv_to_table("stock_movements", df)
                if res:
                    st.success(f"Movements uploaded for {selected_branch_label}!")

# ============================================================
# PAGE: ALERTS & ADVISORIES
# ============================================================
elif page == "Alerts & Advisories":
    st.header("🚨 Alerts & Advisories")
    query = supabase.table("alert_log").select("*, products(name), branches(name)")
    if branch_id:
        query = query.eq("branch_id", branch_id)
    alerts = query.order("created_at", desc=True).execute().data
    if alerts:
        df_al = pd.DataFrame(alerts)
        df_al['product'] = df_al['products'].apply(lambda x: x['name'] if x else '')
        df_al['branch'] = df_al['branches'].apply(lambda x: x['name'] if x else '')
        st.dataframe(df_al[['branch','product','batch','alert_type','details','action_taken','created_at']])
        st.subheader("Manual Action Update")
        unactioned = [a for a in alerts if not a.get('action_taken')]
        if unactioned:
            alert_id = st.selectbox("Select Alert ID", [a['id'] for a in unactioned])
            action_text = st.text_input("Action Description")
            if st.button("Mark Done"):
                supabase.table("alert_log").update({
                    "action_taken": action_text,
                    "action_date": "now()"
                }).eq("id", alert_id).execute()
                st.success("Marked as done.")
                st.rerun()
        else:
            st.info("All alerts have been actioned.")
    else:
        st.info("No alerts available. Good job!")

# ============================================================
# PAGE: AI LIMITS
# ============================================================
elif page == "AI Limits":
    st.header("📊 AI-Computed Stock Limits")
    st.caption("These limits are automatically updated daily based on sales velocity.")
    lim_query = supabase.table("stock_limits").select("*, products(name), branches(name)")
    if branch_id:
        lim_query = lim_query.eq("branch_id", branch_id)
    limits = lim_query.execute().data
    if limits:
        df_l = pd.DataFrame(limits)
        df_l['product'] = df_l['products'].apply(lambda x: x['name'] if x else '')
        df_l['branch'] = df_l['branches'].apply(lambda x: x['name'] if x else '')
        st.dataframe(df_l[['branch','product','avg_daily_demand','safety_stock','reorder_point','max_stock','calculated_at']])
    else:
        st.info("No AI limits computed yet. Ensure the Edge Function has run and stock movements exist.")

# ============================================================
# PAGE: RISK & FEFO (with skipped_no_expiry counter)
# ============================================================
elif page == "Risk & FEFO":
    st.header("⚠️ Risk Scoring & FEFO Recommendations")
    st.markdown("""
    **FEFO** = *First Expired, First Out* – we recommend consuming batches with the earliest expiry date first.  
    **Risk Score** combines expiry proximity, financial exposure, and sales velocity.  
    **Risk Levels:** LOW 🟢 → MODERATE 🟡 → HIGH 🟠 → CRITICAL 🔴
    """)
    inv_query = supabase.table("inventory").select("""
        id, batch, quantity, expiry_date, storage_location,
        product_id, branch_id,
        products(name, sku, cost)
    """)
    if branch_id:
        inv_query = inv_query.eq("branch_id", branch_id)
    inventory = inv_query.execute().data
    if not inventory:
        st.info("No inventory records found. Please upload inventory data first.")
        st.stop()
    today = date.today()
    risk_data = []
    velocity_cache = {}
    unique_keys = {(item['branch_id'], item['product_id']) for item in inventory}
    for (b_id, p_id) in unique_keys:
        velocity_cache[(b_id, p_id)] = get_sales_velocity(b_id, p_id)
    skipped_no_expiry = 0
    for item in inventory:
        product = item.get('products') or {}
        product_name = product.get('name', 'Unknown')
        sku = product.get('sku', '')
        cost = float(product.get('cost', 0))
        quantity = item.get('quantity', 0)
        expiry_date_str = item.get('expiry_date')
        if not expiry_date_str:
            skipped_no_expiry += 1
            continue
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
        days_to_expiry = (expiry_date - today).days
        if days_to_expiry <= 0:
            expiry_score = 100.0
        elif days_to_expiry <= 7:
            expiry_score = 95.0
        elif days_to_expiry <= 30:
            expiry_score = 80.0
        elif days_to_expiry <= 90:
            expiry_score = 50.0
        else:
            expiry_score = 20.0
        financial_value = quantity * cost
        risk_data.append({
            'item': item,
            'product_name': product_name,
            'sku': sku,
            'batch': item['batch'],
            'quantity': quantity,
            'cost': cost,
            'financial_value': financial_value,
            'expiry_date': expiry_date,
            'days_to_expiry': days_to_expiry,
            'expiry_score': expiry_score,
            'branch_id': item['branch_id'],
            'product_id': item['product_id']
        })
    if skipped_no_expiry:
        st.info(f"ℹ️ {skipped_no_expiry} items skipped because they have no expiry date.")
    if not risk_data:
        st.warning("No valid inventory items with expiry dates found.")
        st.stop()
    financial_vals = [d['financial_value'] for d in risk_data]
    max_financial = max(financial_vals) if financial_vals else 1
    for d in risk_data:
        financial_score = (d['financial_value'] / max_financial) * 100 if max_financial > 0 else 0
        d['financial_score'] = financial_score
        velocity = velocity_cache.get((d['branch_id'], d['product_id']), 0.0)
        if velocity <= 0.1:
            velocity_score = 90.0
        elif velocity <= 0.5:
            velocity_score = 70.0
        elif velocity <= 2:
            velocity_score = 40.0
        else:
            velocity_score = 10.0
        d['velocity_score'] = velocity_score
        d['sales_velocity'] = velocity
        risk_score = (d['expiry_score'] * 0.5) + (d['financial_score'] * 0.3) + (velocity_score * 0.2)
        d['risk_score'] = risk_score
        if risk_score >= 80:
            risk_level = "CRITICAL"
            risk_emoji = "🔴"
        elif risk_score >= 60:
            risk_level = "HIGH"
            risk_emoji = "🟠"
        elif risk_score >= 35:
            risk_level = "MODERATE"
            risk_emoji = "🟡"
        else:
            risk_level = "LOW"
            risk_emoji = "🟢"
        d['risk_level'] = f"{risk_emoji} {risk_level}"
    df_risk = pd.DataFrame(risk_data)
    df_risk['expiry_date'] = pd.to_datetime(df_risk['expiry_date']).dt.date
    sort_by = st.selectbox("Sort by", ["Risk Score (highest first)", "Expiry Date (earliest first)", "Financial Value (highest first)"])
    if sort_by == "Risk Score (highest first)":
        df_display = df_risk.sort_values('risk_score', ascending=False)
    elif sort_by == "Expiry Date (earliest first)":
        df_display = df_risk.sort_values('expiry_date')
    else:
        df_display = df_risk.sort_values('financial_value', ascending=False)
    st.subheader("📋 Batch Risk Assessment")
    display_cols = ['product_name', 'sku', 'batch', 'quantity', 'cost', 'financial_value', 
                    'expiry_date', 'days_to_expiry', 'sales_velocity', 'risk_level']
    st.dataframe(df_display[display_cols].rename(columns={
        'product_name': 'Product', 'sku': 'SKU', 'financial_value': 'Financial Exposure (₦)',
        'days_to_expiry': 'Days Left', 'sales_velocity': 'Daily Demand (units)'
    }))
    st.subheader("📌 FEFO Recommendation (Consumption Order)")
    fefo_df = df_risk.sort_values(['expiry_date', 'risk_score'], ascending=[True, False])
    st.markdown("**Recommended order** – consume batches with earliest expiry date first, and within same expiry date prioritise higher risk:")
    for idx, row in fefo_df.iterrows():
        st.write(f"- **{row['product_name']}** (Batch `{row['batch']}`) – Expires **{row['expiry_date']}** – {row['risk_level']}")
    st.subheader("📊 Risk Distribution")
    risk_counts = df_risk['risk_level'].value_counts()
    st.bar_chart(risk_counts)
    with st.expander("ℹ️ How risk score is calculated"):
        st.markdown("""
        **Risk Score = (Expiry Score × 0.5) + (Financial Score × 0.3) + (Low Velocity Score × 0.2)**  
        - **Expiry Score** (0–100): ≤0d→100, 1-7d→95, 8-30d→80, 31-90d→50, >90d→20  
        - **Financial Score** (0–100): normalised quantity×cost  
        - **Low Velocity Score** (0–100): ≤0.1 units/day→90, 0.11-0.5→70, 0.51-2→40, >2→10  
        **Risk levels:** CRITICAL (≥80) → HIGH (60–79) → MODERATE (35–59) → LOW (<35)
        """)

# ============================================================
# PAGE: TRANSFER SUGGESTIONS (with days_str fix)
# ============================================================
elif page == "Transfer Suggestions":
    st.header("🔄 Inter‑Branch Transfer Suggestions")
    st.markdown("""
    **Enterprise logic:** Automatically identifies surplus stock that can be moved to branches with deficit or high demand.
    - **Surplus** = days of inventory > 45 days **OR** quantity > (reorder_point + safety_stock)
    - **Deficit** = days of inventory < 7 days **OR** quantity < reorder_point
    - **Expiry risk** = batches expiring within 30 days with low local demand → transfer to high‑demand branch
    - **High‑value slow movers** = financial exposure > ₦100k and sales velocity < 0.5 units/day → consolidate
    """)
    
    all_branches = supabase.table("branches").select("id, name").execute().data
    if len(all_branches) < 2:
        st.info("Need at least two branches to suggest transfers. Please add more branches.")
        st.stop()
    branch_map = {b['id']: b['name'] for b in all_branches}
    
    inv_all = supabase.table("inventory").select("""
        id, batch, quantity, expiry_date, branch_id, product_id,
        products(name, sku, cost)
    """).execute().data
    
    if not inv_all:
        st.info("No inventory data found. Please upload inventory first.")
        st.stop()
    
    branch_product_data = defaultdict(lambda: {
        'total_qty': 0,
        'batches': [],
        'cost': 0,
        'sales_velocity': 0,
        'reorder_point': 0,
        'safety_stock': 0,
        'days_inventory': float('inf')
    })
    
    velocity_cache = {}
    reorder_cache = {}
    for inv_item in inv_all:
        b_id = inv_item['branch_id']
        p_id = inv_item['product_id']
        key = (b_id, p_id)
        if key not in velocity_cache:
            velocity_cache[key] = get_sales_velocity(b_id, p_id)
        if key not in reorder_cache:
            rp, ss = get_reorder_point(b_id, p_id)
            reorder_cache[key] = (rp, ss)
    
    for inv_item in inv_all:
        b_id = inv_item['branch_id']
        p_id = inv_item['product_id']
        product = inv_item.get('products') or {}
        cost = float(product.get('cost', 0))
        qty = inv_item.get('quantity', 0)
        expiry = inv_item.get('expiry_date')
        key = (b_id, p_id)
        
        branch_product_data[key]['total_qty'] += qty
        branch_product_data[key]['cost'] = cost
        branch_product_data[key]['sales_velocity'] = velocity_cache.get(key, 0.0)
        rp, ss = reorder_cache.get(key, (0,0))
        branch_product_data[key]['reorder_point'] = rp
        branch_product_data[key]['safety_stock'] = ss
        
        if expiry:
            days_left = (datetime.strptime(expiry, '%Y-%m-%d').date() - date.today()).days
            branch_product_data[key]['batches'].append({
                'batch': inv_item['batch'],
                'qty': qty,
                'expiry_date': expiry,
                'days_left': days_left
            })
    
    for key, data in branch_product_data.items():
        vel = data['sales_velocity']
        if vel > 0:
            data['days_inventory'] = data['total_qty'] / vel
        else:
            data['days_inventory'] = 999
    
    surplus_items = []
    deficit_items = []
    for key, data in branch_product_data.items():
        b_id, p_id = key
        qty = data['total_qty']
        days = data['days_inventory']
        rp = data['reorder_point']
        ss = data['safety_stock']
        is_surplus = (days > 45) or (qty > (rp + ss + 10))
        is_deficit = (days < 7) or (qty < rp)
        if is_surplus:
            surplus_items.append({
                'branch_id': b_id,
                'product_id': p_id,
                'quantity': qty,
                'days_inventory': days,
                'reorder_point': rp,
                'safety_stock': ss,
                'batches': data['batches'],
                'cost': data['cost'],
                'sales_velocity': data['sales_velocity']
            })
        if is_deficit:
            deficit_items.append({
                'branch_id': b_id,
                'product_id': p_id,
                'quantity': qty,
                'days_inventory': days,
                'reorder_point': rp,
                'safety_stock': ss,
                'batches': data['batches'],
                'cost': data['cost'],
                'sales_velocity': data['sales_velocity']
            })
    
    suggestions = []
    
    for surp in surplus_items:
        for defi in deficit_items:
            if surp['product_id'] == defi['product_id'] and surp['branch_id'] != defi['branch_id']:
                transfer_qty = min(surp['quantity'] - (surp['reorder_point'] + surp['safety_stock']), 
                                   (defi['reorder_point'] + defi['safety_stock']) - defi['quantity'])
                if transfer_qty > 0:
                    days_from_str = f"{surp['days_inventory']:.0f}" if surp['days_inventory'] < 999 else "No recent sales"
                    days_to_str = f"{defi['days_inventory']:.0f}" if defi['days_inventory'] < 999 else "No recent sales"
                    suggestions.append({
                        'from_branch': branch_map[surp['branch_id']],
                        'to_branch': branch_map[defi['branch_id']],
                        'product_name': next((p['products']['name'] for p in inv_all if p['product_id'] == surp['product_id']), 'Unknown'),
                        'sku': next((p['products']['sku'] for p in inv_all if p['product_id'] == surp['product_id']), ''),
                        'quantity': transfer_qty,
                        'reason': f"Surplus in {branch_map[surp['branch_id']]} ({days_from_str} of stock) → deficit in {branch_map[defi['branch_id']]} (only {days_to_str} left).",
                        'urgency': 'HIGH' if defi['days_inventory'] < 3 else 'MEDIUM'
                    })
    
    for inv_item in inv_all:
        expiry = inv_item.get('expiry_date')
        if not expiry:
            continue
        days_left = (datetime.strptime(expiry, '%Y-%m-%d').date() - date.today()).days
        if days_left <= 30:
            b_id_from = inv_item['branch_id']
            p_id = inv_item['product_id']
            vel_from = velocity_cache.get((b_id_from, p_id), 0.0)
            if vel_from <= 0.5:
                best_target = None
                best_vel = vel_from
                for target_branch in all_branches:
                    t_id = target_branch['id']
                    if t_id == b_id_from:
                        continue
                    vel_to = velocity_cache.get((t_id, p_id), 0.0)
                    if vel_to > best_vel:
                        best_vel = vel_to
                        best_target = t_id
                if best_target and best_vel > vel_from + 0.2:
                    suggestions.append({
                        'from_branch': branch_map[b_id_from],
                        'to_branch': branch_map[best_target],
                        'product_name': inv_item['products']['name'],
                        'sku': inv_item['products']['sku'],
                        'quantity': inv_item['quantity'],
                        'reason': f"Batch expires in {days_left} days, but current branch has very low demand ({vel_from:.1f} units/day). Transfer to {branch_map[best_target]} where demand is {best_vel:.1f} units/day to avoid waste.",
                        'urgency': 'CRITICAL' if days_left <= 7 else 'HIGH'
                    })
    
    for key, data in branch_product_data.items():
        b_id, p_id = key
        if data['total_qty'] * data['cost'] > 100000 and data['sales_velocity'] < 0.5:
            if len(all_branches) > 1:
                target_branch = all_branches[0]['id']
                if target_branch == b_id:
                    target_branch = all_branches[1]['id']
                suggestions.append({
                    'from_branch': branch_map[b_id],
                    'to_branch': branch_map[target_branch],
                    'product_name': next((p['products']['name'] for p in inv_all if p['product_id'] == p_id), 'Unknown'),
                    'sku': next((p['products']['sku'] for p in inv_all if p['product_id'] == p_id), ''),
                    'quantity': data['total_qty'],
                    'reason': f"High‑value slow mover (₦{data['total_qty']*data['cost']:,.0f} value, {data['sales_velocity']:.1f} units/day). Consolidate to reduce holding cost.",
                    'urgency': 'MEDIUM'
                })
    
    unique_suggestions = []
    seen = set()
    for s in suggestions:
        key = (s['from_branch'], s['to_branch'], s['product_name'])
        if key not in seen:
            seen.add(key)
            unique_suggestions.append(s)
    
    if unique_suggestions:
        df_sugg = pd.DataFrame(unique_suggestions)
        urgency_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
        df_sugg['urgency_num'] = df_sugg['urgency'].map(urgency_order)
        df_sugg = df_sugg.sort_values('urgency_num')
        st.subheader("📋 Suggested Transfers")
        st.dataframe(df_sugg[['from_branch', 'to_branch', 'product_name', 'sku', 'quantity', 'urgency', 'reason']])
        st.subheader("📊 Summary by Urgency")
        st.bar_chart(df_sugg['urgency'].value_counts())
    else:
        st.success("✅ No transfer suggestions at this time. Inventory appears well balanced.")
    
    with st.expander("ℹ️ How suggestions are generated"):
        st.markdown("""
        - **Surplus → Deficit:** A branch has >45 days of stock or exceeds reorder point + safety stock; another branch is below reorder point.
        - **Expiry risk transfer:** Batch expiring in ≤30 days located in a slow‑selling branch is suggested to move to a branch with higher demand for that product.
        - **High‑value slow movers:** Products with total value >₦100,000 and sales velocity <0.5 units/day are recommended for consolidation.
        
        Suggestions are deduplicated and sorted by urgency (CRITICAL → HIGH → MEDIUM).
        """)
