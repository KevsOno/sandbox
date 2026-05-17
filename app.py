import streamlit as st
import pandas as pd
from supabase import create_client, Client
from datetime import date, datetime, timedelta
from collections import defaultdict

# ---------- CONFIG ----------
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]

@st.cache_resource
def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)

supabase = get_supabase()

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

# ---------- EMAIL LINK AUTO-MARK ----------
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

# ---------- BRANCH SELECTOR ----------
@st.cache_data(ttl=300)
def get_branches():
    return supabase.table("branches").select("*").execute().data

branches_data = get_branches()
branch_names = [b['name'] for b in branches_data]
branch_id_map = {b['name']: b['id'] for b in branches_data}

selected_branch_name = st.sidebar.selectbox("Select Branch", ["All Branches"] + branch_names)
branch_id = None if selected_branch_name == "All Branches" else branch_id_map[selected_branch_name]

# ---------- NAVIGATION ----------
if st.session_state.user_role == "admin":
    pages = ["Dashboard", "Branches", "Products", "Inventory", "CSV Upload", "Alerts & Advisories", "AI Limits", "Risk & FEFO", "Transfer Suggestions"]
else:
    pages = ["Dashboard", "Products", "Inventory", "CSV Upload", "Alerts & Advisories", "AI Limits", "Risk & FEFO", "Transfer Suggestions"]

page = st.sidebar.radio("Go to", pages)

# ---------- HELPERS ----------
def validate_csv_columns(df, required_cols, label="CSV"):
    missing = required_cols - set(df.columns)
    if missing:
        return False, f"❌ Missing columns in {label}: {', '.join(missing)}"
    return True, ""

def upload_csv_to_table(table_name, df, extra_columns={}):
    for col, val in extra_columns.items():
        df[col] = val
    records = df.to_dict(orient="records")
    try:
        chunk_size = 500
        for i in range(0, len(records), chunk_size):
            supabase.table(table_name).insert(records[i:i+chunk_size]).execute()
        return True
    except Exception as e:
        st.error(f"Error inserting into {table_name}: {e}")
        return False

@st.cache_data(ttl=3600)
def get_branch_product_aggregates():
    """Pre-aggregate inventory per branch+product for transfer suggestions."""
    inv = supabase.table("inventory").select("branch_id, product_id, quantity, expiry_date, batch, products(cost)").execute().data
    agg = {}
    for i in inv:
        key = (i['branch_id'], i['product_id'])
        if key not in agg:
            agg[key] = {
                'total_qty': 0,
                'batches': [],
                'cost': i['products']['cost'] if i['products'] else 0
            }
        agg[key]['total_qty'] += i['quantity']
        if i.get('expiry_date'):
            agg[key]['batches'].append({
                'batch': i['batch'],
                'qty': i['quantity'],
                'expiry_date': i['expiry_date']
            })
    return agg

# ============================================================
# PAGE: DASHBOARD (uses RPC aggregates, no large data pull)
# ============================================================
if page == "Dashboard":
    st.header("📊 Executive Summary")
    
    if branch_id:
        total_val = supabase.rpc("get_total_value", {"branch_id_param": branch_id}).execute().data
        waste_val = supabase.rpc("get_waste_risk", {"branch_id_param": branch_id}).execute().data
    else:
        total_val = supabase.rpc("get_total_value_all").execute().data
        waste_val = supabase.rpc("get_waste_risk_all").execute().data
    
    total_val = total_val or 0
    waste_val = waste_val or 0
    
    col1, col2 = st.columns(2)
    col1.metric("Total Inventory Value", f"₦{total_val:,.0f}")
    col2.metric("Waste Risk (next 30d)", f"₦{waste_val:,.0f}")
    
    # Alert counts
    alert_query = supabase.table("alert_log").select("alert_type, action_taken")
    if branch_id:
        alert_query = alert_query.eq("branch_id", branch_id)
    alerts = alert_query.execute().data
    if alerts:
        df_a = pd.DataFrame(alerts)
        total_alerts = len(df_a)
        actioned = df_a['action_taken'].notna().sum()
        compliance = round(actioned / total_alerts * 100, 1) if total_alerts else 0
        st.metric("Alert Compliance", f"{compliance}%")
        st.subheader("Alert Type Breakdown")
        st.bar_chart(df_a['alert_type'].value_counts())
    else:
        st.info("No alerts yet. Run daily maintenance function.")

# ============================================================
# PAGE: BRANCHES (admin only, editable, no delete)
# ============================================================
elif page == "Branches":
    if st.session_state.user_role != "admin":
        st.error("Permission denied.")
        st.stop()
    
    st.header("🏢 Branch Management")
    st.markdown("Edit branch details below. No deletion is allowed.")
    
    branches = get_branches()
    if not branches:
        st.info("No branches found. Use 'Add Branch' below.")
    else:
        for branch in branches:
            with st.expander(f"✏️ {branch['name']} ({branch['code']})"):
                with st.form(key=f"edit_branch_{branch['id']}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        new_name = st.text_input("Branch Name", value=branch['name'])
                        new_code = st.text_input("Branch Code", value=branch['code'])
                    with col2:
                        new_storekeeper = st.text_input("Storekeeper Email", value=branch.get('storekeeper_email', ''))
                        new_procurement = st.text_input("Procurement Email", value=branch.get('procurement_email', ''))
                        new_inventory = st.text_input("Inventory Email", value=branch.get('inventory_email', ''))
                        new_auditor = st.text_input("Auditor Email", value=branch.get('auditor_email', ''))
                        new_manager = st.text_input("Manager Email", value=branch.get('manager_email', ''))
                    
                    submitted = st.form_submit_button("💾 Save Changes")
                    if submitted:
                        update_data = {}
                        if new_name != branch['name']:
                            update_data['name'] = new_name
                        if new_code != branch['code']:
                            update_data['code'] = new_code
                        if new_storekeeper != branch.get('storekeeper_email', ''):
                            update_data['storekeeper_email'] = new_storekeeper or None
                        if new_procurement != branch.get('procurement_email', ''):
                            update_data['procurement_email'] = new_procurement or None
                        if new_inventory != branch.get('inventory_email', ''):
                            update_data['inventory_email'] = new_inventory or None
                        if new_auditor != branch.get('auditor_email', ''):
                            update_data['auditor_email'] = new_auditor or None
                        if new_manager != branch.get('manager_email', ''):
                            update_data['manager_email'] = new_manager or None
                        
                        if update_data:
                            try:
                                supabase.table("branches").update(update_data).eq("id", branch['id']).execute()
                                st.success(f"✅ Branch '{new_name}' updated.")
                                st.cache_data.clear()
                                st.rerun()
                            except Exception as e:
                                st.error(f"Update failed: {e}")
                        else:
                            st.info("No changes made.")
    
    st.markdown("---")
    st.subheader("➕ Add New Branch")
    with st.form("add_branch_form"):
        col1, col2 = st.columns(2)
        with col1:
            name = st.text_input("Branch Name*")
            code = st.text_input("Branch Code*")
        with col2:
            storekeeper_email = st.text_input("Storekeeper Email")
            procurement_email = st.text_input("Procurement Email")
            inventory_email = st.text_input("Inventory Email")
            auditor_email = st.text_input("Auditor Email")
            manager_email = st.text_input("Manager Email")
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
                        "auditor_email": auditor_email or None,
                        "manager_email": manager_email or None
                    }).execute()
                    st.success(f"Branch '{name}' added.")
                    st.cache_data.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")
    
    st.markdown("---")
    st.subheader("📁 Bulk Upload Branches CSV")
    st.markdown("**CSV columns:** `name`, `code`, `storekeeper_email`, `procurement_email`, `inventory_email`, `auditor_email`, `manager_email`")
    template_df = pd.DataFrame(columns=['name','code','storekeeper_email','procurement_email','inventory_email','auditor_email','manager_email'])
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
        for col in ['storekeeper_email','procurement_email','inventory_email','auditor_email','manager_email']:
            if col not in df.columns:
                df[col] = None
        if st.button("Upload Branches"):
            records = df[['name','code','storekeeper_email','procurement_email','inventory_email','auditor_email','manager_email']].to_dict(orient="records")
            try:
                supabase.table("branches").insert(records).execute()
                st.success("Branches uploaded!")
                st.cache_data.clear()
                st.rerun()
            except Exception as e:
                st.error(f"Upload failed: {e}")

# ============================================================
# PAGE: PRODUCTS (pagination)
# ============================================================
elif page == "Products":
    st.header("📦 Products Master")
    PAGE_SIZE = 50
    if "prod_page" not in st.session_state:
        st.session_state.prod_page = 0
    offset = st.session_state.prod_page * PAGE_SIZE
    
    # Get total count
    total_res = supabase.table("products").select("id", count="exact").execute()
    total = total_res.count
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    
    prods = supabase.table("products").select("*").range(offset, offset+PAGE_SIZE-1).execute().data
    if prods:
        df_p = pd.DataFrame(prods)
        st.dataframe(df_p[['sku','name','category','shelf_life_days','cost']])
    else:
        st.info("No products yet.")
    
    col1, col2 = st.columns(2)
    if col1.button("Prev", disabled=st.session_state.prod_page==0):
        st.session_state.prod_page -= 1
        st.rerun()
    if col2.button("Next", disabled=st.session_state.prod_page>=total_pages-1):
        st.session_state.prod_page += 1
        st.rerun()
    st.caption(f"Page {st.session_state.prod_page+1} of {total_pages}")
    
    st.markdown("---")
    st.subheader("➕ Add Single Product")
    with st.form("add_product"):
        sku = st.text_input("SKU*")
        name = st.text_input("Product Name*")
        category = st.text_input("Category")
        shelf_life = st.number_input("Shelf Life (days)", min_value=1, value=90)
        cost = st.number_input("Unit Cost (₦)", min_value=0.0, value=0.0, format="%.2f")
        if st.form_submit_button("Add"):
            if not sku or not name:
                st.error("SKU and name required.")
            else:
                supabase.table("products").insert({
                    "sku": sku, "name": name, "category": category or None,
                    "shelf_life_days": shelf_life, "cost": cost
                }).execute()
                st.rerun()

# ============================================================
# PAGE: INVENTORY (pagination)
# ============================================================
elif page == "Inventory":
    st.header("📦 Current Inventory")
    PAGE_SIZE = 100
    if "inv_page" not in st.session_state:
        st.session_state.inv_page = 0
    offset = st.session_state.inv_page * PAGE_SIZE
    
    # Build base query for count
    count_query = supabase.table("inventory").select("id", count="exact")
    if branch_id:
        count_query = count_query.eq("branch_id", branch_id)
    total = count_query.execute().count
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    
    # Fetch data for current page
    data_query = supabase.table("inventory").select("*, products(name, sku, cost), branches(name)")
    if branch_id:
        data_query = data_query.eq("branch_id", branch_id)
    inv_data = data_query.range(offset, offset+PAGE_SIZE-1).execute().data
    
    if inv_data:
        df_i = pd.DataFrame(inv_data)
        df_i['product'] = df_i['products'].apply(lambda x: x['name'] if x else '')
        df_i['branch'] = df_i['branches'].apply(lambda x: x['name'] if x else '')
        st.dataframe(df_i[['branch','product','batch','quantity','expiry_date','storage_location']])
    else:
        st.info("No inventory records.")
    
    col1, col2 = st.columns(2)
    if col1.button("Prev", disabled=st.session_state.inv_page==0):
        st.session_state.inv_page -= 1
        st.rerun()
    if col2.button("Next", disabled=st.session_state.inv_page>=total_pages-1):
        st.session_state.inv_page += 1
        st.rerun()
    st.caption(f"Page {st.session_state.inv_page+1} of {total_pages}")

# ============================================================
# PAGE: CSV UPLOAD (unchanged logic, uses chunked helper)
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
                st.error(f"❌ SKUs not found: {missing}")
                st.stop()
            df['branch_id'] = selected_branch_id
            df['expiry_date'] = pd.to_datetime(df['expiry_date']).dt.date
            df = df[['branch_id','product_id','batch','quantity','expiry_date','storage_location']]
            if st.button("Upload Inventory"):
                if upload_csv_to_table("inventory", df):
                    st.success(f"Inventory uploaded for {selected_branch_label}!")
        else:  # movements
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
                st.error(f"❌ SKUs not found: {missing}")
                st.stop()
            df['branch_id'] = selected_branch_id
            df['movement_date'] = pd.to_datetime(df['movement_date']).dt.date
            if 'notes' not in df.columns:
                df['notes'] = ""
            df = df[['branch_id','product_id','quantity_change','movement_date','notes']]
            if st.button("Upload Movements"):
                if upload_csv_to_table("stock_movements", df):
                    st.success(f"Movements uploaded for {selected_branch_label}!")

# ============================================================
# PAGE: ALERTS & ADVISORIES (pagination)
# ============================================================
elif page == "Alerts & Advisories":
    st.header("🚨 Alerts & Advisories")
    PAGE_SIZE = 50
    if "alert_page" not in st.session_state:
        st.session_state.alert_page = 0
    offset = st.session_state.alert_page * PAGE_SIZE
    
    # Count total alerts
    count_query = supabase.table("alert_log").select("id", count="exact")
    if branch_id:
        count_query = count_query.eq("branch_id", branch_id)
    total = count_query.execute().count
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    
    # Fetch data
    data_query = supabase.table("alert_log").select("*, products(name), branches(name)").order("created_at", desc=True)
    if branch_id:
        data_query = data_query.eq("branch_id", branch_id)
    alerts = data_query.range(offset, offset+PAGE_SIZE-1).execute().data
    
    if alerts:
        df_al = pd.DataFrame(alerts)
        df_al['product'] = df_al['products'].apply(lambda x: x['name'] if x else '')
        df_al['branch'] = df_al['branches'].apply(lambda x: x['name'] if x else '')
        st.dataframe(df_al[['branch','product','batch','alert_type','details','action_taken','created_at']])
    else:
        st.info("No alerts.")
    
    col1, col2 = st.columns(2)
    if col1.button("Prev Alerts", disabled=st.session_state.alert_page==0):
        st.session_state.alert_page -= 1
        st.rerun()
    if col2.button("Next Alerts", disabled=st.session_state.alert_page>=total_pages-1):
        st.session_state.alert_page += 1
        st.rerun()
    st.caption(f"Page {st.session_state.alert_page+1} of {total_pages}")
    
    # Manual action update (for unactioned alerts on current page)
    unactioned = [a for a in alerts if not a.get('action_taken')] if alerts else []
    if unactioned:
        st.subheader("Manual Action Update")
        alert_id = st.selectbox("Select Alert ID", [a['id'] for a in unactioned])
        action_text = st.text_input("Action Description")
        if st.button("Mark Done"):
            supabase.table("alert_log").update({
                "action_taken": action_text,
                "action_date": "now()"
            }).eq("id", alert_id).execute()
            st.success("Marked as done.")
            st.rerun()
    elif alerts:
        st.info("All displayed alerts have been actioned.")

# ============================================================
# PAGE: AI LIMITS (pagination)
# ============================================================
elif page == "AI Limits":
    st.header("📊 AI-Computed Stock Limits")
    st.caption("These limits are automatically updated daily based on sales velocity.")
    PAGE_SIZE = 50
    if "limits_page" not in st.session_state:
        st.session_state.limits_page = 0
    offset = st.session_state.limits_page * PAGE_SIZE
    
    count_query = supabase.table("stock_limits").select("id", count="exact")
    if branch_id:
        count_query = count_query.eq("branch_id", branch_id)
    total = count_query.execute().count
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    
    data_query = supabase.table("stock_limits").select("*, products(name), branches(name)")
    if branch_id:
        data_query = data_query.eq("branch_id", branch_id)
    limits = data_query.range(offset, offset+PAGE_SIZE-1).execute().data
    
    if limits:
        df_l = pd.DataFrame(limits)
        df_l['product'] = df_l['products'].apply(lambda x: x['name'] if x else '')
        df_l['branch'] = df_l['branches'].apply(lambda x: x['name'] if x else '')
        st.dataframe(df_l[['branch','product','avg_daily_demand','safety_stock','reorder_point','max_stock','calculated_at']])
    else:
        st.info("No AI limits computed yet. Ensure the daily maintenance function has run.")
    
    col1, col2 = st.columns(2)
    if col1.button("Prev Limits", disabled=st.session_state.limits_page==0):
        st.session_state.limits_page -= 1
        st.rerun()
    if col2.button("Next Limits", disabled=st.session_state.limits_page>=total_pages-1):
        st.session_state.limits_page += 1
        st.rerun()
    st.caption(f"Page {st.session_state.limits_page+1} of {total_pages}")

# ============================================================
# PAGE: RISK & FEFO (reads from precomputed product_risk_scores)
# ============================================================
elif page == "Risk & FEFO":
    st.header("⚠️ Risk Scoring & FEFO Recommendations")
    st.markdown("""
    **FEFO** = *First Expired, First Out* – we recommend consuming batches with the earliest expiry date first.  
    **Risk Score** combines expiry proximity (now with 90-day write‑off threshold), financial exposure, and sales velocity.  
    **Risk Levels:** LOW 🟢 → MODERATE 🟡 → HIGH 🟠 → CRITICAL 🔴
    """)
    query = supabase.table("product_risk_scores").select("*, products(name, sku), branches(name)")
    if branch_id:
        query = query.eq("branch_id", branch_id)
    risk_scores = query.execute().data
    if not risk_scores:
        st.info("No risk scores available. Run the daily maintenance function first.")
        st.stop()
    
    df_risk = pd.DataFrame(risk_scores)
    
    # Flatten nested columns
    df_risk['product_name'] = df_risk['products'].apply(lambda x: x['name'] if x else '')
    df_risk['sku'] = df_risk['products'].apply(lambda x: x['sku'] if x else '')
    df_risk['branch_name'] = df_risk['branches'].apply(lambda x: x['name'] if x else '')
    
    df_risk['expiry_date'] = pd.to_datetime(df_risk['expiry_date']).dt.date
    
    sort_by = st.selectbox("Sort by", ["risk_score desc", "expiry_date asc", "financial_value desc"])
    if sort_by == "risk_score desc":
        df_display = df_risk.sort_values('risk_score', ascending=False)
    elif sort_by == "expiry_date asc":
        df_display = df_risk.sort_values('expiry_date')
    else:
        df_display = df_risk.sort_values('financial_value', ascending=False)
    
    st.subheader("📋 Batch Risk Assessment")
    st.dataframe(df_display[['product_name','sku','batch','quantity','financial_value','expiry_date','days_to_expiry','risk_level']].rename(columns={
        'product_name':'Product','sku':'SKU','financial_value':'Financial Exposure (₦)','days_to_expiry':'Days Left'
    }))
    
    st.subheader("📌 FEFO Recommendation (Consumption Order)")
    fefo_df = df_risk.sort_values(['expiry_date', 'risk_score'], ascending=[True, False])
    for idx, row in fefo_df.head(20).iterrows():
        st.write(f"- **{row['product_name']}** (Batch `{row['batch']}`) – Expires **{row['expiry_date']}** – {row['risk_level']}")
    
    st.subheader("📊 Risk Distribution")
    risk_counts = df_risk['risk_level'].value_counts()
    st.bar_chart(risk_counts)
    
    with st.expander("ℹ️ How risk score is calculated"):
        st.markdown("""
        **Risk Score = (Expiry Score × 0.5) + (Financial Score × 0.3) + (Low Velocity Score × 0.2)**  
        - **Expiry Score** (0–100): ≤30d→100, 31–60d→90, 61–90d→75, 91–180d→40, >180d→10  
        - **Financial Score** (0–100): normalised quantity × cost  
        - **Low Velocity Score** (0–100): ≤0.1 units/day→90, 0.11–0.5→70, 0.51–2→40, >2→10  
        **Risk levels:** CRITICAL (≥80) → HIGH (60–79) → MODERATE (35–59) → LOW (<35)
        
        ⚠️ **Real‑world note:** Products with ≤90 days to expiry are considered write‑off risks and trigger alerts.
        """)

# ============================================================
# PAGE: TRANSFER SUGGESTIONS (cached aggregates)
# ============================================================
elif page == "Transfer Suggestions":
    st.header("🔄 Inter‑Branch Transfer Suggestions")
    st.markdown("""
    **Enterprise logic:** Automatically identifies surplus stock that can be moved to branches with deficit or high demand.
    - **Surplus** = days of inventory > 45 days OR quantity > (reorder_point + safety_stock)
    - **Deficit** = days of inventory < 7 days OR quantity < reorder_point
    - **Expiry risk** = batches expiring within 30 days with low local demand → transfer to high‑demand branch
    - **High‑value slow movers** = financial exposure > ₦100k and sales velocity < 0.5 units/day → consolidate
    """)
    all_branches = supabase.table("branches").select("id, name").execute().data
    if len(all_branches) < 2:
        st.info("Need at least two branches to suggest transfers.")
        st.stop()
    branch_map = {b['id']: b['name'] for b in all_branches}
    
    # Use cached aggregates
    agg = get_branch_product_aggregates()
    
    # Fetch velocities and reorder points from stock_limits
    limits_data = supabase.table("stock_limits").select("branch_id, product_id, avg_daily_demand, reorder_point, safety_stock").execute().data
    velocity = {(l['branch_id'], l['product_id']): l['avg_daily_demand'] for l in limits_data}
    reorder = {(l['branch_id'], l['product_id']): (l['reorder_point'], l['safety_stock']) for l in limits_data}
    
    suggestions = []
    # Surplus -> Deficit
    for (b_id, p_id), data in agg.items():
        qty = data['total_qty']
        vel = velocity.get((b_id, p_id), 0)
        rp, ss = reorder.get((b_id, p_id), (5, 3))
        days_inv = qty / vel if vel > 0 else 999
        is_surplus = (days_inv > 45) or (qty > (rp + ss + 10))
        if is_surplus:
            for other_b in all_branches:
                if other_b['id'] == b_id:
                    continue
                other_key = (other_b['id'], p_id)
                other_agg = agg.get(other_key, {'total_qty': 0})
                other_vel = velocity.get(other_key, 0)
                other_days = other_agg['total_qty'] / other_vel if other_vel > 0 else 0
                other_rp, other_ss = reorder.get(other_key, (5, 3))
                if other_days < 7 or other_agg['total_qty'] < other_rp:
                    transfer_qty = min(qty - (rp + ss), (other_rp + other_ss) - other_agg['total_qty'])
                    if transfer_qty > 0:
                        suggestions.append({
                            'from_branch': branch_map[b_id],
                            'to_branch': branch_map[other_b['id']],
                            'product_name': f"Product {p_id}",
                            'quantity': transfer_qty,
                            'reason': f"Surplus ({days_inv:.0f} days) → deficit ({other_days:.0f} days)",
                            'urgency': 'HIGH' if other_days < 3 else 'MEDIUM'
                        })
    # Expiry risk transfer (simplified: any batch ≤30 days with low local demand)
    for inv_item in supabase.table("inventory").select("*, products(name)").execute().data:
        expiry = inv_item.get('expiry_date')
        if not expiry:
            continue
        days_left = (datetime.strptime(expiry, '%Y-%m-%d').date() - date.today()).days
        if days_left <= 30:
            b_id = inv_item['branch_id']
            p_id = inv_item['product_id']
            vel_from = velocity.get((b_id, p_id), 0)
            if vel_from <= 0.5:
                best_target = None
                best_vel = vel_from
                for target in all_branches:
                    if target['id'] == b_id:
                        continue
                    vel_to = velocity.get((target['id'], p_id), 0)
                    if vel_to > best_vel:
                        best_vel = vel_to
                        best_target = target['id']
                if best_target and best_vel > vel_from + 0.2:
                    suggestions.append({
                        'from_branch': branch_map[b_id],
                        'to_branch': branch_map[best_target],
                        'product_name': inv_item['products']['name'] if inv_item['products'] else 'Unknown',
                        'quantity': inv_item['quantity'],
                        'reason': f"Expires in {days_left} days, low local demand ({vel_from:.1f} units/day). Transfer to {branch_map[best_target]} ({best_vel:.1f} units/day).",
                        'urgency': 'CRITICAL' if days_left <= 7 else 'HIGH'
                    })
    # High-value slow movers
    for (b_id, p_id), data in agg.items():
        if data['total_qty'] * data['cost'] > 100000 and velocity.get((b_id, p_id), 0) < 0.5:
            # pick a different branch to consolidate to
            target = all_branches[0]['id']
            if target == b_id and len(all_branches) > 1:
                target = all_branches[1]['id']
            if target != b_id:
                suggestions.append({
                    'from_branch': branch_map[b_id],
                    'to_branch': branch_map[target],
                    'product_name': f"Product {p_id}",
                    'quantity': data['total_qty'],
                    'reason': f"High-value slow mover (₦{data['total_qty']*data['cost']:,.0f}, {velocity.get((b_id, p_id),0):.1f} units/day). Consolidate.",
                    'urgency': 'MEDIUM'
                })
    # Deduplicate
    unique = []
    seen = set()
    for s in suggestions:
        key = (s['from_branch'], s['to_branch'], s['product_name'])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    if unique:
        df_sugg = pd.DataFrame(unique)
        urgency_order = {'CRITICAL':0, 'HIGH':1, 'MEDIUM':2}
        df_sugg['urgency_num'] = df_sugg['urgency'].map(urgency_order)
        df_sugg = df_sugg.sort_values('urgency_num')
        st.subheader("📋 Suggested Transfers")
        st.dataframe(df_sugg[['from_branch','to_branch','product_name','quantity','urgency','reason']])
        st.bar_chart(df_sugg['urgency'].value_counts())
    else:
        st.success("✅ No transfer suggestions at this time.")
    with st.expander("ℹ️ How suggestions are generated"):
        st.markdown("""
        - Surplus → Deficit: >45 days of stock or exceeds reorder point; another branch below reorder point.
        - Expiry risk transfer: Batch expiring in ≤30 days in a slow-selling branch → move to higher-demand branch.
        - High-value slow movers: >₦100k value and <0.5 units/day → consolidate.
        Sorted by urgency: CRITICAL → HIGH → MEDIUM.
        """)