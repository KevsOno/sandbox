import streamlit as st
import pandas as pd
from supabase import create_client, Client
from datetime import date, datetime, timedelta, timezone

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

# ---------- EMAIL LINK AUTO-MARK (fixed timestamp) ----------
params = st.query_params
if "alert_id" in params and "action" in params:
    alert_id = params["alert_id"]  # modern Streamlit returns string, not list
    supabase.table("alert_log").update({
        "action_taken": "Marked done via email link",
        "action_date": datetime.now(timezone.utc).isoformat()
    }).eq("id", alert_id).execute()
    st.success(f"✅ Alert #{alert_id} marked as done!")
    st.query_params.clear()
    st.rerun()

# ---------- BRANCH SELECTOR with pagination reset ----------
@st.cache_data(ttl=300)
def get_branches():
    return supabase.table("branches").select("id,name,code").execute().data

branches_data = get_branches()
branch_names = [b['name'] for b in branches_data]
branch_id_map = {b['name']: b['id'] for b in branches_data}

def reset_pagination():
    st.session_state.prod_page = 0
    st.session_state.inv_page = 0
    st.session_state.alert_page = 0
    st.session_state.limits_page = 0
    st.session_state.risk_page = 0

selected_branch_name = st.sidebar.selectbox(
    "Select Branch",
    ["All Branches"] + branch_names,
    on_change=reset_pagination
)
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
    """Chunked upload with partial‑failure protection."""
    for col, val in extra_columns.items():
        df[col] = val
    records = df.to_dict(orient="records")
    chunk_size = 500
    total_chunks = (len(records) + chunk_size - 1) // chunk_size
    i = 0  # ✅ initialised to avoid NameError on empty records
    try:
        for i in range(0, len(records), chunk_size):
            chunk_num = i // chunk_size + 1
            supabase.table(table_name).insert(records[i:i+chunk_size]).execute()
        return True, None
    except Exception as e:
        error_msg = f"Upload failed at chunk {chunk_num}/{total_chunks}. No data was committed for this chunk. Error: {e}"
        return False, error_msg

# ---------- PAGINATION COUNT CACHING (improved) ----------
@st.cache_data(ttl=60, show_spinner=False)
def get_cached_count(table_name, filter_col=None, filter_val=None):
    """Returns exact count, cached for 60 seconds."""
    query = supabase.table(table_name).select("*", head=True, count="exact")
    if filter_col and filter_val:
        query = query.eq(filter_col, filter_val)
    return query.execute().count

def invalidate_count_cache(table_name, filter_col=None, filter_val=None):
    """Force cache invalidation for a specific table/criteria."""
    # Build a dummy key – cache_data doesn't expose direct clear, so we rely on TTL.
    # For immediate invalidation, we can use a simple session state flag.
    # Simpler: just let TTL expire – acceptable because counts don't change that often.
    # For bulk uploads after, we can just rerun and the 60s TTL will refresh soon.
    pass

# ============================================================
# PAGE: DASHBOARD (RPC aggregates, now with alert limit)
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

    # Alert counts – cap to 1000 rows to avoid memory overload
    alert_query = supabase.table("alert_log").select("alert_type, action_taken")
    if branch_id:
        alert_query = alert_query.eq("branch_id", branch_id)
    alerts = alert_query.limit(1000).execute().data  # ✅ safety cap
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
# PAGE: BRANCHES (admin only, editable, no delete) – now uses chunked upload
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
                                get_branches.clear()
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
                    get_branches.clear()
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
            # Use same chunked helper as inventory/movements (consistent)
            records = df[['name','code','storekeeper_email','procurement_email','inventory_email','auditor_email','manager_email']].to_dict(orient="records")
            # For branches, we can still use the chunked helper but with a simple DF -> records
            success, err = upload_csv_to_table("branches", df[['name','code','storekeeper_email','procurement_email','inventory_email','auditor_email','manager_email']])
            if success:
                st.success("Branches uploaded!")
                get_branches.clear()
                st.rerun()
            else:
                st.error(err)

# ============================================================
# PAGE: PRODUCTS (explicit columns, cached count)
# ============================================================
elif page == "Products":
    st.header("📦 Products Master")
    PAGE_SIZE = 50
    if "prod_page" not in st.session_state:
        st.session_state.prod_page = 0
    offset = st.session_state.prod_page * PAGE_SIZE

    total = get_cached_count("products")
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE

    prods = supabase.table("products").select("id,sku,name,category,shelf_life_days,cost").range(offset, offset+PAGE_SIZE-1).execute().data
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
                # Count cache will refresh within 60s; fine.
                st.rerun()

# ============================================================
# PAGE: INVENTORY (uses view_inventory_list, explicit columns, cached count)
# ============================================================
elif page == "Inventory":
    st.header("📦 Current Inventory")
    PAGE_SIZE = 100
    if "inv_page" not in st.session_state:
        st.session_state.inv_page = 0
    offset = st.session_state.inv_page * PAGE_SIZE

    total = get_cached_count("inventory", filter_col="branch_id" if branch_id else None,
                             filter_val=branch_id if branch_id else None)
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE

    query = supabase.table("view_inventory_list").select("id,branch_id,branch_name,product_id,product_name,sku,cost,batch,quantity,expiry_date,storage_location")
    if branch_id:
        query = query.eq("branch_id", branch_id)
    inv_data = query.range(offset, offset+PAGE_SIZE-1).execute().data

    if inv_data:
        df_i = pd.DataFrame(inv_data)
        st.dataframe(df_i[['branch_name','product_name','sku','batch','quantity','expiry_date','storage_location']].rename(columns={
            'branch_name':'Branch','product_name':'Product'
        }))
    else:
        st.info("No inventory records.")

    col1, col2 = st.columns(2)
    if col1.button("Prev Inv", disabled=st.session_state.inv_page==0):
        st.session_state.inv_page -= 1
        st.rerun()
    if col2.button("Next Inv", disabled=st.session_state.inv_page>=total_pages-1):
        st.session_state.inv_page += 1
        st.rerun()
    st.caption(f"Page {st.session_state.inv_page+1} of {total_pages}")

# ============================================================
# PAGE: CSV UPLOAD (unchanged logic, uses safe upload helper)
# ============================================================
elif page == "CSV Upload":
    st.header("📁 Upload Inventory or Movement Data")
    upload_type = st.selectbox("Data Type", ["Inventory (current stock)", "Stock Movements (sales/restock)"])
    if upload_type == "Inventory (current stock)":
        st.markdown("""
        ### 📋 Required CSV Headers for Inventory
        Your CSV file **must** contain these exact column names:
        - `product_sku` – the SKU of the product (must already exist in the Products table)
        - `batch` – batch identifier (text, e.g., "BATCH-001")
        - `quantity` – integer (number of units)
        - `expiry_date` – date in YYYY-MM-DD format
        - `storage_location` – one of: `warehouse`, `shelf`, `cold_room`
        """)
        template_df = pd.DataFrame(columns=['product_sku','batch','quantity','expiry_date','storage_location'])
        template_df.loc[0] = ['SKU12345', 'BATCH-001', 100, '2026-12-31', 'warehouse']
        csv_template = template_df.to_csv(index=False)
        st.download_button("📥 Download Inventory CSV Template", csv_template, "inventory_template.csv", "text/csv")
    else:
        st.markdown("""
        ### 📋 Required CSV Headers for Stock Movements
        Your CSV file **must** contain these exact column names:
        - `product_sku` – the SKU of the product (must already exist in the Products table)
        - `quantity_change` – integer (positive for restock, negative for sales)
        - `movement_date` – date in YYYY-MM-DD format
        - `notes` (optional) – any additional text
        """)
        template_df = pd.DataFrame(columns=['product_sku','quantity_change','movement_date','notes'])
        template_df.loc[0] = ['SKU12345', -5, '2026-05-17', 'Daily sales']
        csv_template = template_df.to_csv(index=False)
        st.download_button("📥 Download Movements CSV Template", csv_template, "movements_template.csv", "text/csv")

    st.markdown("---")
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
                st.error(f"❌ SKUs not found in products table: {missing}. Please add them first.")
                st.stop()
            df['branch_id'] = selected_branch_id
            df['expiry_date'] = pd.to_datetime(df['expiry_date']).dt.date
            df = df[['branch_id','product_id','batch','quantity','expiry_date','storage_location']]
            if st.button("Upload Inventory"):
                success, err = upload_csv_to_table("inventory", df)
                if success:
                    st.success(f"Inventory uploaded for {selected_branch_label}!")
                    # Count cache will auto-refresh within 60s; fine.
                else:
                    st.error(err)
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
                st.error(f"❌ SKUs not found in products table: {missing}")
                st.stop()
            df['branch_id'] = selected_branch_id
            df['movement_date'] = pd.to_datetime(df['movement_date']).dt.date
            if 'notes' not in df.columns:
                df['notes'] = ""
            df = df[['branch_id','product_id','quantity_change','movement_date','notes']]
            if st.button("Upload Movements"):
                success, err = upload_csv_to_table("stock_movements", df)
                if success:
                    st.success(f"Movements uploaded for {selected_branch_label}!")
                else:
                    st.error(err)

# ============================================================
# PAGE: ALERTS & ADVISORIES (explicit columns, cached count)
# ============================================================
elif page == "Alerts & Advisories":
    st.header("🚨 Alerts & Advisories")
    PAGE_SIZE = 50
    if "alert_page" not in st.session_state:
        st.session_state.alert_page = 0
    offset = st.session_state.alert_page * PAGE_SIZE

    total = get_cached_count("alert_log", filter_col="branch_id" if branch_id else None,
                             filter_val=branch_id if branch_id else None)
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE

    query = supabase.table("alert_log").select("id,branch_id,product_id,batch,alert_type,details,action_taken,created_at,products(name),branches(name)").order("created_at", desc=True)
    if branch_id:
        query = query.eq("branch_id", branch_id)
    alerts = query.range(offset, offset+PAGE_SIZE-1).execute().data

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

    unactioned = [a for a in alerts if not a.get('action_taken')] if alerts else []
    if unactioned:
        st.subheader("Manual Action Update")
        alert_id = st.selectbox("Select Alert ID", [a['id'] for a in unactioned])
        action_text = st.text_input("Action Description")
        if st.button("Mark Done"):
            supabase.table("alert_log").update({
                "action_taken": action_text,
                "action_date": datetime.now(timezone.utc).isoformat()
            }).eq("id", alert_id).execute()
            st.success("Marked as done.")
            st.rerun()
    elif alerts:
        st.info("All displayed alerts have been actioned.")

# ============================================================
# PAGE: AI LIMITS (explicit columns, cached count)
# ============================================================
elif page == "AI Limits":
    st.header("📊 AI-Computed Stock Limits")
    st.caption("These limits are automatically updated daily based on sales velocity.")
    PAGE_SIZE = 50
    if "limits_page" not in st.session_state:
        st.session_state.limits_page = 0
    offset = st.session_state.limits_page * PAGE_SIZE

    total = get_cached_count("stock_limits", filter_col="branch_id" if branch_id else None,
                             filter_val=branch_id if branch_id else None)
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE

    query = supabase.table("stock_limits").select("id,branch_id,product_id,avg_daily_demand,safety_stock,reorder_point,max_stock,calculated_at,products(name),branches(name)")
    if branch_id:
        query = query.eq("branch_id", branch_id)
    limits = query.range(offset, offset+PAGE_SIZE-1).execute().data

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
# PAGE: RISK & FEFO (uses view_risk_list, explicit columns, cached count)
# ============================================================
elif page == "Risk & FEFO":
    st.header("⚠️ Risk Scoring & FEFO Recommendations")
    st.markdown("""
    **FEFO** = *First Expired, First Out* – we recommend consuming batches with the earliest expiry date first.  
    **Risk Score** combines expiry proximity (now with 90-day write‑off threshold), financial exposure, and sales velocity.  
    **Risk Levels:** LOW 🟢 → MODERATE 🟡 → HIGH 🟠 → CRITICAL 🔴
    """)

    PAGE_SIZE = 100
    if "risk_page" not in st.session_state:
        st.session_state.risk_page = 0
    offset = st.session_state.risk_page * PAGE_SIZE

    total = get_cached_count("product_risk_scores", filter_col="branch_id" if branch_id else None,
                             filter_val=branch_id if branch_id else None)
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE

    sort_by = st.selectbox("Sort by", ["risk_score desc", "expiry_date asc", "financial_value desc"])

    query = supabase.table("view_risk_list").select("id,branch_id,branch_name,product_id,product_name,sku,batch,quantity,financial_value,expiry_date,days_to_expiry,risk_score,risk_level")
    if branch_id:
        query = query.eq("branch_id", branch_id)

    if sort_by == "risk_score desc":
        query = query.order("risk_score", desc=True)
    elif sort_by == "expiry_date asc":
        query = query.order("expiry_date", desc=False)
    else:
        query = query.order("financial_value", desc=True)

    risk_scores = query.range(offset, offset+PAGE_SIZE-1).execute().data

    if not risk_scores:
        st.info("No risk scores available. Run the daily maintenance function first.")
        st.stop()

    df_risk = pd.DataFrame(risk_scores)
    df_risk['expiry_date'] = pd.to_datetime(df_risk['expiry_date']).dt.date

    st.subheader("📋 Batch Risk Assessment")
    st.dataframe(df_risk[['product_name','sku','batch','quantity','financial_value','expiry_date','days_to_expiry','risk_level']].rename(columns={
        'product_name':'Product','sku':'SKU','financial_value':'Financial Exposure (₦)','days_to_expiry':'Days Left'
    }))

    col1, col2 = st.columns(2)
    if col1.button("Prev Risk", disabled=st.session_state.risk_page==0):
        st.session_state.risk_page -= 1
        st.rerun()
    if col2.button("Next Risk", disabled=st.session_state.risk_page>=total_pages-1):
        st.session_state.risk_page += 1
        st.rerun()
    st.caption(f"Page {st.session_state.risk_page+1} of {total_pages}")

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
# PAGE: TRANSFER SUGGESTIONS (database view, defensive)
# ============================================================
elif page == "Transfer Suggestions":
    st.header("🔄 Inter‑Branch Transfer Suggestions")
    st.markdown("""
    **Optimised suggestions** – computed entirely inside the database for speed and scalability.
    - **Surplus → Deficit:** Branch has more than reorder point + safety stock + 5 units; another branch is below reorder point.
    - **Urgency:** CRITICAL if deficit is high, HIGH if source branch has low sales velocity, else MEDIUM.
    - No client‑side memory overhead – only final suggestions are fetched.
    """)
    try:
        query = supabase.table("view_transfer_suggestions").select("*")
        if branch_id:
            query = query.eq("from_branch_id", branch_id)
        res = query.execute()
        suggestions = res.data
    except Exception as e:
        st.error("⚠️ Unable to fetch transfer suggestions. Please contact your administrator.")
        st.stop()
    if isinstance(suggestions, list) and len(suggestions) > 0:
        df_sugg = pd.DataFrame(suggestions)
        st.subheader("📋 Suggested Transfers")
        st.dataframe(df_sugg[['from_branch','to_branch','product_name','sku','quantity','urgency','reason']])
        st.subheader("📊 Urgency Breakdown")
        st.bar_chart(df_sugg['urgency'].value_counts())
    else:
        st.success("✅ No transfer suggestions at this time. Inventory appears well balanced.")
    with st.expander("ℹ️ How suggestions are generated"):
        st.markdown("""
        - A **surplus** branch has `total_qty > (reorder_point + safety_stock + 5)`.
        - A **deficit** branch has `total_qty < reorder_point`.
        - Transfer quantity is the smaller of surplus excess and deficit need.
        - **Urgency:**  
          - `CRITICAL` if the deficit branch needs less than 5 units to restock.  
          - `HIGH` if the surplus branch has very low daily demand (<0.5 units/day).  
          - `MEDIUM` otherwise.
        - All calculations run inside PostgreSQL using indexed joins – no client‑side processing.
        """)