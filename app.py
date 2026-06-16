import streamlit as st
import pandas as pd
from supabase import create_client, Client
from datetime import date, datetime, timedelta, timezone
import re
from functools import wraps
import hashlib
import json

# ---------- CONFIG ----------
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]

@st.cache_resource
def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)

supabase = get_supabase()

# ---------- CACHE MANAGEMENT ----------
class CacheManager:
    """Centralized cache management with invalidation"""
    _cache_keys = set()
    
    @staticmethod
    def invalidate_all():
        """Invalidate all cached functions"""
        for key in list(CacheManager._cache_keys):
            try:
                st.cache_data.clear()
            except:
                pass
        CacheManager._cache_keys.clear()
    
    @staticmethod
    def register(key):
        CacheManager._cache_keys.add(key)

def cached_with_invalidation(ttl=300, key_prefix=""):
    """Decorator for cached functions with invalidation tracking"""
    def decorator(func):
        @st.cache_data(ttl=ttl, show_spinner=False)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        # Register the function for invalidation
        func_name = key_prefix or func.__name__
        CacheManager.register(func_name)
        
        @wraps(func)
        def wrapped(*args, **kwargs):
            return wrapper(*args, **kwargs)
        return wrapped
    return decorator

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
    alert_id = params["alert_id"]
    supabase.table("alert_log").update({
        "action_taken": "Marked done via email link",
        "action_date": datetime.now(timezone.utc).isoformat()
    }).eq("id", alert_id).execute()
    st.success(f"✅ Alert #{alert_id} marked as done!")
    st.query_params.clear()
    st.rerun()

# ---------- BRANCH SELECTOR ----------
@cached_with_invalidation(ttl=3600, key_prefix="branches")
def get_branches():
    """Get branches with efficient single query"""
    return supabase.table("branches").select("id,name,code").execute().data

@cached_with_invalidation(ttl=3600, key_prefix="branch_maps")
def get_branch_maps():
    """Pre-compute branch lookup maps to avoid repeated lookups"""
    branches = get_branches()
    return {
        'id_to_name': {b['id']: b['name'] for b in branches},
        'name_to_id': {b['name']: b['id'] for b in branches},
        'id_to_code': {b['id']: b['code'] for b in branches}
    }

branches_data = get_branches()
branch_maps = get_branch_maps()
branch_names = [b['name'] for b in branches_data]

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
branch_id = None if selected_branch_name == "All Branches" else branch_maps['name_to_id'].get(selected_branch_name)

# ---------- NAVIGATION ----------
if st.session_state.user_role == "admin":
    pages = ["Dashboard", "Products & Inventory", "Branches", "CSV Upload", 
             "Alerts & Advisories", "Stock & Demand Limits", "Risk & FEFO", "Transfer Suggestions"]
else:
    pages = ["Dashboard", "Products & Inventory", "CSV Upload", 
             "Alerts & Advisories", "Stock & Demand Limits", "Risk & FEFO", "Transfer Suggestions"]

page = st.sidebar.radio("Go to", pages)

# ---------- HELPERS ----------
def validate_csv_columns(df, required_cols, label="CSV"):
    """Validate CSV has required columns with better error messages"""
    missing = required_cols - set(df.columns)
    if missing:
        return False, f"❌ Missing columns in {label}: {', '.join(missing)}"
    return True, ""

def validate_sku_format(sku):
    """Validate SKU format - alphanumeric, underscores, hyphens only"""
    if not sku or not isinstance(sku, str):
        return False
    return bool(re.match(r'^[A-Za-z0-9_\-\.]+$', sku))

def validate_expiry_date(expiry_date):
    """Validate expiry date is in the future"""
    if expiry_date is None:
        return True
    if isinstance(expiry_date, str):
        try:
            expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d').date()
        except:
            return False
    today = date.today()
    return expiry_date >= today

def upload_with_transaction(table_name, records, batch_size=500):
    """Upload with transaction-like behavior"""
    if not records:
        return True, None, 0
    
    total_records = len(records)
    successful = 0
    
    for i in range(0, total_records, batch_size):
        batch = records[i:i+batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (total_records + batch_size - 1) // batch_size
        
        try:
            batch_clean = []
            for rec in batch:
                rec_clean = {}
                for k, v in rec.items():
                    if isinstance(v, (date, datetime)):
                        rec_clean[k] = v.isoformat()
                    elif isinstance(v, pd.Timestamp):
                        rec_clean[k] = v.isoformat()
                    else:
                        rec_clean[k] = v
                batch_clean.append(rec_clean)
            
            supabase.table(table_name).insert(batch_clean).execute()
            successful += len(batch)
        except Exception as e:
            return False, f"Upload failed at batch {batch_num}/{total_batches}. Error: {str(e)}", successful
    
    return True, None, successful

def bulk_upsert_products(products_data, batch_size=200):
    """Upsert products with SKU validation and uniqueness check"""
    if not products_data:
        return True, None, 0, 0
    
    invalid_skus = []
    for p in products_data:
        if not validate_sku_format(p.get('sku', '')):
            invalid_skus.append(p.get('sku', 'unknown'))
    
    if invalid_skus:
        return False, f"Invalid SKU format in: {', '.join(invalid_skus[:10])}", 0, 0
    
    sku_map = {}
    for p in products_data:
        sku = p['sku']
        if sku not in sku_map:
            sku_map[sku] = p
        else:
            existing = sku_map[sku]
            for key, value in p.items():
                if key not in existing or existing[key] is None:
                    existing[key] = value
    
    unique_products = list(sku_map.values())
    skus = [p['sku'] for p in unique_products]
    existing_skus = get_existing_skus(skus)
    
    created_count = 0
    updated_count = 0
    
    for i in range(0, len(unique_products), batch_size):
        batch = unique_products[i:i+batch_size]
        for product in batch:
            sku = product['sku']
            if sku in existing_skus:
                try:
                    product_clean = {k: v for k, v in product.items() if k != 'id'}
                    supabase.table("products").update(product_clean).eq("sku", sku).execute()
                    updated_count += 1
                except Exception as e:
                    return False, f"Update failed for SKU {sku}: {str(e)}", created_count, updated_count
            else:
                try:
                    product_clean = {k: v for k, v in product.items() if k != 'id'}
                    supabase.table("products").insert(product_clean).execute()
                    created_count += 1
                except Exception as e:
                    return False, f"Insert failed for SKU {sku}: {str(e)}", created_count, updated_count
    
    return True, None, created_count, updated_count

@cached_with_invalidation(ttl=300, key_prefix="existing_skus")
def get_existing_skus(sku_list=None):
    """Get existing SKUs from products table with caching"""
    query = supabase.table("products").select("sku")
    if sku_list:
        all_skus = set()
        for i in range(0, len(sku_list), 500):
            chunk = sku_list[i:i+500]
            result = query.in_("sku", chunk).execute()
            all_skus.update([r['sku'] for r in result.data])
        return all_skus
    else:
        all_skus = set()
        offset = 0
        while True:
            result = query.range(offset, offset+1000).execute()
            if not result.data:
                break
            all_skus.update([r['sku'] for r in result.data])
            offset += 1000
        return all_skus

@cached_with_invalidation(ttl=60, key_prefix="sku_to_id")
def chunked_sku_lookup(skus, chunk_size=200):
    """Efficient SKU to ID lookup with caching"""
    if not skus:
        return {}
    
    sku_to_id = {}
    for i in range(0, len(skus), chunk_size):
        chunk = skus[i:i+chunk_size]
        products_data = supabase.table("products").select("id, sku").in_("sku", chunk).execute().data
        for p in products_data:
            sku_to_id[p['sku']] = p['id']
    return sku_to_id

def ensure_products_exist(skus, default_cost=0.0, default_shelf_life=90):
    """Ensure products exist, with better error handling and validation"""
    if not skus:
        return {}
    
    sku_to_id = chunked_sku_lookup(skus)
    missing = [sku for sku in skus if sku not in sku_to_id]
    
    if missing:
        invalid_skus = [sku for sku in missing if not validate_sku_format(sku)]
        if invalid_skus:
            st.error(f"❌ Invalid SKU format in: {', '.join(invalid_skus[:10])}")
            return {}
        
        new_products = []
        for sku in missing:
            new_products.append({
                "sku": sku,
                "name": f"Auto-created: {sku}",
                "category": "Auto-created",
                "shelf_life_days": default_shelf_life,
                "cost": default_cost
            })
        
        success, error, created, updated = bulk_upsert_products(new_products)
        if not success:
            st.error(f"❌ Failed to create products: {error}")
            return {}
        
        CacheManager.invalidate_all()
        sku_to_id.update(chunked_sku_lookup(missing))
        st.warning(f"⚠️ Auto-created {len(missing)} missing product(s) with default values. Please review and update them later.")
    
    return sku_to_id

@cached_with_invalidation(ttl=60, key_prefix="count")
def get_cached_count(table_or_view, filter_col=None, filter_val=None):
    """Get count with better caching and pagination support"""
    query = supabase.table(table_or_view).select("*", head=True, count="exact")
    if filter_col and filter_val:
        query = query.eq(filter_col, filter_val)
    return query.execute().count

def search_products(search_term, branch_id=None, limit=100):
    """Search products by SKU or name with inventory info"""
    search_term = search_term.strip()
    if not search_term:
        return []
    
    # First, find matching products
    product_query = supabase.table("products").select(
        "id,sku,name,category,shelf_life_days,cost"
    ).or_(
        f"sku.ilike.%{search_term}%,name.ilike.%{search_term}%"
    ).limit(limit)
    
    products = product_query.execute().data
    
    if not products:
        return []
    
    # Get inventory for these products if branch is selected
    product_ids = [p['id'] for p in products]
    
    if branch_id:
        inventory_query = supabase.table("view_inventory_list").select(
            "product_id,batch,quantity,expiry_date,storage_location"
        ).in_("product_id", product_ids).eq("branch_id", branch_id)
        inventory = inventory_query.execute().data
        
        # Group inventory by product_id
        inv_by_product = {}
        for inv in inventory:
            prod_id = inv['product_id']
            if prod_id not in inv_by_product:
                inv_by_product[prod_id] = []
            inv_by_product[prod_id].append(inv)
        
        # Add inventory to products
        for product in products:
            product['inventory'] = inv_by_product.get(product['id'], [])
    else:
        # Show all branches inventory
        for product in products:
            inventory_query = supabase.table("view_inventory_list").select(
                "branch_name,batch,quantity,expiry_date,storage_location"
            ).eq("product_id", product['id'])
            product['inventory'] = inventory_query.execute().data
    
    return products

def search_inventory(search_term, branch_id=None, limit=100):
    """Search inventory by product SKU, name, or batch"""
    search_term = search_term.strip()
    if not search_term:
        return []
    
    query = supabase.table("view_inventory_list").select(
        "id,branch_id,branch_name,product_id,product_name,sku,batch,quantity,expiry_date,storage_location,cost"
    )
    
    if branch_id:
        query = query.eq("branch_id", branch_id)
    
    # Search across multiple fields
    query = query.or_(
        f"sku.ilike.%{search_term}%,product_name.ilike.%{search_term}%,batch.ilike.%{search_term}%"
    ).limit(limit)
    
    return query.execute().data

# ============================================================
# PAGE: DASHBOARD
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
    col2.metric("Waste Risk (next 90d)", f"₦{waste_val:,.0f}")

    alert_query = supabase.table("alert_log").select("alert_type, action_taken")
    if branch_id:
        alert_query = alert_query.eq("branch_id", branch_id)
    alerts = alert_query.limit(1000).execute().data
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
# PAGE: PRODUCTS & INVENTORY (MERGED WITH SEARCH)
# ============================================================
elif page == "Products & Inventory":
    st.header("📦 Products & Inventory Management")
    
    # Search and filter section
    st.subheader("🔍 Search Products & Inventory")
    col1, col2 = st.columns([3, 1])
    with col1:
        search_term = st.text_input("Search by SKU, Product Name, or Batch", 
                                   placeholder="e.g., SKU123, Paracetamol, BATCH-001",
                                   key="product_search")
    with col2:
        search_type = st.selectbox("Search in", ["Products", "Inventory"], key="search_type")
    
    # Action buttons for quick operations
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("➕ Add Product", use_container_width=True):
            st.session_state.show_add_product = True
    with col2:
        if st.button("📊 View All Products", use_container_width=True):
            st.session_state.show_all_products = True
            st.session_state.show_inventory = False
    with col3:
        if st.button("📦 View All Inventory", use_container_width=True):
            st.session_state.show_inventory = True
            st.session_state.show_all_products = False
    with col4:
        if st.button("🔄 Refresh Data", use_container_width=True):
            CacheManager.invalidate_all()
            st.rerun()
    
    st.divider()
    
    # Initialize session state for views
    if "show_add_product" not in st.session_state:
        st.session_state.show_add_product = False
    if "show_all_products" not in st.session_state:
        st.session_state.show_all_products = True
    if "show_inventory" not in st.session_state:
        st.session_state.show_inventory = False
    
    # Handle add product form
    if st.session_state.show_add_product:
        with st.expander("➕ Add New Product", expanded=True):
            with st.form("add_product_form"):
                col1, col2 = st.columns(2)
                with col1:
                    new_sku = st.text_input("SKU*", help="Alphanumeric, underscores, hyphens, or periods")
                    new_name = st.text_input("Product Name*")
                with col2:
                    new_category = st.text_input("Category")
                    new_shelf_life = st.number_input("Shelf Life (days)", min_value=1, value=90)
                    new_cost = st.number_input("Unit Cost (₦)", min_value=0.0, value=0.0, format="%.2f")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("✅ Add Product", use_container_width=True):
                        if not new_sku or not new_name:
                            st.error("SKU and name are required.")
                        elif not validate_sku_format(new_sku):
                            st.error("Invalid SKU format. Use alphanumeric, underscores, hyphens, or periods.")
                        else:
                            try:
                                supabase.table("products").insert({
                                    "sku": new_sku,
                                    "name": new_name,
                                    "category": new_category or None,
                                    "shelf_life_days": new_shelf_life,
                                    "cost": new_cost
                                }).execute()
                                st.success(f"✅ Product '{new_name}' added successfully!")
                                CacheManager.invalidate_all()
                                st.session_state.show_add_product = False
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to add product: {e}")
                with col2:
                    if st.form_submit_button("❌ Cancel", use_container_width=True):
                        st.session_state.show_add_product = False
                        st.rerun()
    
    # Search results or default views
    if search_term:
        if search_type == "Products":
            results = search_products(search_term, branch_id)
            if results:
                st.success(f"Found {len(results)} products matching '{search_term}'")
                for product in results:
                    with st.expander(f"📦 {product['name']} ({product['sku']})"):
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Category", product.get('category', 'N/A'))
                            st.metric("Shelf Life", f"{product.get('shelf_life_days', 'N/A')} days")
                        with col2:
                            st.metric("Cost", f"₦{product.get('cost', 0):,.2f}")
                            if product.get('inventory'):
                                total_qty = sum(inv['quantity'] for inv in product['inventory'])
                                st.metric("Total Stock", total_qty)
                        with col3:
                            if st.button(f"✏️ Edit {product['sku']}", key=f"edit_{product['id']}"):
                                st.session_state.edit_product = product
                        
                        # Show inventory for this product
                        if product.get('inventory'):
                            st.subheader("Inventory Locations")
                            inv_df = pd.DataFrame(product['inventory'])
                            if 'branch_name' in inv_df.columns:
                                display_cols = ['branch_name', 'batch', 'quantity', 'expiry_date', 'storage_location']
                            else:
                                display_cols = ['batch', 'quantity', 'expiry_date', 'storage_location']
                            st.dataframe(inv_df[display_cols])
            else:
                st.info(f"No products found matching '{search_term}'")
        
        else:  # Search inventory
            results = search_inventory(search_term, branch_id)
            if results:
                st.success(f"Found {len(results)} inventory records matching '{search_term}'")
                df_results = pd.DataFrame(results)
                df_results['expiry_display'] = df_results['expiry_date'].apply(lambda x: x if pd.notna(x) else "No expiry")
                st.dataframe(df_results[['branch_name', 'product_name', 'sku', 'batch', 'quantity', 'expiry_display', 'storage_location']])
                
                # Quick action: Adjust inventory
                st.subheader("⚡ Quick Inventory Adjustment")
                selected_item = st.selectbox("Select inventory item to adjust", 
                                           [f"{row['sku']} - {row['batch']}" for row in results])
                if selected_item:
                    selected_row = results[[f"{row['sku']} - {row['batch']}" == selected_item for row in results].index(True)]
                    new_qty = st.number_input("New Quantity", min_value=0, value=selected_row['quantity'])
                    if st.button("Update Quantity"):
                        try:
                            supabase.table("inventory").update({"quantity": new_qty}).eq("id", selected_row['id']).execute()
                            st.success("✅ Inventory updated!")
                            CacheManager.invalidate_all()
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to update: {e}")
            else:
                st.info(f"No inventory records found matching '{search_term}'")
    
    else:
        # Default view: Show products or inventory based on session state
        if st.session_state.show_inventory:
            st.subheader("📊 All Inventory")
            PAGE_SIZE = 50
            if "inv_page" not in st.session_state:
                st.session_state.inv_page = 0
            offset = st.session_state.inv_page * PAGE_SIZE
            
            total = get_cached_count("view_inventory_list", filter_col="branch_id" if branch_id else None,
                                   filter_val=branch_id if branch_id else None)
            total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
            
            query = supabase.table("view_inventory_list").select(
                "id,branch_id,branch_name,product_id,product_name,sku,cost,batch,quantity,expiry_date,storage_location"
            )
            if branch_id:
                query = query.eq("branch_id", branch_id)
            inv_data = query.range(offset, offset+PAGE_SIZE-1).execute().data
            
            if inv_data:
                df_i = pd.DataFrame(inv_data)
                df_i['expiry_display'] = df_i['expiry_date'].apply(lambda x: x if pd.notna(x) else "No expiry")
                st.dataframe(df_i[['branch_name','product_name','sku','batch','quantity','expiry_display','storage_location']].rename(columns={
                    'branch_name':'Branch','product_name':'Product','expiry_display':'Expiry Date'
                }))
                
                col1, col2 = st.columns(2)
                if col1.button("⬅️ Prev", disabled=st.session_state.inv_page==0):
                    st.session_state.inv_page -= 1
                    st.rerun()
                if col2.button("Next ➡️", disabled=st.session_state.inv_page>=total_pages-1):
                    st.session_state.inv_page += 1
                    st.rerun()
                st.caption(f"Page {st.session_state.inv_page+1} of {total_pages}")
            else:
                st.info("No inventory records found.")
        
        else:  # Show products
            st.subheader("📋 All Products")
            PAGE_SIZE = 50
            if "prod_page" not in st.session_state:
                st.session_state.prod_page = 0
            offset = st.session_state.prod_page * PAGE_SIZE
            
            total = get_cached_count("products")
            total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
            
            prods = supabase.table("products").select("id,sku,name,category,shelf_life_days,cost").range(offset, offset+PAGE_SIZE-1).execute().data
            
            if prods:
                # Add edit functionality directly in the dataframe display
                df_p = pd.DataFrame(prods)
                st.dataframe(df_p[['sku','name','category','shelf_life_days','cost']])
                
                col1, col2 = st.columns(2)
                if col1.button("⬅️ Prev", disabled=st.session_state.prod_page==0):
                    st.session_state.prod_page -= 1
                    st.rerun()
                if col2.button("Next ➡️", disabled=st.session_state.prod_page>=total_pages-1):
                    st.session_state.prod_page += 1
                    st.rerun()
                st.caption(f"Page {st.session_state.prod_page+1} of {total_pages}")
                
                # Edit product section
                st.subheader("✏️ Edit Product")
                edit_sku = st.selectbox("Select product to edit", [p['sku'] for p in prods])
                if edit_sku:
                    product = next(p for p in prods if p['sku'] == edit_sku)
                    with st.form("edit_product_form"):
                        col1, col2 = st.columns(2)
                        with col1:
                            new_name = st.text_input("Product Name", value=product['name'])
                            new_category = st.text_input("Category", value=product.get('category', ''))
                        with col2:
                            new_shelf_life = st.number_input("Shelf Life (days)", min_value=1, value=product['shelf_life_days'])
                            new_cost = st.number_input("Unit Cost (₦)", min_value=0.0, value=float(product['cost']), format="%.2f")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.form_submit_button("💾 Save Changes", use_container_width=True):
                                try:
                                    supabase.table("products").update({
                                        "name": new_name,
                                        "category": new_category or None,
                                        "shelf_life_days": new_shelf_life,
                                        "cost": new_cost
                                    }).eq("id", product['id']).execute()
                                    st.success("✅ Product updated successfully!")
                                    CacheManager.invalidate_all()
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Failed to update: {e}")
                        with col2:
                            if st.form_submit_button("🗑️ Delete Product", use_container_width=True):
                                if st.warning("Are you sure? This will delete the product and all associated inventory."):
                                    try:
                                        # Delete inventory first
                                        supabase.table("inventory").delete().eq("product_id", product['id']).execute()
                                        # Then delete product
                                        supabase.table("products").delete().eq("id", product['id']).execute()
                                        st.success("✅ Product and associated inventory deleted.")
                                        CacheManager.invalidate_all()
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"Failed to delete: {e}")
            else:
                st.info("No products found. Add your first product above!")

# ============================================================
# PAGE: BRANCHES (admin only)
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
                                CacheManager.invalidate_all()
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
                    CacheManager.invalidate_all()
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")
    st.markdown("---")
    st.subheader("📁 Bulk Upload Branches CSV")
    st.markdown("**CSV columns:** `name`, `code`, `storekeeper_email`, `procurement_email`, `inventory_email`, `auditor_email`, `manager_email`")
    st.info("📌 Recommended max rows: 500. Upload is chunked (500 rows per batch).")
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
            success, err, count = upload_with_transaction("branches", records)
            if success:
                st.success(f"Branches uploaded! {count} rows processed.")
                CacheManager.invalidate_all()
                st.rerun()
            else:
                st.error(err)

# ============================================================
# PAGE: CSV UPLOAD (with search for products)
# ============================================================
elif page == "CSV Upload":
    st.header("📁 Upload Inventory or Movement Data")
    
    # Quick search for products before upload
    with st.expander("🔍 Search Products Before Upload", expanded=False):
        search_term = st.text_input("Search products", placeholder="SKU or product name", key="upload_search")
        if search_term:
            results = search_products(search_term, branch_id, limit=20)
            if results:
                st.dataframe(pd.DataFrame(results)[['sku', 'name', 'category', 'cost']])
            else:
                st.info("No products found")
    
    upload_type = st.selectbox("Data Type", ["Inventory (current stock)", "Stock Movements (sales/restock)"])

    if upload_type == "Inventory (current stock)":
        st.markdown("""
        ### 📋 Required CSV Headers for Inventory
        - `product_sku` – SKU (will auto‑create product if missing)
        - `batch` – batch identifier
        - `quantity` – integer
        - `expiry_date` – YYYY-MM-DD (leave blank for non‑expiring items)
        - `storage_location` – warehouse / shelf / cold_room

        ⚠️ **Recommended max rows:** 5,000 per upload (chunked automatically).  
        ✅ **Missing SKUs will be auto‑created** as placeholder products (you can edit them later).  
        ✅ **Expiry dates must be in the future** (or blank for non-expiring items).
        """)
        template_df = pd.DataFrame(columns=['product_sku','batch','quantity','expiry_date','storage_location'])
        template_df.loc[0] = ['SKU12345', 'BATCH-001', 100, '2026-12-31', 'warehouse']
        csv_template = template_df.to_csv(index=False)
        st.download_button("📥 Download Inventory CSV Template", csv_template, "inventory_template.csv", "text/csv")
    else:
        st.markdown("""
        ### 📋 Required CSV Headers for Stock Movements
        - `product_sku` – SKU (must exist in Products table)
        - `quantity_change` – integer (negative = sale, positive = restock)
        - `movement_date` – YYYY-MM-DD
        - `notes` – optional text

        ⚠️ **Recommended max rows:** 10,000 per upload (chunked automatically).  
        ❗ Movements require that the SKU already exists in products (no auto‑creation).
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

            df['product_sku'] = df['product_sku'].astype(str).str.strip()
            df = df[df['product_sku'].notna() & (df['product_sku'] != '')]
            df['quantity'] = pd.to_numeric(df['quantity'], errors='coerce').fillna(0).astype(int).clip(lower=0)
            
            df['expiry_date_raw'] = df['expiry_date']
            df['expiry_date'] = pd.to_datetime(df['expiry_date'], errors='coerce').dt.date
            
            invalid_expiry = df[df['expiry_date'].notna() & (df['expiry_date'] < date.today())]
            if not invalid_expiry.empty:
                st.error(f"❌ {len(invalid_expiry)} rows have expiry dates in the past. Please correct them.")
                st.dataframe(invalid_expiry[['product_sku', 'batch', 'expiry_date_raw']])
                st.stop()
            
            df['expiry_date'] = df['expiry_date'].where(pd.notna(df['expiry_date']), None)

            skus = df['product_sku'].unique().tolist()
            sku_to_id = ensure_products_exist(skus)
            if not sku_to_id:
                st.error("❌ Failed to create or find products. Please check SKU formats.")
                st.stop()
                
            df['product_id'] = df['product_sku'].map(sku_to_id)
            if df['product_id'].isna().any():
                missing_after = df[df['product_id'].isna()]['product_sku'].unique()
                st.error(f"❌ SKUs could not be matched or created: {missing_after}. Please check product master.")
                st.stop()

            df['branch_id'] = selected_branch_id
            df = df[['branch_id','product_id','batch','quantity','expiry_date','storage_location']]

            if st.button("Upload Inventory"):
                records = df.to_dict(orient="records")
                success, err, count = upload_with_transaction("inventory", records)
                if success:
                    st.success(f"Inventory uploaded for {selected_branch_label}! {count} rows processed.")
                    CacheManager.invalidate_all()
                else:
                    st.error(err)

        else:  # movements
            required_cols = {'product_sku','quantity_change','movement_date'}
            is_valid, msg = validate_csv_columns(df, required_cols, "movements CSV")
            if not is_valid:
                st.error(msg)
                st.stop()

            df['product_sku'] = df['product_sku'].astype(str).str.strip()
            df = df[df['product_sku'].notna() & (df['product_sku'] != '')]
            df['quantity_change'] = pd.to_numeric(df['quantity_change'], errors='coerce').fillna(0).astype(int)

            skus = df['product_sku'].unique().tolist()
            sku_to_id = chunked_sku_lookup(skus)
            df['product_id'] = df['product_sku'].map(sku_to_id)
            missing = df[df['product_id'].isna()]['product_sku'].unique()
            if len(missing) > 0:
                st.error(f"❌ SKUs not found in products table: {missing}. Please add them first (or use Inventory upload to auto‑create).")
                st.stop()

            df['branch_id'] = selected_branch_id
            df['movement_date'] = pd.to_datetime(df['movement_date']).dt.date
            if 'notes' not in df.columns:
                df['notes'] = ""
            df = df[['branch_id','product_id','quantity_change','movement_date','notes']]

            if st.button("Upload Movements"):
                records = df.to_dict(orient="records")
                success, err, count = upload_with_transaction("stock_movements", records)
                if success:
                    st.success(f"Movements uploaded for {selected_branch_label}! {count} rows processed.")
                    CacheManager.invalidate_all()
                else:
                    st.error(err)

# ============================================================
# PAGE: ALERTS & ADVISORIES
# ============================================================
elif page == "Alerts & Advisories":
    st.header("🚨 Alerts & Advisories")
    st.markdown("""
    **Alert Thresholds:**
    - 🔴 **CRITICAL:** Expiry ≤ 90 days (3 months) - Immediate action required
    - 🟠 **HIGH:** Expiry 91-120 days (4 months) - Plan for consumption or transfer
    - 🟡 **MEDIUM:** Expiry 121-180 days (6 months) - Monitor closely
    """)
    
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
            CacheManager.invalidate_all()
            st.rerun()
    elif alerts:
        st.info("All displayed alerts have been actioned.")

# ============================================================
# PAGE: STOCK & DEMAND LIMITS
# ============================================================
elif page == "Stock & Demand Limits":
    st.header("📊 Stock & Demand Limits")
    st.caption("These limits are automatically recomputed daily based on sales velocity (not AI / machine learning).")
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
        st.info("No stock limits computed yet. Ensure the daily maintenance function has run.")

    col1, col2 = st.columns(2)
    if col1.button("Prev Limits", disabled=st.session_state.limits_page==0):
        st.session_state.limits_page -= 1
        st.rerun()
    if col2.button("Next Limits", disabled=st.session_state.limits_page>=total_pages-1):
        st.session_state.limits_page += 1
        st.rerun()
    st.caption(f"Page {st.session_state.limits_page+1} of {total_pages}")

# ============================================================
# PAGE: RISK & FEFO
# ============================================================
elif page == "Risk & FEFO":
    st.header("⚠️ Risk Scoring & FEFO Recommendations")
    st.markdown("""
    **FEFO** = *First Expired, First Out* – we recommend consuming batches with the earliest expiry date first.  
    **Risk Score** combines expiry proximity (with 90-day write‑off threshold), financial exposure, and sales velocity.  
    **Risk Levels:** LOW 🟢 → MODERATE 🟡 → HIGH 🟠 → CRITICAL 🔴
    
    **Critical Threshold:** Products with **≤90 days (3 months)** to expiry are considered high risk and require immediate attention.
    """)

    PAGE_SIZE = 100
    if "risk_page" not in st.session_state:
        st.session_state.risk_page = 0
    offset = st.session_state.risk_page * PAGE_SIZE

    total = get_cached_count("product_risk_scores", filter_col="branch_id" if branch_id else None,
                             filter_val=branch_id if branch_id else None)
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE

    sort_display = st.selectbox("Sort by", [
        "Highest risk first",
        "Earliest expiry first",
        "Highest financial value first"
    ])
    if sort_display == "Highest risk first":
        order_col = "risk_score"
        order_desc = True
    elif sort_display == "Earliest expiry first":
        order_col = "expiry_date"
        order_desc = False
    else:
        order_col = "financial_value"
        order_desc = True

    query = supabase.table("view_risk_list").select("id,branch_id,branch_name,product_id,product_name,sku,batch,quantity,financial_value,expiry_date,days_to_expiry,risk_score,risk_level")
    if branch_id:
        query = query.eq("branch_id", branch_id)

    query = query.order(order_col, desc=order_desc)
    risk_scores = query.range(offset, offset+PAGE_SIZE-1).execute().data

    if not risk_scores:
        st.info("No risk scores available. Run the daily maintenance function first.")
        st.stop()

    df_risk = pd.DataFrame(risk_scores)
    df_risk['expiry_date'] = pd.to_datetime(df_risk['expiry_date']).dt.date

    def get_risk_color(row):
        if row['days_to_expiry'] is None or pd.isna(row['days_to_expiry']):
            return "🟢"
        if row['days_to_expiry'] <= 90:
            return "🔴"
        elif row['days_to_expiry'] <= 120:
            return "🟠"
        elif row['days_to_expiry'] <= 180:
            return "🟡"
        else:
            return "🟢"

    df_risk['risk_indicator'] = df_risk.apply(get_risk_color, axis=1)

    st.subheader("📋 Batch Risk Assessment")
    st.dataframe(df_risk[['risk_indicator', 'product_name','sku','batch','quantity','financial_value','expiry_date','days_to_expiry','risk_level']].rename(columns={
        'risk_indicator': 'Risk',
        'product_name':'Product',
        'sku':'SKU',
        'financial_value':'Financial Exposure (₦)',
        'days_to_expiry':'Days Left'
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
    fefo_order = df_risk.sort_values('expiry_date').head(20)
    for idx, row in fefo_order.iterrows():
        if pd.notna(row['expiry_date']):
            days_left = row['days_to_expiry']
            if days_left <= 90:
                urgency = "🔴 CRITICAL - Consume immediately!"
            elif days_left <= 120:
                urgency = "🟠 HIGH - Prioritize consumption"
            elif days_left <= 180:
                urgency = "🟡 MODERATE - Plan consumption"
            else:
                urgency = "🟢 LOW - Normal rotation"
            st.write(f"- **{row['product_name']}** (Batch `{row['batch']}`) – Expires **{row['expiry_date']}** ({days_left} days) – {urgency}")

    st.subheader("📊 Risk Distribution")
    risk_counts = df_risk['risk_level'].value_counts()
    st.bar_chart(risk_counts)

    critical_items = df_risk[df_risk['days_to_expiry'] <= 90]
    if not critical_items.empty:
        st.warning(f"⚠️ **{len(critical_items)}** batches have ≤90 days to expiry and require immediate attention!")
        st.dataframe(critical_items[['product_name', 'sku', 'batch', 'quantity', 'days_to_expiry']].head(10))

    with st.expander("ℹ️ How risk score is calculated"):
        st.markdown("""
        **Risk Score = (Expiry Score × 0.5) + (Financial Score × 0.3) + (Low Velocity Score × 0.2)**  
        - **Expiry Score** (0–100): 
          - ≤90 days → 100 (CRITICAL - 3 months or less)
          - 91-120 days → 90 (HIGH - 4 months)
          - 121-180 days → 75 (MODERATE - 6 months)
          - 181-365 days → 40 (LOW - 1 year)
          - >365 days → 10 (VERY LOW - over 1 year)
        - **Financial Score** (0–100): normalised quantity × cost  
        - **Low Velocity Score** (0–100): ≤0.1 units/day→90, 0.11–0.5→70, 0.51–2→40, >2→10  
        
        **Risk levels:** 
        - CRITICAL (≥80) → Products with ≤90 days to expiry
        - HIGH (60–79) → Products with 91-120 days to expiry
        - MODERATE (35–59) → Products with 121-180 days to expiry
        - LOW (<35) → Products with >180 days to expiry
        
        ⚠️ **Real‑world note:** Products with **≤90 days (3 months)** to expiry are considered write‑off risks and trigger immediate alerts.
        """)

# ============================================================
# PAGE: TRANSFER SUGGESTIONS
# ============================================================
elif page == "Transfer Suggestions":
    st.header("🔄 Inter‑Branch Transfer Suggestions")
    st.markdown("""
    **Optimised suggestions** – computed entirely inside the database.
    - **Stock imbalance:** Branch has excess stock; another branch needs it (expiry‑agnostic).
    - **Expiry risk:** Batch expiring soon in a slow‑selling branch → transfer to a branch with higher demand.
    - **Urgency (Updated for 90-day threshold):**  
      - **CRITICAL** – Expiry ≤90 days (3 months) **or** deficit very high (urgent transfer needed)  
      - **HIGH** – Expiry 91-120 days (4 months)  
      - **MEDIUM** – Expiry 121-180 days (6 months)
    """)
    
    try:
        query = supabase.table("view_all_transfer_suggestions").select("*")
        if branch_id:
            query = query.eq("from_branch_id", branch_id)
        res = query.execute()
        suggestions = res.data
    except Exception as e:
        st.error("⚠️ Unable to fetch transfer suggestions. Please contact your administrator.")
        st.stop()
    
    if not isinstance(suggestions, list) or len(suggestions) == 0:
        st.success("✅ No transfer suggestions at this time. Inventory appears well balanced.")
        st.stop()
    
    df_sugg = pd.DataFrame(suggestions)
    if 'suggestion_type' not in df_sugg.columns:
        df_sugg['suggestion_type'] = df_sugg.apply(
            lambda row: "Expiry Risk Transfer" if pd.notna(row.get('batch')) else "Stock Imbalance Transfer",
            axis=1
        )
    
    def get_urgency_color(urgency):
        if urgency == "CRITICAL":
            return "🔴"
        elif urgency == "HIGH":
            return "🟠"
        elif urgency == "MEDIUM":
            return "🟡"
        else:
            return "🟢"
    
    df_sugg['urgency_indicator'] = df_sugg['urgency'].apply(get_urgency_color)
    
    for idx, row in df_sugg.iterrows():
        with st.container():
            st.markdown(f"{row['urgency_indicator']} **{row['product_name']}** ({row['sku']})")
            st.markdown(f"📦 {row['quantity']} units from **{row['from_branch']}** → **{row['to_branch']}**")
            st.caption(f"🏷️ **{row['suggestion_type']}** – {row['reason']} (Urgency: {row['urgency']})")
            if pd.notna(row.get('batch')):
                st.caption(f"Batch: `{row['batch']}`")
            st.divider()
    
    st.subheader("📊 Urgency Breakdown")
    st.bar_chart(df_sugg['urgency'].value_counts())
    
    with st.expander("ℹ️ How suggestions are generated"):
        st.markdown("""
        - **Stock imbalance transfer (surplus → deficit):** Branch has more than reorder point + safety stock + 5 units; another branch is below reorder point. Applies to all products (including non‑expiring).
        - **Expiry risk transfer:** Batch expiring ≤90 days (3 months) in a branch with very low demand (<0.5 units/day) → transfer to branch with higher demand.
        - **Urgency (Updated thresholds):** 
          - CRITICAL (expiry ≤90 days or deficit very high)
          - HIGH (expiry 91-120 days)
          - MEDIUM (expiry 121-180 days)
        - All calculations run inside PostgreSQL using indexed joins – no client‑side processing.
        """)
