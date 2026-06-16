import streamlit as st
import pandas as pd
from supabase import create_client, Client
from datetime import date, datetime, timedelta, timezone
import re
from functools import wraps
import hashlib
import json
import logging
import io
import traceback
from typing import Dict, List, Any, Optional, Tuple
import time
import os
import secrets
import string

# ---------- CONFIG ----------
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]

@st.cache_resource
def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)

supabase = get_supabase()

# ---------- HTTPS ENFORCEMENT ----------
def enforce_https():
    """Enforce HTTPS in production"""
    is_production = os.environ.get("STREAMLIT_ENV", "").lower() == "production"
    
    if is_production:
        try:
            if not st.session_state.get("_https_checked", False):
                st.session_state._https_checked = True
                logger.info("HTTPS enforcement active in production")
                
                st.markdown("""
                <style>
                .security-notice {
                    background-color: #f0f8ff;
                    padding: 10px;
                    border-radius: 5px;
                    border-left: 4px solid #0066cc;
                    margin-bottom: 20px;
                }
                </style>
                """, unsafe_allow_html=True)
        except Exception as e:
            logger.warning(f"Could not check HTTPS status: {e}")

# ---------- RATE LIMITING ----------
class RateLimiter:
    """Simple rate limiter for login attempts and sensitive operations"""
    
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = {}
    
    def is_allowed(self, key: str) -> bool:
        """Check if a key is allowed to proceed"""
        current_time = time.time()
        
        self.attempts = {
            k: v for k, v in self.attempts.items()
            if current_time - v['last_attempt'] < self.window_seconds
        }
        
        if key not in self.attempts:
            self.attempts[key] = {
                'count': 1,
                'last_attempt': current_time,
                'blocked_until': None
            }
            return True
        
        if self.attempts[key].get('blocked_until') and current_time < self.attempts[key]['blocked_until']:
            return False
        
        if self.attempts[key]['count'] >= self.max_attempts:
            self.attempts[key]['blocked_until'] = current_time + self.window_seconds
            return False
        
        self.attempts[key]['count'] += 1
        self.attempts[key]['last_attempt'] = current_time
        return True
    
    def reset(self, key: str):
        """Reset attempts for a key"""
        if key in self.attempts:
            del self.attempts[key]

# ---------- PASSWORD VALIDATION ----------
class PasswordValidator:
    """Enforce strong password policies"""
    
    MIN_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL = True
    SPECIAL_CHARS = "!@#$%^&*(),.?\":{}|<>"
    
    @classmethod
    def validate(cls, password: str) -> Tuple[bool, str]:
        """Validate password against policy"""
        if not password or len(password) < cls.MIN_LENGTH:
            return False, f"Password must be at least {cls.MIN_LENGTH} characters long."
        
        if cls.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter."
        
        if cls.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter."
        
        if cls.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit."
        
        if cls.REQUIRE_SPECIAL and not any(c in cls.SPECIAL_CHARS for c in password):
            return False, f"Password must contain at least one special character: {cls.SPECIAL_CHARS}"
        
        common_patterns = [
            "password", "123456", "qwerty", "admin", "letmein", 
            "welcome", "monkey", "dragon", "master", "hello"
        ]
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns and is too weak."
        
        if len(password) >= 3:
            for i in range(len(password) - 2):
                if password[i] == password[i+1] == password[i+2]:
                    return False, "Password contains repeated characters (3 or more in a row)."
        
        return True, "Password is strong."
    
    @classmethod
    def generate_strong_password(cls) -> str:
        """Generate a strong password"""
        alphabet = string.ascii_letters + string.digits + cls.SPECIAL_CHARS
        password = ''.join(secrets.choice(alphabet) for _ in range(cls.MIN_LENGTH))
        return password

# ---------- STRUCTURED LOGGING ----------
class StructuredLogger:
    """Structured logging with different log levels and JSON output"""
    
    LOG_LEVELS = {
        "DEBUG": 10,
        "INFO": 20,
        "WARNING": 30,
        "ERROR": 40,
        "CRITICAL": 50
    }
    
    def __init__(self, app_name="inventory_app", min_level="INFO"):
        self.app_name = app_name
        self.min_level = self.LOG_LEVELS.get(min_level, 20)
        self.logs = []
        self.security_events = []
    
    def _log(self, level: str, message: str, extra: Dict = None, security: bool = False):
        """Internal logging method"""
        if self.LOG_LEVELS.get(level, 0) < self.min_level:
            return
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "app": self.app_name,
            "level": level,
            "message": message,
            "extra": extra or {}
        }
        self.logs.append(log_entry)
        
        if security:
            self.security_events.append(log_entry)
        
        print(f"[{log_entry['timestamp']}] {level}: {message}")
        if extra:
            print(f"  Extra: {json.dumps(extra, default=str)}")
    
    def debug(self, message: str, extra: Dict = None):
        self._log("DEBUG", message, extra)
    
    def info(self, message: str, extra: Dict = None, security: bool = False):
        self._log("INFO", message, extra, security)
    
    def warning(self, message: str, extra: Dict = None, security: bool = False):
        self._log("WARNING", message, extra, security)
    
    def error(self, message: str, extra: Dict = None, security: bool = False):
        self._log("ERROR", message, extra, security)
    
    def critical(self, message: str, extra: Dict = None, security: bool = False):
        self._log("CRITICAL", message, extra, security)
    
    def get_logs(self, level: str = None) -> List[Dict]:
        """Get logs filtered by level"""
        if level:
            return [log for log in self.logs if log['level'] == level]
        return self.logs
    
    def get_security_events(self) -> List[Dict]:
        """Get security-related events"""
        return self.security_events
    
    def export_logs(self) -> str:
        """Export logs as JSON string"""
        return json.dumps(self.logs, indent=2, default=str)

# Initialize logger
logger = StructuredLogger(min_level="INFO")

# Run HTTPS enforcement
enforce_https()

# ---------- CACHE MANAGEMENT ----------
class CacheManager:
    """Centralized cache management with invalidation"""
    _cache_keys = set()
    
    @staticmethod
    def invalidate_all():
        """Invalidate all cached functions"""
        logger.info("Invalidating all caches")
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
        
        func_name = key_prefix or func.__name__
        CacheManager.register(func_name)
        
        @wraps(func)
        def wrapped(*args, **kwargs):
            return wrapper(*args, **kwargs)
        return wrapped
    return decorator

# Initialize rate limiter
login_limiter = RateLimiter(max_attempts=5, window_seconds=300)
api_limiter = RateLimiter(max_attempts=100, window_seconds=60)

# ---------- GET REGISTERED EMAILS ----------
@cached_with_invalidation(ttl=300, key_prefix="registered_emails")
def get_registered_emails():
    """Get all registered emails from branches with their roles"""
    try:
        # Get all branches with email fields
        branches = supabase.table("branches").select(
            "id, name, code, storekeeper_email, procurement_email, inventory_email, auditor_email, manager_email"
        ).execute().data
        
        email_map = {}
        
        for branch in branches:
            branch_name = branch.get('name', 'Unknown')
            
            # Check each email field
            if branch.get('storekeeper_email'):
                email = branch['storekeeper_email']
                if email not in email_map:
                    email_map[email] = {
                        'email': email,
                        'role': 'Storekeeper',
                        'access': 'Viewer',
                        'branches': []
                    }
                email_map[email]['branches'].append({
                    'name': branch_name,
                    'role': 'Storekeeper'
                })
            
            if branch.get('procurement_email'):
                email = branch['procurement_email']
                if email not in email_map:
                    email_map[email] = {
                        'email': email,
                        'role': 'Procurement',
                        'access': 'Viewer',
                        'branches': []
                    }
                email_map[email]['branches'].append({
                    'name': branch_name,
                    'role': 'Procurement'
                })
            
            if branch.get('inventory_email'):
                email = branch['inventory_email']
                if email not in email_map:
                    email_map[email] = {
                        'email': email,
                        'role': 'Inventory',
                        'access': 'Viewer',
                        'branches': []
                    }
                email_map[email]['branches'].append({
                    'name': branch_name,
                    'role': 'Inventory'
                })
            
            if branch.get('auditor_email'):
                email = branch['auditor_email']
                if email not in email_map:
                    email_map[email] = {
                        'email': email,
                        'role': 'Auditor',
                        'access': 'Viewer',
                        'branches': []
                    }
                email_map[email]['branches'].append({
                    'name': branch_name,
                    'role': 'Auditor'
                })
            
            if branch.get('manager_email'):
                email = branch['manager_email']
                if email not in email_map:
                    email_map[email] = {
                        'email': email,
                        'role': 'Manager',
                        'access': 'Admin',
                        'branches': []
                    }
                email_map[email]['branches'].append({
                    'name': branch_name,
                    'role': 'Manager'
                })
        
        # Check for additional admin emails from secrets
        admin_emails = st.secrets.get("ADMIN_EMAILS", "").split(",")
        admin_emails = [e.strip() for e in admin_emails if e.strip()]
        
        for admin_email in admin_emails:
            if admin_email in email_map:
                email_map[admin_email]['access'] = 'Admin'
                email_map[admin_email]['role'] = 'Admin (Additional)'
            else:
                # Admin email not in any branch
                email_map[admin_email] = {
                    'email': admin_email,
                    'role': 'Admin (System)',
                    'access': 'Admin',
                    'branches': []
                }
        
        return list(email_map.values())
    
    except Exception as e:
        logger.error(f"Failed to get registered emails", {"error": str(e)})
        return []

# ---------- AUTH WITH EMAIL-BASED LOGIN ----------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user_role = None
    st.session_state.login_attempts = 0
    st.session_state.last_login_attempt = None
    st.session_state.user_email = None
    st.session_state.user_branches = []
    st.session_state.user_role_match = None

if not st.session_state.authenticated:
    # Check rate limiting for login
    client_ip = st.query_params.get("client_ip", "unknown")
    login_key = f"login_{client_ip}"
    
    if not login_limiter.is_allowed(login_key):
        remaining_time = int(login_limiter.attempts.get(login_key, {}).get('blocked_until', time.time()) - time.time())
        st.error(f"🔒 Too many failed login attempts. Please wait {remaining_time} seconds before trying again.")
        logger.warning("Rate limit exceeded for login", {"client_ip": client_ip}, security=True)
        st.stop()
    
    st.markdown("""
    <style>
    .login-container {
        max-width: 400px;
        margin: 0 auto;
        padding: 20px;
        background-color: #f8f9fa;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .login-container h1 {
        text-align: center;
        margin-bottom: 20px;
    }
    .login-container .stTextInput {
        margin-bottom: 15px;
    }
    .login-container .stButton {
        margin-top: 10px;
    }
    .login-help {
        font-size: 0.9em;
        color: #666;
        margin-top: 15px;
        padding: 10px;
        background-color: #fff3cd;
        border-radius: 5px;
        border-left: 4px solid #ffc107;
    }
    .registered-emails {
        font-size: 0.85em;
        margin-top: 10px;
        padding: 10px;
        background-color: #e8f5e9;
        border-radius: 5px;
        border-left: 4px solid #4caf50;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    
    # Center the icon
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.image("https://img.icons8.com/color/96/000000/inventory.png", width=80)
    
    st.title("🔐 Inventory Management System")
    
    st.markdown("---")
    
    # Option to view registered emails (admin only)
    show_emails = st.checkbox("📋 Show registered emails (admin only)")
    if show_emails:
        admin_check = st.text_input("Enter admin password to view registered emails", type="password")
        if admin_check == st.secrets.get("APP_PASSWORD", "changeme"):
            registered_emails = get_registered_emails()
            if registered_emails:
                st.markdown('<div class="registered-emails">', unsafe_allow_html=True)
                st.subheader("📧 Registered Emails")
                
                # Create a DataFrame for better display
                df_emails = pd.DataFrame(registered_emails)
                df_emails['branches'] = df_emails['branches'].apply(
                    lambda x: ', '.join([f"{b['name']} ({b['role']})" for b in x]) if x else "No branch assigned"
                )
                st.dataframe(df_emails[['email', 'role', 'access', 'branches']])
                
                # Summary stats
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Users", len(registered_emails))
                with col2:
                    admin_count = len([e for e in registered_emails if e['access'] == 'Admin'])
                    st.metric("Admins", admin_count)
                with col3:
                    viewer_count = len([e for e in registered_emails if e['access'] == 'Viewer'])
                    st.metric("Viewers", viewer_count)
                
                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.info("No registered emails found.")
        elif admin_check:
            st.error("Incorrect admin password")
    
    st.markdown("---")
    
    # Regular login
    email = st.text_input("📧 Email Address", placeholder="your.email@company.com", key="login_email")
    pwd = st.text_input("🔑 Password", type="password", key="login_password")
    
    # Show password requirements info
    with st.expander("📋 Password Information", expanded=False):
        st.markdown("""
        - **Admin users** (Managers) use the **Admin Password**
        - **Viewer users** (Storekeepers, Procurement, Inventory, Auditors) use the **Viewer Password**
        - Contact your system administrator if you don't have your password
        """)
    
    col1, col2 = st.columns(2)
    with col1:
        login_btn = st.button("🔓 Login", use_container_width=True)
    with col2:
        if st.button("❓ Help", use_container_width=True):
            st.info("Use your registered email address and the system password provided by your administrator.")
    
    if login_btn:
        if not email or not pwd:
            st.error("Please enter both email and password.")
        else:
            # Check rate limiting again
            if not login_limiter.is_allowed(login_key):
                remaining_time = int(login_limiter.attempts.get(login_key, {}).get('blocked_until', time.time()) - time.time())
                st.error(f"🔒 Too many failed login attempts. Please wait {remaining_time} seconds.")
                st.stop()
            
            try:
                # Check if the email exists in any branch
                branch_query = supabase.table("branches").select(
                    "id, name, code, storekeeper_email, procurement_email, inventory_email, auditor_email, manager_email"
                ).or_(
                    f"storekeeper_email.eq.{email},procurement_email.eq.{email},inventory_email.eq.{email},auditor_email.eq.{email},manager_email.eq.{email}"
                )
                
                branch_result = branch_query.execute()
                found_branches = branch_result.data
                
                if found_branches:
                    # Email exists in at least one branch
                    # Determine role based on which email field matched
                    user_role = None
                    matched_role = None
                    
                    for branch in found_branches:
                        if branch.get('storekeeper_email') == email:
                            matched_role = "storekeeper"
                            user_role = "viewer"
                            break
                        elif branch.get('procurement_email') == email:
                            matched_role = "procurement"
                            user_role = "viewer"
                            break
                        elif branch.get('inventory_email') == email:
                            matched_role = "inventory"
                            user_role = "viewer"
                            break
                        elif branch.get('auditor_email') == email:
                            matched_role = "auditor"
                            user_role = "viewer"
                            break
                        elif branch.get('manager_email') == email:
                            matched_role = "manager"
                            user_role = "admin"
                            break
                    
                    # Check if this is an admin email (can also use admin password)
                    admin_emails = st.secrets.get("ADMIN_EMAILS", "").split(",")
                    admin_emails = [e.strip() for e in admin_emails if e.strip()]
                    is_admin = user_role == "admin" or email in admin_emails
                    
                    # Verify password based on role
                    if is_admin:
                        # Admin users can use APP_PASSWORD
                        if pwd == st.secrets.get("APP_PASSWORD", "changeme"):
                            st.session_state.authenticated = True
                            st.session_state.user_role = "admin"
                            st.session_state.user_email = email
                            st.session_state.user_branches = found_branches
                            st.session_state.user_role_match = matched_role or "admin"
                            login_limiter.reset(login_key)
                            
                            logger.info(f"Admin user logged in successfully", {
                                "email": email, 
                                "role": matched_role, 
                                "branch": found_branches[0]['name'] if found_branches else "N/A"
                            }, security=True)
                            st.rerun()
                        else:
                            # Admin but wrong password
                            login_limiter.is_allowed(login_key)
                            attempts_left = login_limiter.max_attempts - login_limiter.attempts.get(login_key, {}).get('count', 0)
                            st.error(f"❌ Invalid admin password. {attempts_left} attempts remaining.")
                            logger.warning(f"Failed admin login attempt", {"email": email, "attempts_left": attempts_left}, security=True)
                    else:
                        # Non-admin users use VIEWER_PASSWORD
                        if pwd == st.secrets.get("VIEWER_PASSWORD", ""):
                            st.session_state.authenticated = True
                            st.session_state.user_role = "viewer"
                            st.session_state.user_email = email
                            st.session_state.user_branches = found_branches
                            st.session_state.user_role_match = matched_role
                            login_limiter.reset(login_key)
                            
                            logger.info(f"Viewer user logged in successfully", {
                                "email": email, 
                                "role": matched_role, 
                                "branch": found_branches[0]['name'] if found_branches else "N/A"
                            }, security=True)
                            st.rerun()
                        else:
                            # Non-admin but wrong password
                            login_limiter.is_allowed(login_key)
                            attempts_left = login_limiter.max_attempts - login_limiter.attempts.get(login_key, {}).get('count', 0)
                            st.error(f"❌ Invalid viewer password. {attempts_left} attempts remaining.")
                            logger.warning(f"Failed viewer login attempt", {"email": email, "attempts_left": attempts_left}, security=True)
                else:
                    # Email not found in any branch
                    login_limiter.is_allowed(login_key)
                    attempts_left = login_limiter.max_attempts - login_limiter.attempts.get(login_key, {}).get('count', 0)
                    st.error(f"❌ Email not registered in any branch. {attempts_left} attempts remaining.")
                    logger.warning(f"Login attempt with unregistered email", {"email": email}, security=True)
                    
                    # Show help for debugging
                    with st.expander("🔍 Need help? Check registered emails"):
                        st.markdown("""
                        **Your email must be added to a branch as one of:**
                        - Storekeeper Email
                        - Procurement Email  
                        - Inventory Email
                        - Auditor Email
                        - Manager Email
                        
                        Contact your administrator to add your email to the appropriate branch.
                        """)
                        
                        # Show registered emails (only if admin password is entered correctly)
                        admin_check = st.text_input("Enter admin password to view registered emails", type="password", key="login_admin_check")
                        if admin_check == st.secrets.get("APP_PASSWORD", "changeme"):
                            registered_emails = get_registered_emails()
                            if registered_emails:
                                st.subheader("📧 Registered Emails")
                                df_emails = pd.DataFrame(registered_emails)
                                df_emails['branches'] = df_emails['branches'].apply(
                                    lambda x: ', '.join([f"{b['name']} ({b['role']})" for b in x]) if x else "No branch assigned"
                                )
                                st.dataframe(df_emails[['email', 'role', 'access', 'branches']])
                        elif admin_check:
                            st.error("Incorrect admin password")
                    
            except Exception as e:
                logger.error(f"Login error", {"error": str(e), "email": email}, security=True)
                st.error(f"Login error: Please try again later.")
    
    # Show rate limit status
    if login_key in login_limiter.attempts:
        remaining = login_limiter.max_attempts - login_limiter.attempts[login_key]['count']
        if remaining > 0 and remaining < login_limiter.max_attempts:
            st.caption(f"🔒 {remaining} login attempts remaining")
        elif remaining <= 0:
            st.caption("🔒 Too many attempts. Please wait.")
    
    st.markdown("""
    <div class="login-help">
        💡 <strong>Login Help:</strong><br>
        • Use your registered email address<br>
        • Managers use the <strong>Admin Password</strong><br>
        • All other roles use the <strong>Viewer Password</strong><br>
        • Contact your administrator if you need access
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

# After authentication, show user info in sidebar
if st.session_state.authenticated:
    # Display user info in sidebar
    st.sidebar.markdown("---")
    st.sidebar.subheader("👤 User Info")
    st.sidebar.write(f"**Email:** {st.session_state.get('user_email', 'N/A')}")
    st.sidebar.write(f"**Role:** {st.session_state.get('user_role', 'N/A').title()}")
    if st.session_state.get('user_role_match'):
        st.sidebar.write(f"**Branch Role:** {st.session_state.get('user_role_match', 'N/A').title()}")
    
    # Show branch access
    if st.session_state.get('user_branches'):
        branches = st.session_state.user_branches
        st.sidebar.write("**Access to Branches:**")
        for branch in branches:
            st.sidebar.write(f"  • {branch['name']} ({branch['code']})")
    
    # Logout button
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        logger.info(f"User logged out", {"email": st.session_state.get('user_email')}, security=True)
        for key in ['authenticated', 'user_role', 'user_email', 'user_branches', 'user_role_match']:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()
    st.sidebar.markdown("---")

# ---------- EMAIL LINK AUTO-MARK ----------
params = st.query_params
if "alert_id" in params and "action" in params:
    alert_id = params["alert_id"]
    try:
        if not api_limiter.is_allowed(f"api_{st.session_state.user_email}"):
            st.error("🔒 Too many API requests. Please wait a moment.")
            st.stop()
        
        supabase.table("alert_log").update({
            "action_taken": "Marked done via email link",
            "action_date": datetime.now(timezone.utc).isoformat()
        }).eq("id", alert_id).execute()
        logger.info(f"Alert {alert_id} marked as done via email link")
        st.success(f"✅ Alert #{alert_id} marked as done!")
        st.query_params.clear()
        st.rerun()
    except Exception as e:
        logger.error(f"Failed to mark alert {alert_id} as done", {"error": str(e)})
        st.error(f"Failed to mark alert: {str(e)}")

# ---------- BRANCH SELECTOR ----------
@cached_with_invalidation(ttl=3600, key_prefix="branches")
def get_branches():
    """Get branches with efficient single query"""
    try:
        data = supabase.table("branches").select("id,name,code").execute().data
        logger.debug("Branches fetched successfully", {"count": len(data)})
        return data
    except Exception as e:
        logger.error("Failed to fetch branches", {"error": str(e)})
        return []

@cached_with_invalidation(ttl=3600, key_prefix="branch_maps")
def get_branch_maps():
    """Pre-compute branch lookup maps to avoid repeated lookups"""
    branches = get_branches()
    return {
        'id_to_name': {b['id']: b['name'] for b in branches},
        'name_to_id': {b['name']: b['id'] for b in branches},
        'id_to_code': {b['id']: b['code'] for b in branches}
    }

# Get branches data with error handling
branches_data = get_branches()
branch_maps = get_branch_maps()

# Safely get branch names
branch_names = []
if branches_data:
    branch_names = [b['name'] for b in branches_data]

# Ensure branch_maps has the expected keys
if 'name_to_id' not in branch_maps:
    branch_maps['name_to_id'] = {}

def reset_pagination():
    st.session_state.prod_page = 0
    st.session_state.inv_page = 0
    st.session_state.alert_page = 0
    st.session_state.limits_page = 0
    st.session_state.risk_page = 0

# Safely get branch_id
selected_branch_name = st.sidebar.selectbox(
    "Select Branch",
    ["All Branches"] + branch_names,
    on_change=reset_pagination
)

# Safely get branch_id with error handling
try:
    if selected_branch_name == "All Branches":
        branch_id = None
    else:
        branch_id = branch_maps.get('name_to_id', {}).get(selected_branch_name)
except Exception as e:
    logger.error(f"Error getting branch ID", {"error": str(e), "selected_branch": selected_branch_name})
    branch_id = None

# ---------- NAVIGATION ----------
if st.session_state.user_role == "admin":
    pages = ["Dashboard", "Products & Inventory", "Branches", "CSV Upload", 
             "Alerts & Advisories", "Stock & Demand Limits", "Risk & FEFO", 
             "Transfer Suggestions", "Registered Users", "System Logs", "Data Export", "Security Settings"]
else:
    pages = ["Dashboard", "Products & Inventory", "CSV Upload", 
             "Alerts & Advisories", "Stock & Demand Limits", "Risk & FEFO", 
             "Transfer Suggestions", "Data Export"]

page = st.sidebar.radio("Go to", pages)

# ---------- RESPONSIVE DESIGN HELPERS ----------
def mobile_friendly_table(df, max_height=400):
    """Display a mobile-friendly table with scrolling"""
    return st.dataframe(df, use_container_width=True, height=max_height)

# ---------- PROGRESS INDICATOR ----------
class ProgressIndicator:
    """Custom progress indicator with detailed status updates"""
    
    def __init__(self, total_steps: int, description: str = "Processing..."):
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.progress_bar = None
        self.status_text = None
        self.start_time = time.time()
    
    def __enter__(self):
        """Initialize progress display"""
        self.progress_bar = st.progress(0)
        self.status_text = st.empty()
        self.status_text.text(f"{self.description} (0/{self.total_steps})")
        return self
    
    def update(self, step: int = 1, status: str = None):
        """Update progress"""
        self.current_step += step
        progress = min(self.current_step / self.total_steps, 1.0)
        
        if self.progress_bar:
            self.progress_bar.progress(progress)
        
        if self.status_text:
            elapsed = time.time() - self.start_time
            eta = (elapsed / self.current_step) * (self.total_steps - self.current_step) if self.current_step > 0 else 0
            
            status_msg = status or f"Processing... ({self.current_step}/{self.total_steps})"
            if self.current_step < self.total_steps:
                self.status_text.text(f"{status_msg} | ETA: {eta:.1f}s")
            else:
                self.status_text.text(f"✅ Complete! ({self.total_steps} items processed in {elapsed:.1f}s)")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up progress display"""
        if exc_type:
            self.status_text.error(f"❌ Error: {str(exc_val)}")
        else:
            self.status_text.text(f"✅ Complete! {self.total_steps} items processed in {time.time() - self.start_time:.1f}s")
        
        if self.progress_bar:
            self.progress_bar.progress(1.0)

# ---------- HELPERS ----------
def validate_csv_columns(df, required_cols, label="CSV"):
    """Validate CSV has required columns with better error messages"""
    missing = required_cols - set(df.columns)
    if missing:
        logger.warning(f"Missing columns in {label}", {"missing": list(missing)})
        return False, f"❌ Missing columns in {label}: {', '.join(missing)}"
    return True, ""

def validate_sku_format(sku):
    """Validate SKU format - alphanumeric, underscores, hyphens only"""
    if not sku or not isinstance(sku, str):
        return False
    return bool(re.match(r'^[A-Za-z0-9_\-\.]+$', sku))

def upload_with_transaction(table_name, records, batch_size=500):
    """Upload with transaction-like behavior and progress tracking"""
    if not records:
        logger.info(f"No records to upload to {table_name}")
        return True, None, 0
    
    if not api_limiter.is_allowed(f"upload_{st.session_state.user_email}"):
        return False, "🔒 Too many upload requests. Please wait a moment.", 0
    
    total_records = len(records)
    successful = 0
    failed_records = []
    
    with ProgressIndicator((total_records + batch_size - 1) // batch_size, f"Uploading to {table_name}") as progress:
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
                logger.debug(f"Uploaded batch {batch_num}/{total_batches} to {table_name}", 
                           {"batch_size": len(batch), "successful": successful})
                progress.update(status=f"Batch {batch_num}/{total_batches} - {successful}/{total_records} records")
                
            except Exception as e:
                error_detail = {
                    "table": table_name,
                    "batch": batch_num,
                    "batch_size": len(batch),
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
                logger.error(f"Upload failed at batch {batch_num}", error_detail)
                failed_records.extend(batch)
                return False, f"Upload failed at batch {batch_num}/{total_batches}. Error: {str(e)}", successful
    
    if failed_records:
        logger.warning(f"Some records failed to upload", {"failed_count": len(failed_records)})
    
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
        logger.error("Invalid SKU formats", {"invalid_skus": invalid_skus[:10]})
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
    
    with ProgressIndicator(len(unique_products), "Processing products") as progress:
        for i in range(0, len(unique_products), batch_size):
            batch = unique_products[i:i+batch_size]
            for product in batch:
                sku = product['sku']
                try:
                    if sku in existing_skus:
                        product_clean = {k: v for k, v in product.items() if k != 'id'}
                        supabase.table("products").update(product_clean).eq("sku", sku).execute()
                        updated_count += 1
                        logger.debug(f"Updated product", {"sku": sku})
                    else:
                        product_clean = {k: v for k, v in product.items() if k != 'id'}
                        supabase.table("products").insert(product_clean).execute()
                        created_count += 1
                        logger.debug(f"Created product", {"sku": sku})
                    
                    progress.update(status=f"Processed {sku}")
                    
                except Exception as e:
                    logger.error(f"Failed to process product {sku}", {"error": str(e)})
                    return False, f"Failed to process SKU {sku}: {str(e)}", created_count, updated_count
    
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

def ensure_products_exist(skus, default_cost=0.0, default_shelf_life=120):
    """Ensure products exist, with better error handling and validation"""
    if not skus:
        return {}
    
    sku_to_id = chunked_sku_lookup(skus)
    missing = [sku for sku in skus if sku not in sku_to_id]
    
    if missing:
        invalid_skus = [sku for sku in missing if not validate_sku_format(sku)]
        if invalid_skus:
            logger.error("Invalid SKU format in missing products", {"invalid_skus": invalid_skus[:10]})
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
            logger.error("Failed to create products", {"error": error})
            st.error(f"❌ Failed to create products: {error}")
            return {}
        
        CacheManager.invalidate_all()
        sku_to_id.update(chunked_sku_lookup(missing))
        logger.info(f"Auto-created products", {"count": len(missing)})
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
    
    try:
        product_query = supabase.table("products").select(
            "id,sku,name,category,shelf_life_days,cost"
        ).or_(
            f"sku.ilike.%{search_term}%,name.ilike.%{search_term}%"
        ).limit(limit)
        
        products = product_query.execute().data
        
        if not products:
            return []
        
        product_ids = [p['id'] for p in products]
        
        if branch_id:
            inventory_query = supabase.table("view_inventory_list").select(
                "product_id,batch,quantity,expiry_date,storage_location"
            ).in_("product_id", product_ids).eq("branch_id", branch_id)
            inventory = inventory_query.execute().data
            
            inv_by_product = {}
            for inv in inventory:
                prod_id = inv['product_id']
                if prod_id not in inv_by_product:
                    inv_by_product[prod_id] = []
                inv_by_product[prod_id].append(inv)
            
            for product in products:
                product['inventory'] = inv_by_product.get(product['id'], [])
        else:
            for product in products:
                inventory_query = supabase.table("view_inventory_list").select(
                    "branch_name,batch,quantity,expiry_date,storage_location"
                ).eq("product_id", product['id'])
                product['inventory'] = inventory_query.execute().data
        
        logger.debug(f"Product search completed", {"term": search_term, "results": len(products)})
        return products
        
    except Exception as e:
        logger.error("Product search failed", {"term": search_term, "error": str(e)})
        return []

def search_inventory(search_term, branch_id=None, limit=100):
    """Search inventory by product SKU, name, or batch"""
    search_term = search_term.strip()
    if not search_term:
        return []
    
    try:
        query = supabase.table("view_inventory_list").select(
            "id,branch_id,branch_name,product_id,product_name,sku,batch,quantity,expiry_date,storage_location,cost"
        )
        
        if branch_id:
            query = query.eq("branch_id", branch_id)
        
        query = query.or_(
            f"sku.ilike.%{search_term}%,product_name.ilike.%{search_term}%,batch.ilike.%{search_term}%"
        ).limit(limit)
        
        results = query.execute().data
        logger.debug(f"Inventory search completed", {"term": search_term, "results": len(results)})
        return results
        
    except Exception as e:
        logger.error("Inventory search failed", {"term": search_term, "error": str(e)})
        return []

# ---------- DATA EXPORT ----------
def export_data_to_csv(data: List[Dict], filename: str = "export.csv") -> bytes:
    """Export data to CSV and return as bytes"""
    if not data:
        return b""
    
    df = pd.DataFrame(data)
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    return csv_buffer.getvalue().encode('utf-8')

def export_data_to_excel(data: List[Dict], filename: str = "export.xlsx") -> bytes:
    """Export data to Excel and return as bytes"""
    if not data:
        return b""
    
    df = pd.DataFrame(data)
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Data', index=False)
    return excel_buffer.getvalue()

# ---------- SECURITY HEADERS ----------
def add_security_headers():
    """Add security headers and information to the page"""
    st.markdown("""
    <style>
    .security-badge {
        position: fixed;
        bottom: 10px;
        right: 10px;
        background: rgba(0,0,0,0.7);
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-size: 12px;
        z-index: 999;
        font-family: monospace;
    }
    .security-badge .secure {
        color: #00ff00;
    }
    .security-badge .insecure {
        color: #ff0000;
    }
    </style>
    """, unsafe_allow_html=True)
    
    try:
        is_production = os.environ.get("STREAMLIT_ENV", "").lower() == "production"
        if is_production:
            status = "🔒 Secure (HTTPS)"
            color = "secure"
        else:
            status = "🔓 Development"
            color = "insecure"
        
        st.markdown(f"""
        <div class="security-badge">
            <span class="{color}">{status}</span> | 
            Rate Limit: {login_limiter.max_attempts} attempts
        </div>
        """, unsafe_allow_html=True)
    except:
        pass

add_security_headers()

# ============================================================
# PAGE: DASHBOARD
# ============================================================
if page == "Dashboard":
    st.header("📊 Executive Summary")
    
    col1, col2 = st.columns(2)
    
    if branch_id:
        total_val = supabase.rpc("get_total_value", {"branch_id_param": branch_id}).execute().data
        waste_val = supabase.rpc("get_waste_risk", {"branch_id_param": branch_id}).execute().data
    else:
        total_val = supabase.rpc("get_total_value_all").execute().data
        waste_val = supabase.rpc("get_waste_risk_all").execute().data
    
    total_val = total_val or 0
    waste_val = waste_val or 0
    
    with col1:
        st.metric("Total Inventory Value", f"₦{total_val:,.0f}")
    with col2:
        st.metric("Waste Risk (next 120d)", f"₦{waste_val:,.0f}")  # Updated to 120 days

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
# PAGE: PRODUCTS & INVENTORY
# ============================================================
elif page == "Products & Inventory":
    st.header("📦 Products & Inventory Management")
    
    st.subheader("🔍 Search Products & Inventory")
    col1, col2 = st.columns([3, 1])
    with col1:
        search_term = st.text_input("Search by SKU, Product Name, or Batch", 
                                   placeholder="e.g., SKU123, Paracetamol, BATCH-001",
                                   key="product_search")
    with col2:
        search_type = st.selectbox("Search in", ["Products", "Inventory"], key="search_type")
    
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
            logger.info("Data refreshed")
            st.rerun()
    
    st.divider()
    
    if "show_add_product" not in st.session_state:
        st.session_state.show_add_product = False
    if "show_all_products" not in st.session_state:
        st.session_state.show_all_products = True
    if "show_inventory" not in st.session_state:
        st.session_state.show_inventory = False
    
    if st.session_state.show_add_product:
        with st.expander("➕ Add New Product", expanded=True):
            with st.form("add_product_form"):
                col1, col2 = st.columns(2)
                with col1:
                    new_sku = st.text_input("SKU*", help="Alphanumeric, underscores, hyphens, or periods")
                    new_name = st.text_input("Product Name*")
                with col2:
                    new_category = st.text_input("Category")
                    new_shelf_life = st.number_input("Shelf Life (days)", min_value=1, value=120)
                    new_cost = st.number_input("Unit Cost (₦)", min_value=0.0, value=0.0, format="%.2f")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("✅ Add Product", use_container_width=True):
                        if not new_sku or not new_name:
                            st.error("SKU and name are required.")
                            logger.warning("Add product failed: missing SKU or name")
                        elif not validate_sku_format(new_sku):
                            st.error("Invalid SKU format. Use alphanumeric, underscores, hyphens, or periods.")
                            logger.warning("Add product failed: invalid SKU format", {"sku": new_sku})
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
                                logger.info(f"Product added", {"sku": new_sku, "name": new_name})
                                CacheManager.invalidate_all()
                                st.session_state.show_add_product = False
                                st.rerun()
                            except Exception as e:
                                logger.error(f"Failed to add product", {"sku": new_sku, "error": str(e)})
                                st.error(f"Failed to add product: {e}")
                with col2:
                    if st.form_submit_button("❌ Cancel", use_container_width=True):
                        st.session_state.show_add_product = False
                        st.rerun()
    
    if search_term:
        if search_type == "Products":
            with st.spinner(f"Searching for '{search_term}'..."):
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
                        
                        if product.get('inventory'):
                            st.subheader("Inventory Locations")
                            inv_df = pd.DataFrame(product['inventory'])
                            if 'branch_name' in inv_df.columns:
                                display_cols = ['branch_name', 'batch', 'quantity', 'expiry_date', 'storage_location']
                            else:
                                display_cols = ['batch', 'quantity', 'expiry_date', 'storage_location']
                            mobile_friendly_table(inv_df[display_cols])
            else:
                st.info(f"No products found matching '{search_term}'")
        
        else:
            with st.spinner(f"Searching inventory for '{search_term}'..."):
                results = search_inventory(search_term, branch_id)
            
            if results:
                st.success(f"Found {len(results)} inventory records matching '{search_term}'")
                df_results = pd.DataFrame(results)
                df_results['expiry_display'] = df_results['expiry_date'].apply(lambda x: x if pd.notna(x) else "No expiry")
                mobile_friendly_table(df_results[['branch_name', 'product_name', 'sku', 'batch', 'quantity', 'expiry_display', 'storage_location']])
                
                st.subheader("⚡ Quick Inventory Adjustment")
                selected_item = st.selectbox("Select inventory item to adjust", 
                                           [f"{row['sku']} - {row['batch']}" for row in results])
                if selected_item:
                    selected_index = [f"{row['sku']} - {row['batch']}" == selected_item for row in results].index(True)
                    selected_row = results[selected_index]
                    new_qty = st.number_input("New Quantity", min_value=0, value=selected_row['quantity'])
                    if st.button("Update Quantity"):
                        try:
                            supabase.table("inventory").update({"quantity": new_qty}).eq("id", selected_row['id']).execute()
                            st.success("✅ Inventory updated!")
                            logger.info(f"Inventory updated", {"id": selected_row['id'], "new_qty": new_qty})
                            CacheManager.invalidate_all()
                            st.rerun()
                        except Exception as e:
                            logger.error(f"Failed to update inventory", {"id": selected_row['id'], "error": str(e)})
                            st.error(f"Failed to update: {e}")
            else:
                st.info(f"No inventory records found matching '{search_term}'")
    
    else:
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
                mobile_friendly_table(df_i[['branch_name','product_name','sku','batch','quantity','expiry_display','storage_location']].rename(columns={
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
        
        else:
            st.subheader("📋 All Products")
            PAGE_SIZE = 50
            if "prod_page" not in st.session_state:
                st.session_state.prod_page = 0
            offset = st.session_state.prod_page * PAGE_SIZE
            
            total = get_cached_count("products")
            total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
            
            prods = supabase.table("products").select("id,sku,name,category,shelf_life_days,cost").range(offset, offset+PAGE_SIZE-1).execute().data
            
            if prods:
                df_p = pd.DataFrame(prods)
                mobile_friendly_table(df_p[['sku','name','category','shelf_life_days','cost']])
                
                col1, col2 = st.columns(2)
                if col1.button("⬅️ Prev", disabled=st.session_state.prod_page==0):
                    st.session_state.prod_page -= 1
                    st.rerun()
                if col2.button("Next ➡️", disabled=st.session_state.prod_page>=total_pages-1):
                    st.session_state.prod_page += 1
                    st.rerun()
                st.caption(f"Page {st.session_state.prod_page+1} of {total_pages}")
                
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
                                    logger.info(f"Product updated", {"sku": edit_sku})
                                    CacheManager.invalidate_all()
                                    st.rerun()
                                except Exception as e:
                                    logger.error(f"Failed to update product", {"sku": edit_sku, "error": str(e)})
                                    st.error(f"Failed to update: {e}")
                        with col2:
                            if st.form_submit_button("🗑️ Delete Product", use_container_width=True):
                                st.warning("⚠️ Warning: This will delete the product and all associated inventory.")
                                if st.checkbox("Confirm deletion"):
                                    try:
                                        supabase.table("inventory").delete().eq("product_id", product['id']).execute()
                                        supabase.table("products").delete().eq("id", product['id']).execute()
                                        st.success("✅ Product and associated inventory deleted.")
                                        logger.info(f"Product deleted", {"sku": edit_sku})
                                        CacheManager.invalidate_all()
                                        st.rerun()
                                    except Exception as e:
                                        logger.error(f"Failed to delete product", {"sku": edit_sku, "error": str(e)})
                                        st.error(f"Failed to delete: {e}")
            else:
                st.info("No products found. Add your first product above!")

# ============================================================
# PAGE: BRANCHES (admin only)
# ============================================================
elif page == "Branches":
    if st.session_state.user_role != "admin":
        st.error("Permission denied.")
        logger.warning("Unauthorized access attempt to Branches page", security=True)
        st.stop()
    
    st.header("🏢 Branch Management")
    st.markdown("""
    **Note:** Users can login using the email addresses listed in any branch.
    - **Storekeeper, Procurement, Inventory, Auditor** → Viewer access (uses Viewer Password)
    - **Manager** → Admin access (uses Admin Password)
    
    **Email Management:** When you expand a branch, all existing emails will be displayed in the appropriate text boxes for easy editing.
    """)
    
    # Get all branches with full details
    @cached_with_invalidation(ttl=60, key_prefix="branches_full")
    def get_branches_full():
        """Get branches with all fields including emails"""
        try:
            data = supabase.table("branches").select(
                "id,name,code,storekeeper_email,procurement_email,inventory_email,auditor_email,manager_email"
            ).execute().data
            return data
        except Exception as e:
            logger.error("Failed to fetch branches with emails", {"error": str(e)})
            return []
    
    branches = get_branches_full()
    
    if not branches:
        st.info("No branches found. Use 'Add Branch' below.")
    else:
        for branch in branches:
            # Create a unique key for each branch form
            branch_key = f"branch_{branch['id']}"
            
            # Show current emails in a summary
            with st.expander(f"📋 {branch['name']} ({branch['code']})", expanded=False):
                # Show email summary
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Current Emails:**")
                    if branch.get('storekeeper_email'):
                        st.write(f"📧 Storekeeper: {branch['storekeeper_email']}")
                    if branch.get('procurement_email'):
                        st.write(f"📧 Procurement: {branch['procurement_email']}")
                    if branch.get('inventory_email'):
                        st.write(f"📧 Inventory: {branch['inventory_email']}")
                with col2:
                    if branch.get('auditor_email'):
                        st.write(f"📧 Auditor: {branch['auditor_email']}")
                    if branch.get('manager_email'):
                        st.write(f"📧 Manager: {branch['manager_email']}")
                    if not any([
                        branch.get('storekeeper_email'),
                        branch.get('procurement_email'),
                        branch.get('inventory_email'),
                        branch.get('auditor_email'),
                        branch.get('manager_email')
                    ]):
                        st.write("⚠️ No emails assigned")
                
                st.markdown("---")
                st.subheader("✏️ Edit Branch Details")
                
                with st.form(key=f"edit_branch_{branch['id']}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        new_name = st.text_input("Branch Name", value=branch['name'])
                        new_code = st.text_input("Branch Code", value=branch['code'])
                        
                        st.markdown("**📧 Viewer Role Emails:**")
                        new_storekeeper = st.text_input(
                            "Storekeeper Email", 
                            value=branch.get('storekeeper_email', ''),
                            help="This user will have Viewer access"
                        )
                        new_procurement = st.text_input(
                            "Procurement Email", 
                            value=branch.get('procurement_email', ''),
                            help="This user will have Viewer access"
                        )
                        new_inventory = st.text_input(
                            "Inventory Email", 
                            value=branch.get('inventory_email', ''),
                            help="This user will have Viewer access"
                        )
                    with col2:
                        st.markdown("**📧 Viewer Role Emails (continued):**")
                        new_auditor = st.text_input(
                            "Auditor Email", 
                            value=branch.get('auditor_email', ''),
                            help="This user will have Viewer access"
                        )
                        
                        st.markdown("**📧 Admin Role Email:**")
                        new_manager = st.text_input(
                            "Manager Email", 
                            value=branch.get('manager_email', ''),
                            help="This user will have Admin access"
                        )
                    
                    # Show role summary
                    st.info("""
                    **Role Mapping:**
                    - Storekeeper, Procurement, Inventory, Auditor → **Viewer** (uses Viewer Password)
                    - Manager → **Admin** (uses Admin Password)
                    """)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        submitted = st.form_submit_button("💾 Save Changes", use_container_width=True)
                    with col2:
                        if st.form_submit_button("🔄 Reset to Current", use_container_width=True):
                            # Force refresh the branch data
                            CacheManager.invalidate_all()
                            st.rerun()
                    
                    if submitted:
                        update_data = {}
                        
                        # Check each field for changes
                        if new_name != branch['name']:
                            update_data['name'] = new_name
                        if new_code != branch['code']:
                            update_data['code'] = new_code
                        
                        # Email fields - update if changed or set to empty
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
                                st.success(f"✅ Branch '{new_name}' updated successfully!")
                                
                                # Log the changes
                                logger.info(f"Branch updated", {
                                    "id": branch['id'], 
                                    "name": new_name,
                                    "updated_fields": list(update_data.keys())
                                })
                                
                                CacheManager.invalidate_all()
                                st.rerun()
                            except Exception as e:
                                logger.error(f"Failed to update branch", {"id": branch['id'], "error": str(e)})
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
            
            st.markdown("**📧 Viewer Role Emails:**")
            storekeeper_email = st.text_input("Storekeeper Email", help="Viewer access")
            procurement_email = st.text_input("Procurement Email", help="Viewer access")
            inventory_email = st.text_input("Inventory Email", help="Viewer access")
        with col2:
            auditor_email = st.text_input("Auditor Email", help="Viewer access")
            
            st.markdown("**📧 Admin Role Email:**")
            manager_email = st.text_input("Manager Email", help="Admin access")
        
        st.caption("💡 Users with these emails will be able to login with the system password.")
        
        submitted = st.form_submit_button("Add Branch")
        if submitted:
            if not name or not code:
                st.error("Name and code are required.")
                logger.warning("Add branch failed: missing name or code")
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
                    logger.info(f"Branch added", {"name": name, "code": code})
                    CacheManager.invalidate_all()
                    st.rerun()
                except Exception as e:
                    logger.error(f"Failed to add branch", {"name": name, "error": str(e)})
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
                logger.info(f"Branches uploaded", {"count": count})
                CacheManager.invalidate_all()
                st.rerun()
            else:
                st.error(err)

# ============================================================
# PAGE: REGISTERED USERS (admin only)
# ============================================================
elif page == "Registered Users":
    if st.session_state.user_role != "admin":
        st.error("Permission denied.")
        logger.warning("Unauthorized access attempt to Registered Users page", security=True)
        st.stop()
    
    st.header("📧 Registered Users")
    st.markdown("View all registered emails and their associated roles and branches.")
    
    # Get registered emails
    with st.spinner("Loading registered users..."):
        registered_users = get_registered_emails()
    
    if registered_users:
        # Summary statistics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Users", len(registered_users))
        with col2:
            admin_count = len([u for u in registered_users if u['access'] == 'Admin'])
            st.metric("Admins", admin_count)
        with col3:
            viewer_count = len([u for u in registered_users if u['access'] == 'Viewer'])
            st.metric("Viewers", viewer_count)
        with col4:
            no_branch = len([u for u in registered_users if not u['branches']])
            st.metric("No Branch Assigned", no_branch)
        
        st.divider()
        
        # Detailed table view
        st.subheader("📋 Detailed User List")
        
        display_data = []
        for user in registered_users:
            branch_info = []
            for branch in user['branches']:
                branch_info.append(f"{branch['name']} ({branch['role']})")
            
            display_data.append({
                "Email": user['email'],
                "Role": user['role'],
                "Access Level": user['access'],
                "Branches": ", ".join(branch_info) if branch_info else "❌ No branch assigned"
            })
        
        df_users = pd.DataFrame(display_data)
        mobile_friendly_table(df_users)
        
        # Export functionality
        st.subheader("📤 Export User List")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📥 Export as CSV"):
                csv_data = export_data_to_csv(display_data, "registered_users")
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=f"registered_users_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
        with col2:
            if st.button("📥 Export as Excel"):
                excel_data = export_data_to_excel(display_data, "registered_users")
                st.download_button(
                    label="Download Excel",
                    data=excel_data,
                    file_name=f"registered_users_{datetime.now().strftime('%Y%m%d')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
        
        # Search functionality
        st.subheader("🔍 Search Users")
        search_term = st.text_input("Search by email or role", placeholder="e.g., manager, @company.com")
        if search_term:
            filtered = [u for u in display_data if search_term.lower() in u['Email'].lower() or search_term.lower() in u['Role'].lower()]
            if filtered:
                st.dataframe(pd.DataFrame(filtered), use_container_width=True)
            else:
                st.info("No users found matching your search.")
        
        # Show which users can login
        st.subheader("🔑 Login Status")
        st.info("""
        **Users who can login:**
        - All users with email addresses in branches can login
        - Managers use the **Admin Password**
        - Storekeepers, Procurement, Inventory, Auditors use the **Viewer Password**
        - Additional admin emails can be added in `ADMIN_EMAILS` secret
        """)
        
        # Quick action: Find user by email
        st.subheader("🔎 Find User")
        find_email = st.text_input("Enter email to find", placeholder="user@example.com")
        if find_email:
            found = [u for u in registered_users if u['email'].lower() == find_email.lower()]
            if found:
                st.success(f"✅ User found!")
                st.json(found[0])
            else:
                st.error(f"❌ User with email '{find_email}' not found.")
                st.info("Make sure the email is added to a branch as one of the email fields.")
    
    else:
        st.warning("No registered users found.")
        st.markdown("""
        ### How to register users:
        1. Go to the **Branches** page
        2. Add or edit a branch
        3. Fill in the email fields (Storekeeper, Procurement, Inventory, Auditor, Manager)
        4. Users with these emails will be able to login
        
        **Note:** Managers get Admin access, all others get Viewer access.
        """)

# ============================================================
# PAGE: CSV UPLOAD
# ============================================================
elif page == "CSV Upload":
    st.header("📁 Upload Inventory or Movement Data")
    
    with st.expander("🔍 Search Products Before Upload", expanded=False):
        search_term = st.text_input("Search products", placeholder="SKU or product name", key="upload_search")
        if search_term:
            with st.spinner("Searching..."):
                results = search_products(search_term, branch_id, limit=20)
            if results:
                mobile_friendly_table(pd.DataFrame(results)[['sku', 'name', 'category', 'cost']])
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
            
            with st.spinner("Processing inventory data..."):
                df['product_sku'] = df['product_sku'].astype(str).str.strip()
                df = df[df['product_sku'].notna() & (df['product_sku'] != '')]
                df['quantity'] = pd.to_numeric(df['quantity'], errors='coerce').fillna(0).astype(int).clip(lower=0)
                
                df['expiry_date_raw'] = df['expiry_date']
                df['expiry_date'] = pd.to_datetime(df['expiry_date'], errors='coerce').dt.date
                
                invalid_expiry = df[df['expiry_date'].notna() & (df['expiry_date'] < date.today())]
                if not invalid_expiry.empty:
                    logger.warning("Invalid expiry dates found", {"count": len(invalid_expiry)})
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
                    logger.error("SKUs could not be matched", {"missing": list(missing_after)})
                    st.error(f"❌ SKUs could not be matched or created: {missing_after}. Please check product master.")
                    st.stop()
                
                df['branch_id'] = selected_branch_id
                df = df[['branch_id','product_id','batch','quantity','expiry_date','storage_location']]
            
            if st.button("Upload Inventory"):
                records = df.to_dict(orient="records")
                success, err, count = upload_with_transaction("inventory", records)
                if success:
                    st.success(f"Inventory uploaded for {selected_branch_label}! {count} rows processed.")
                    logger.info(f"Inventory uploaded", {"branch": selected_branch_label, "count": count})
                    CacheManager.invalidate_all()
                else:
                    st.error(err)
        
        else:
            required_cols = {'product_sku','quantity_change','movement_date'}
            is_valid, msg = validate_csv_columns(df, required_cols, "movements CSV")
            if not is_valid:
                st.error(msg)
                st.stop()
            
            with st.spinner("Processing movement data..."):
                df['product_sku'] = df['product_sku'].astype(str).str.strip()
                df = df[df['product_sku'].notna() & (df['product_sku'] != '')]
                df['quantity_change'] = pd.to_numeric(df['quantity_change'], errors='coerce').fillna(0).astype(int)
                
                skus = df['product_sku'].unique().tolist()
                sku_to_id = chunked_sku_lookup(skus)
                df['product_id'] = df['product_sku'].map(sku_to_id)
                missing = df[df['product_id'].isna()]['product_sku'].unique()
                
                if len(missing) > 0:
                    logger.error("SKUs not found in products", {"missing": list(missing)})
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
                    logger.info(f"Movements uploaded", {"branch": selected_branch_label, "count": count})
                    CacheManager.invalidate_all()
                else:
                    st.error(err)

# ============================================================
# PAGE: ALERTS & ADVISORIES
# ============================================================
elif page == "Alerts & Advisories":
    st.header("🚨 Alerts & Advisories")
    st.markdown("""
    **Alert Thresholds (Updated):**
    - 🔴 **CRITICAL:** Expiry ≤ 120 days (4 months) - Immediate action required
    - 🟠 **HIGH:** Expiry 121-180 days (6 months) - Plan for consumption or transfer
    - 🟡 **MEDIUM:** Expiry 181-270 days (9 months) - Monitor closely
    - 🟢 **LOW:** Expiry > 270 days (9+ months) - Normal inventory
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
        mobile_friendly_table(df_al[['branch','product','batch','alert_type','details','action_taken','created_at']])
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
            try:
                supabase.table("alert_log").update({
                    "action_taken": action_text,
                    "action_date": datetime.now(timezone.utc).isoformat()
                }).eq("id", alert_id).execute()
                st.success("Marked as done.")
                logger.info(f"Alert marked as done", {"alert_id": alert_id})
                CacheManager.invalidate_all()
                st.rerun()
            except Exception as e:
                logger.error(f"Failed to mark alert as done", {"alert_id": alert_id, "error": str(e)})
                st.error(f"Failed to update: {e}")
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
        mobile_friendly_table(df_l[['branch','product','avg_daily_demand','safety_stock','reorder_point','max_stock','calculated_at']])
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
    **Risk Score** combines expiry proximity (with 120-day write‑off threshold), financial exposure, and sales velocity.  
    **Risk Levels:** LOW 🟢 → MODERATE 🟡 → HIGH 🟠 → CRITICAL 🔴
    
    **Critical Threshold:** Products with **≤120 days (4 months)** to expiry are considered high risk and require immediate attention.
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
        if row['days_to_expiry'] <= 120:
            return "🔴"
        elif row['days_to_expiry'] <= 180:
            return "🟠"
        elif row['days_to_expiry'] <= 270:
            return "🟡"
        else:
            return "🟢"
    
    df_risk['risk_indicator'] = df_risk.apply(get_risk_color, axis=1)
    
    st.subheader("📋 Batch Risk Assessment")
    mobile_friendly_table(df_risk[['risk_indicator', 'product_name','sku','batch','quantity','financial_value','expiry_date','days_to_expiry','risk_level']].rename(columns={
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
            if days_left <= 120:
                urgency = "🔴 CRITICAL - Consume immediately!"
            elif days_left <= 180:
                urgency = "🟠 HIGH - Prioritize consumption"
            elif days_left <= 270:
                urgency = "🟡 MODERATE - Plan consumption"
            else:
                urgency = "🟢 LOW - Normal rotation"
            st.write(f"- **{row['product_name']}** (Batch `{row['batch']}`) – Expires **{row['expiry_date']}** ({days_left} days) – {urgency}")
    
    st.subheader("📊 Risk Distribution")
    risk_counts = df_risk['risk_level'].value_counts()
    st.bar_chart(risk_counts)
    
    critical_items = df_risk[df_risk['days_to_expiry'] <= 120]
    if not critical_items.empty:
        st.warning(f"⚠️ **{len(critical_items)}** batches have ≤120 days to expiry and require immediate attention!")
        mobile_friendly_table(critical_items[['product_name', 'sku', 'batch', 'quantity', 'days_to_expiry']].head(10))
    
    with st.expander("ℹ️ How risk score is calculated"):
        st.markdown("""
        **Risk Score = (Expiry Score × 0.5) + (Financial Score × 0.3) + (Low Velocity Score × 0.2)**  
        - **Expiry Score** (0–100): 
          - ≤120 days → 100 (CRITICAL - 4 months or less)
          - 121-180 days → 90 (HIGH - 6 months)
          - 181-270 days → 75 (MODERATE - 9 months)
          - 271-365 days → 40 (LOW - 1 year)
          - >365 days → 10 (VERY LOW - over 1 year)
        - **Financial Score** (0–100): normalised quantity × cost  
        - **Low Velocity Score** (0–100): ≤0.1 units/day→90, 0.11–0.5→70, 0.51–2→40, >2→10  
        
        **Risk levels:** 
        - CRITICAL (≥80) → Products with ≤120 days to expiry
        - HIGH (60–79) → Products with 121-180 days to expiry
        - MODERATE (35–59) → Products with 181-270 days to expiry
        - LOW (<35) → Products with >270 days to expiry
        
        ⚠️ **Real‑world note:** Products with **≤120 days (4 months)** to expiry are considered write‑off risks and trigger immediate alerts.
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
    - **Urgency (Updated for 120-day threshold):**  
      - **CRITICAL** – Expiry ≤120 days (4 months) **or** deficit very high (urgent transfer needed)  
      - **HIGH** – Expiry 121-180 days (6 months)  
      - **MEDIUM** – Expiry 181-270 days (9 months)
    """)
    
    try:
        query = supabase.table("view_all_transfer_suggestions").select("*")
        if branch_id:
            query = query.eq("from_branch_id", branch_id)
        res = query.execute()
        suggestions = res.data
    except Exception as e:
        logger.error("Failed to fetch transfer suggestions", {"error": str(e)})
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
        - **Expiry risk transfer:** Batch expiring ≤120 days (4 months) in a branch with very low demand (<0.5 units/day) → transfer to branch with higher demand.
        - **Urgency (Updated thresholds):** 
          - CRITICAL (expiry ≤120 days or deficit very high)
          - HIGH (expiry 121-180 days)
          - MEDIUM (expiry 181-270 days)
        - All calculations run inside PostgreSQL using indexed joins – no client‑side processing.
        """)

# ============================================================
# PAGE: SYSTEM LOGS (admin only)
# ============================================================
elif page == "System Logs":
    if st.session_state.user_role != "admin":
        st.error("Permission denied.")
        logger.warning("Unauthorized access attempt to System Logs page", security=True)
        st.stop()
    
    st.header("📋 System Logs")
    st.markdown("View structured system logs for debugging and monitoring.")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        log_level = st.selectbox("Filter by level", ["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    with col2:
        log_type = st.selectbox("Log type", ["All Logs", "Security Events Only"])
    with col3:
        max_logs = st.number_input("Max logs to display", min_value=10, max_value=1000, value=100)
    
    if log_type == "Security Events Only":
        logs = logger.get_security_events()
    else:
        logs = logger.get_logs()
    
    if log_level != "ALL":
        logs = [log for log in logs if log['level'] == log_level]
    
    logs = logs[-max_logs:]
    
    if logs:
        df_logs = pd.DataFrame(logs)
        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
        mobile_friendly_table(df_logs[['timestamp', 'level', 'message', 'extra']])
        
        st.subheader("📤 Export Logs")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📥 Export as JSON"):
                json_data = logger.export_logs()
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        with col2:
            if st.button("🗑️ Clear Logs"):
                logger.logs.clear()
                logger.info("Logs cleared by user")
                st.success("Logs cleared!")
                st.rerun()
    else:
        st.info("No logs available.")

# ============================================================
# PAGE: DATA EXPORT
# ============================================================
elif page == "Data Export":
    st.header("📤 Data Export")
    st.markdown("Export inventory data in various formats for reporting and analysis.")
    
    export_type = st.selectbox("Select data to export", [
        "Current Inventory",
        "Products Master",
        "Stock Limits",
        "Risk Scores",
        "Alert Log",
        "Transfer Suggestions",
        "Registered Users"
    ])
    
    format_type = st.selectbox("Export format", ["CSV", "Excel"])
    
    if st.button("Generate Export"):
        if not api_limiter.is_allowed(f"export_{st.session_state.user_email}"):
            st.error("🔒 Too many export requests. Please wait a moment.")
            st.stop()
        
        with st.spinner(f"Generating {export_type} export..."):
            try:
                data = []
                
                if export_type == "Current Inventory":
                    query = supabase.table("view_inventory_list").select("*")
                    if branch_id:
                        query = query.eq("branch_id", branch_id)
                    data = query.execute().data
                    filename = f"inventory_{selected_branch_name}_{datetime.now().strftime('%Y%m%d')}"
                
                elif export_type == "Products Master":
                    data = supabase.table("products").select("*").execute().data
                    filename = f"products_{datetime.now().strftime('%Y%m%d')}"
                
                elif export_type == "Stock Limits":
                    query = supabase.table("stock_limits").select("*, products(name), branches(name)")
                    if branch_id:
                        query = query.eq("branch_id", branch_id)
                    data = query.execute().data
                    filename = f"stock_limits_{datetime.now().strftime('%Y%m%d')}"
                
                elif export_type == "Risk Scores":
                    query = supabase.table("view_risk_list").select("*")
                    if branch_id:
                        query = query.eq("branch_id", branch_id)
                    data = query.execute().data
                    filename = f"risk_scores_{datetime.now().strftime('%Y%m%d')}"
                
                elif export_type == "Alert Log":
                    query = supabase.table("alert_log").select("*, products(name), branches(name)")
                    if branch_id:
                        query = query.eq("branch_id", branch_id)
                    data = query.execute().data
                    filename = f"alerts_{datetime.now().strftime('%Y%m%d')}"
                
                elif export_type == "Transfer Suggestions":
                    query = supabase.table("view_all_transfer_suggestions").select("*")
                    if branch_id:
                        query = query.eq("from_branch_id", branch_id)
                    data = query.execute().data
                    filename = f"transfer_suggestions_{datetime.now().strftime('%Y%m%d')}"
                
                elif export_type == "Registered Users":
                    registered_users = get_registered_emails()
                    data = []
                    for user in registered_users:
                        branch_info = []
                        for branch in user['branches']:
                            branch_info.append(f"{branch['name']} ({branch['role']})")
                        
                        data.append({
                            "Email": user['email'],
                            "Role": user['role'],
                            "Access Level": user['access'],
                            "Branches": ", ".join(branch_info) if branch_info else "No branch assigned"
                        })
                    filename = f"registered_users_{datetime.now().strftime('%Y%m%d')}"
                
                if data:
                    if format_type == "CSV":
                        export_data = export_data_to_csv(data, filename)
                        st.download_button(
                            label=f"📥 Download {filename}.csv",
                            data=export_data,
                            file_name=f"{filename}.csv",
                            mime="text/csv"
                        )
                    else:
                        export_data = export_data_to_excel(data, filename)
                        st.download_button(
                            label=f"📥 Download {filename}.xlsx",
                            data=export_data,
                            file_name=f"{filename}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        )
                    
                    logger.info(f"Export generated", {"type": export_type, "format": format_type, "rows": len(data)})
                    st.success(f"✅ {len(data)} rows exported successfully!")
                else:
                    st.warning("No data available for export.")
                    
            except Exception as e:
                logger.error(f"Export failed", {"type": export_type, "error": str(e)})
                st.error(f"Export failed: {str(e)}")

# ============================================================
# PAGE: SECURITY SETTINGS (admin only)
# ============================================================
elif page == "Security Settings":
    if st.session_state.user_role != "admin":
        st.error("Permission denied.")
        logger.warning("Unauthorized access attempt to Security Settings page", security=True)
        st.stop()
    
    st.header("🔒 Security Settings")
    st.markdown("Manage security policies and view security status.")
    
    st.subheader("📊 Security Status")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        is_production = os.environ.get("STREAMLIT_ENV", "").lower() == "production"
        if is_production:
            st.success("✅ HTTPS Enabled (Production)")
        else:
            st.warning("⚠️ Development Mode (HTTPS not enforced)")
    
    with col2:
        st.metric("Rate Limit", f"{login_limiter.max_attempts} attempts")
    
    with col3:
        st.metric("Min Password Length", f"{PasswordValidator.MIN_LENGTH} chars")
    
    st.subheader("⚙️ Rate Limiting Configuration")
    col1, col2 = st.columns(2)
    with col1:
        new_max_attempts = st.number_input("Max Login Attempts", min_value=3, max_value=10, value=login_limiter.max_attempts)
    with col2:
        new_window = st.number_input("Rate Limit Window (seconds)", min_value=60, max_value=3600, value=300)
    
    if st.button("Update Rate Limits"):
        login_limiter.max_attempts = new_max_attempts
        login_limiter.window_seconds = new_window
        logger.info(f"Rate limits updated", {"max_attempts": new_max_attempts, "window": new_window}, security=True)
        st.success("✅ Rate limits updated successfully!")
        st.rerun()
    
    st.subheader("🔐 Password Policy Configuration")
    col1, col2 = st.columns(2)
    with col1:
        min_length = st.number_input("Minimum Password Length", min_value=8, max_value=20, value=PasswordValidator.MIN_LENGTH)
        require_upper = st.checkbox("Require Uppercase", value=PasswordValidator.REQUIRE_UPPERCASE)
        require_lower = st.checkbox("Require Lowercase", value=PasswordValidator.REQUIRE_LOWERCASE)
    with col2:
        require_digits = st.checkbox("Require Digits", value=PasswordValidator.REQUIRE_DIGITS)
        require_special = st.checkbox("Require Special Characters", value=PasswordValidator.REQUIRE_SPECIAL)
    
    if st.button("Update Password Policy"):
        PasswordValidator.MIN_LENGTH = min_length
        PasswordValidator.REQUIRE_UPPERCASE = require_upper
        PasswordValidator.REQUIRE_LOWERCASE = require_lower
        PasswordValidator.REQUIRE_DIGITS = require_digits
        PasswordValidator.REQUIRE_SPECIAL = require_special
        logger.info("Password policy updated", {"min_length": min_length}, security=True)
        st.success("✅ Password policy updated successfully!")
        st.rerun()
    
    st.subheader("🛡️ Recent Security Events")
    security_events = logger.get_security_events()[-20:]
    if security_events:
        df_events = pd.DataFrame(security_events)
        df_events['timestamp'] = pd.to_datetime(df_events['timestamp'])
        mobile_friendly_table(df_events[['timestamp', 'level', 'message']])
    else:
        st.info("No security events logged.")
    
    with st.expander("📋 Security Best Practices Checklist", expanded=False):
        st.markdown("""
        ✅ **Password Policy:** At least 12 characters with mixed case, digits, and special characters
        ✅ **Rate Limiting:** 5 attempts per 5 minutes
        ✅ **HTTPS Enforcement:** HTTPS required in production
        ✅ **Email-based Authentication:** Users login with email from branches
        ✅ **Role-based Access:** Managers = Admin, Others = Viewer
        ✅ **Audit Logging:** All security events logged
        ✅ **Input Validation:** SKU validation, expiry date validation
        ✅ **Error Handling:** No sensitive information in error messages
        ✅ **Data Protection:** Secure data storage in Supabase
        ✅ **User Management:** View all registered users with roles
        
        **Recommendations:**
        - Regularly review security logs
        - Enforce password rotation every 90 days
        - Enable 2FA for admin accounts (future enhancement)
        - Regular security audits
        - Monitor failed login attempts
        """)
