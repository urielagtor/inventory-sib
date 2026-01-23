import streamlit as st
import sqlite3
import hashlib
import os
import hmac
import secrets
from datetime import date, datetime
import pandas as pd

APP_TITLE = "SIB Inventory Supply Checkout System"
DB_PATH = "inventory_checkout.db"

# ---------------------------
# Security / Password hashing
# ---------------------------
# PBKDF2-HMAC-SHA256 with per-user salt
PBKDF2_ITERS = 200_000

def _pbkdf2_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _pbkdf2_hash(password, salt)
    return f"{salt.hex()}:{digest.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        got = _pbkdf2_hash(password, salt)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False

# ---------------------------
# Database
# ---------------------------

LOGO_LIGHT_URL = "https://www.asoit.org/ASOIT_Logo_Regular.png"
LOGO_DARK_URL  = "https://www.asoit.org/ASOIT_Logo_DarkBg.png"

def render_sidebar_logo():
    # Streamlit 1.53+: st.context.theme.type -> "light" or "dark"
    theme_type = None
    try:
        theme_type = st.context.theme.get("type", None)  # dict-like
    except Exception:
        theme_type = None

    logo = LOGO_DARK_URL if theme_type == "dark" else LOGO_LIGHT_URL

    with st.sidebar:
        st.image(logo, use_container_width=True)

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',         -- 'admin' or 'user'
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    # Categories
    cur.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    # Items
    cur.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            category_id INTEGER,
            total_qty INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(category_id) REFERENCES categories(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    # Checkout "header"
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checkouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checkout_date TEXT NOT NULL,
            expected_return_date TEXT NOT NULL,
            borrower_name TEXT NOT NULL,
            borrower_email TEXT NOT NULL,
            borrower_group TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            actual_return_date TEXT,                   -- if fully returned, optional convenience
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    # Checkout line items
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checkout_lines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checkout_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,
            returned_qty INTEGER NOT NULL DEFAULT 0,
            returned_at TEXT,                          -- when last updated (optional)
            FOREIGN KEY(checkout_id) REFERENCES checkouts(id),
            FOREIGN KEY(item_id) REFERENCES items(id)
        )
    """)

    conn.commit()

    # Create default admin if none exists
    cur.execute("SELECT COUNT(*) as c FROM users WHERE role='admin'")
    if cur.fetchone()["c"] == 0:
        default_user = "admin"
        default_pass = "admin123"
        cur.execute("""
            INSERT INTO users (username, password_hash, role, active, created_at)
            VALUES (?, ?, 'admin', 1, ?)
        """, (default_user, hash_password(default_pass), datetime.utcnow().isoformat()))
        conn.commit()

    conn.close()

# ---------------------------
# Data helpers
# ---------------------------
def fetch_one(query, params=()):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(query, params)
    row = cur.fetchone()
    conn.close()
    return row

def fetch_all(query, params=()):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows

def execute(query, params=()):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()
    last_id = cur.lastrowid
    conn.close()
    return last_id

def execute_many(query, params_list):
    conn = get_conn()
    cur = conn.cursor()
    cur.executemany(query, params_list)
    conn.commit()
    conn.close()

def is_admin():
    return st.session_state.get("role") == "admin"

def require_login():
    if not st.session_state.get("logged_in"):
        st.warning("Please log in to continue.")
        st.stop()

def now_iso():
    return datetime.utcnow().isoformat()

# ---------------------------
# Inventory availability math
# ---------------------------
def get_outstanding_by_item():
    """
    Returns dict[item_id] = outstanding_qty (checked out but not returned).
    """
    rows = fetch_all("""
        SELECT item_id,
               SUM(qty - returned_qty) AS outstanding
        FROM checkout_lines
        GROUP BY item_id
    """)
    out = {}
    for r in rows:
        out[r["item_id"]] = int(r["outstanding"] or 0)
    return out

def get_available_qty(item_id: int) -> int:
    item = fetch_one("SELECT total_qty FROM items WHERE id=?", (item_id,))
    if not item:
        return 0
    total = int(item["total_qty"])
    outstanding = get_outstanding_by_item().get(item_id, 0)
    return max(total - outstanding, 0)

# ---------------------------
# UI Pages
# ---------------------------
def page_login():
    st.title(APP_TITLE)
    st.subheader("Login")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")

    if submitted:
        row = fetch_one("SELECT * FROM users WHERE username=?", (username.strip(),))
        if not row:
            st.error("Invalid username or password.")
            return
        if row["active"] != 1:
            st.error("Account is deactivated. Contact an admin.")
            return
        if not verify_password(password, row["password_hash"]):
            st.error("Invalid username or password.")
            return

        st.session_state.logged_in = True
        st.session_state.user_id = row["id"]
        st.session_state.username = row["username"]
        st.session_state.role = row["role"]
        st.success(f"Welcome, {row['username']}!")
        st.rerun()

def page_admin_users():
    require_login()
    if not is_admin():
        st.error("Admins only.")
        st.stop()

    st.header("Admin: User Management")

    st.caption("Create users, reset passwords, and activate/deactivate accounts.")

    # List users
    users = fetch_all("SELECT id, username, role, active, created_at FROM users ORDER BY role DESC, username ASC")
    df = pd.DataFrame([dict(u) for u in users]) if users else pd.DataFrame(columns=["id","username","role","active","created_at"])
    if not df.empty:
        df["active"] = df["active"].map(lambda x: "Yes" if x == 1 else "No")
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()

    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.subheader("Create user")
        with st.form("create_user"):
            new_username = st.text_input("Username", key="new_username")
            new_password = st.text_input("Password", type="password", key="new_password")
            new_role = st.selectbox("Role", ["user", "admin"], index=0)
            create = st.form_submit_button("Create")
        if create:
            u = new_username.strip()
            if not u:
                st.error("Username required.")
            elif len(new_password) < 6:
                st.error("Use a password of at least 6 characters.")
            else:
                try:
                    execute("""
                        INSERT INTO users (username, password_hash, role, active, created_at)
                        VALUES (?, ?, ?, 1, ?)
                    """, (u, hash_password(new_password), new_role, now_iso()))
                    st.success("User created.")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("That username already exists.")

    with col2:
        st.subheader("Manage existing user")
        user_options = [(u["id"], u["username"]) for u in users]
        if not user_options:
            st.info("No users found.")
            return

        selected_id = st.selectbox("Select user", options=[x[0] for x in user_options],
                                   format_func=lambda uid: dict(user_options).get(uid, str(uid)))
        selected = fetch_one("SELECT * FROM users WHERE id=?", (selected_id,))
        if not selected:
            st.warning("User not found.")
            return

        st.write(f"**Role:** {selected['role']}")
        st.write(f"**Active:** {'Yes' if selected['active']==1 else 'No'}")

        with st.form("manage_user"):
            reset_pw = st.text_input("Reset password (optional)", type="password")
            new_role2 = st.selectbox("Change role", ["user", "admin"], index=0 if selected["role"]=="user" else 1)
            active2 = st.selectbox("Active?", ["Yes", "No"], index=0 if selected["active"]==1 else 1)
            save = st.form_submit_button("Save changes")

        if save:
            updates = []
            params = []
            updates.append("role=?")
            params.append(new_role2)
            updates.append("active=?")
            params.append(1 if active2 == "Yes" else 0)

            if reset_pw.strip():
                if len(reset_pw) < 6:
                    st.error("Password must be at least 6 characters.")
                    return
                updates.append("password_hash=?")
                params.append(hash_password(reset_pw))

            params.append(selected_id)
            execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", tuple(params))
            st.success("User updated.")
            st.rerun()

def page_categories():
    require_login()
    st.header("Categories")

    cats = fetch_all("SELECT * FROM categories ORDER BY name ASC")
    cat_df = pd.DataFrame([dict(c) for c in cats]) if cats else pd.DataFrame(columns=["id","name","created_at"])
    if not cat_df.empty:
        cat_df = cat_df[["id","name","created_at"]]
    st.dataframe(cat_df, use_container_width=True, hide_index=True)

    st.divider()

    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.subheader("Create category")
        with st.form("create_cat"):
            name = st.text_input("Category name")
            create = st.form_submit_button("Create")
        if create:
            n = name.strip()
            if not n:
                st.error("Name required.")
            else:
                try:
                    execute("""
                        INSERT INTO categories (name, created_by, created_at)
                        VALUES (?, ?, ?)
                    """, (n, st.session_state.user_id, now_iso()))
                    st.success("Category created.")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("That category already exists.")

    with col2:
        st.subheader("Rename / Delete")
        if not cats:
            st.info("Create a category first.")
        else:
            cat_map = {c["name"]: c["id"] for c in cats}
            selected_name = st.selectbox("Select category", list(cat_map.keys()))
            selected_id = cat_map[selected_name]

            with st.form("rename_cat"):
                new_name = st.text_input("New name", value=selected_name)
                do_rename = st.form_submit_button("Rename")
            if do_rename:
                nn = new_name.strip()
                if not nn:
                    st.error("New name required.")
                else:
                    try:
                        execute("UPDATE categories SET name=? WHERE id=?", (nn, selected_id))
                        st.success("Renamed.")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("A category with that name already exists.")

            with st.form("delete_cat"):
                st.warning("Deleting a category will NOT delete items, but items will lose their category assignment.")
                confirm = st.checkbox("I understand", value=False)
                do_delete = st.form_submit_button("Delete category")
            if do_delete:
                if not confirm:
                    st.error("Please confirm.")
                else:
                    execute("UPDATE items SET category_id=NULL WHERE category_id=?", (selected_id,))
                    execute("DELETE FROM categories WHERE id=?", (selected_id,))
                    st.success("Deleted.")
                    st.rerun()

def page_items():
    require_login()
    st.header("Items")

    cats = fetch_all("SELECT id, name FROM categories ORDER BY name ASC")
    cat_lookup = {c["id"]: c["name"] for c in cats}

    outstanding = get_outstanding_by_item()

    items = fetch_all("""
        SELECT i.id, i.name, i.category_id, i.total_qty, i.notes, i.created_at
        FROM items i
        ORDER BY i.name ASC
    """)
    rows = []
    for it in items:
        out = int(outstanding.get(it["id"], 0))
        total = int(it["total_qty"])
        avail = max(total - out, 0)
        rows.append({
            "id": it["id"],
            "name": it["name"],
            "category": cat_lookup.get(it["category_id"], ""),
            "total_qty": total,
            "checked_out": out,
            "available": avail,
            "notes": it["notes"] or "",
            "created_at": it["created_at"],
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["id","name","category","total_qty","checked_out","available","notes","created_at"])
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()

    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.subheader("Create item")
        with st.form("create_item"):
            name = st.text_input("Item name")
            category = st.selectbox("Category (optional)", ["(none)"] + [c["name"] for c in cats])
            total_qty = st.number_input("Total available quantity", min_value=0, step=1, value=0)
            notes = st.text_area("Notes (optional)")
            create = st.form_submit_button("Create")
        if create:
            n = name.strip()
            if not n:
                st.error("Name required.")
            else:
                cat_id = None
                if category != "(none)":
                    cat_id = fetch_one("SELECT id FROM categories WHERE name=?", (category,))["id"]
                try:
                    execute("""
                        INSERT INTO items (name, category_id, total_qty, notes, created_by, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (n, cat_id, int(total_qty), notes.strip() or None, st.session_state.user_id, now_iso()))
                    st.success("Item created.")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("That item already exists.")

    with col2:
        st.subheader("Update / Delete item")
        if not items:
            st.info("Create an item first.")
        else:
            item_map = {it["name"]: it["id"] for it in items}
            selected_name = st.selectbox("Select item", list(item_map.keys()))
            item_id = item_map[selected_name]
            it = fetch_one("SELECT * FROM items WHERE id=?", (item_id,))
            if not it:
                st.warning("Item not found.")
                return

            current_cat = "(none)"
            if it["category_id"] and it["category_id"] in cat_lookup:
                current_cat = cat_lookup[it["category_id"]]

            with st.form("update_item"):
                new_name = st.text_input("Name", value=it["name"])
                new_cat = st.selectbox("Category", ["(none)"] + [c["name"] for c in cats],
                                       index=(["(none)"] + [c["name"] for c in cats]).index(current_cat) if current_cat in (["(none)"] + [c["name"] for c in cats]) else 0)
                new_total = st.number_input("Total qty", min_value=0, step=1, value=int(it["total_qty"]))
                new_notes = st.text_area("Notes", value=it["notes"] or "")
                save = st.form_submit_button("Save changes")

            if save:
                nn = new_name.strip()
                if not nn:
                    st.error("Name required.")
                else:
                    cat_id = None
                    if new_cat != "(none)":
                        cat_id = fetch_one("SELECT id FROM categories WHERE name=?", (new_cat,))["id"]
                    try:
                        execute("""
                            UPDATE items
                            SET name=?, category_id=?, total_qty=?, notes=?
                            WHERE id=?
                        """, (nn, cat_id, int(new_total), new_notes.strip() or None, item_id))
                        st.success("Updated.")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Another item already uses that name.")

            with st.form("delete_item"):
                st.warning("Cannot delete an item if it has outstanding checkouts.")
                confirm = st.checkbox("I understand", value=False, key="del_item_confirm")
                do_delete = st.form_submit_button("Delete item")
            if do_delete:
                if not confirm:
                    st.error("Please confirm.")
                else:
                    out = get_outstanding_by_item().get(item_id, 0)
                    if out > 0:
                        st.error(f"Item has {out} still checked out; return them first.")
                    else:
                        execute("DELETE FROM items WHERE id=?", (item_id,))
                        st.success("Deleted.")
                        st.rerun()

def page_checkout():
    require_login()
    st.header("Checkout Supplies")

    items = fetch_all("SELECT id, name, total_qty FROM items ORDER BY name ASC")
    if not items:
        st.info("No items found. Add items first.")
        return

    outstanding = get_outstanding_by_item()
    item_options = []
    for it in items:
        out = int(outstanding.get(it["id"], 0))
        total = int(it["total_qty"])
        avail = max(total - out, 0)
        label = f"{it['name']} (available: {avail} / total: {total})"
        item_options.append((it["id"], label, avail))

    st.caption("Build a checkout cart (multiple items), then submit as one checkout record.")

    # "Cart" stored in session
    if "cart" not in st.session_state:
        st.session_state.cart = []  # list of dict: {item_id, item_label, qty}

    with st.expander("1) Borrower details & dates", expanded=True):
        colA, colB = st.columns(2, gap="large")
        with colA:
            borrower_name = st.text_input("Borrower name", key="borrower_name")
            borrower_email = st.text_input("Borrower email", key="borrower_email")
            borrower_group = st.text_input("Group / organization", key="borrower_group")
        with colB:
            checkout_date = st.date_input("Checkout date", value=date.today(), key="checkout_date")
            expected_return = st.date_input("Expected return date", value=date.today(), key="expected_return")

    with st.expander("2) Add items to checkout cart", expanded=True):
        col1, col2, col3 = st.columns([3, 1, 1], gap="large")

        id_list = [x[0] for x in item_options]
        label_map = {x[0]: x[1] for x in item_options}
        avail_map = {x[0]: x[2] for x in item_options}

        with col1:
            selected_item_id = st.selectbox(
                "Item",
                options=id_list,
                format_func=lambda i: label_map[i],
                key="selected_item_id"
            )
        with col2:
            max_avail = int(avail_map.get(selected_item_id, 0))
            qty = st.number_input("Qty", min_value=1, step=1, value=1, max_value=max(1, max_avail), key="selected_qty")
        with col3:
            add = st.button("Add to cart", use_container_width=True)

        if add:
            max_avail = int(avail_map.get(selected_item_id, 0))
            if max_avail <= 0:
                st.error("No quantity available for this item.")
            elif int(qty) > max_avail:
                st.error(f"Only {max_avail} available.")
            else:
                # If already in cart, increment but do not exceed availability (simple check)
                found = False
                for line in st.session_state.cart:
                    if line["item_id"] == selected_item_id:
                        new_qty = line["qty"] + int(qty)
                        if new_qty > max_avail:
                            st.error(f"Cart already has {line['qty']}. Max available is {max_avail}.")
                        else:
                            line["qty"] = new_qty
                            st.success("Updated quantity in cart.")
                        found = True
                        break
                if not found:
                    st.session_state.cart.append({
                        "item_id": selected_item_id,
                        "item_label": label_map[selected_item_id],
                        "qty": int(qty),
                    })
                    st.success("Added to cart.")
                st.rerun()

        # Show cart
        st.subheader("Current cart")
        if not st.session_state.cart:
            st.info("Cart is empty.")
        else:
            cart_df = pd.DataFrame([{"item": c["item_label"], "qty": c["qty"]} for c in st.session_state.cart])
            st.dataframe(cart_df, use_container_width=True, hide_index=True)

            colx, coly = st.columns([1, 1], gap="large")
            with colx:
                if st.button("Clear cart", use_container_width=True):
                    st.session_state.cart = []
                    st.rerun()
            with coly:
                remove_idx = st.number_input("Remove line # (1..n)", min_value=1, step=1, value=1, max_value=len(st.session_state.cart))
                if st.button("Remove line", use_container_width=True):
                    idx = int(remove_idx) - 1
                    if 0 <= idx < len(st.session_state.cart):
                        st.session_state.cart.pop(idx)
                        st.rerun()

    st.divider()
    st.subheader("3) Submit checkout")

    if st.button("Submit checkout", type="primary", use_container_width=True):
        # Validate
        if not borrower_name.strip():
            st.error("Borrower name is required.")
            return
        if not borrower_email.strip():
            st.error("Borrower email is required.")
            return
        if not borrower_group.strip():
            st.error("Borrower group/organization is required.")
            return
        if expected_return < checkout_date:
            st.error("Expected return date cannot be before checkout date.")
            return
        if not st.session_state.cart:
            st.error("Add at least one item to the cart.")
            return

        # Re-check availability at submit time (race-safety for multi-user local)
        for c in st.session_state.cart:
            avail = get_available_qty(c["item_id"])
            if c["qty"] > avail:
                st.error(f"Not enough available for: {c['item_label']} (need {c['qty']}, available {avail})")
                return

        # Create checkout header
        checkout_id = execute("""
            INSERT INTO checkouts (
                checkout_date, expected_return_date,
                borrower_name, borrower_email, borrower_group,
                created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            checkout_date.isoformat(),
            expected_return.isoformat(),
            borrower_name.strip(),
            borrower_email.strip(),
            borrower_group.strip(),
            st.session_state.user_id,
            now_iso()
        ))

        # Insert lines
        params = []
        for c in st.session_state.cart:
            params.append((checkout_id, c["item_id"], int(c["qty"])))
        execute_many("""
            INSERT INTO checkout_lines (checkout_id, item_id, qty)
            VALUES (?, ?, ?)
        """, params)

        st.session_state.cart = []
        st.success(f"Checkout submitted (ID: {checkout_id}).")
        st.rerun()

def page_checked_out():
    require_login()
    st.header("Currently Checked Out")

    # All outstanding lines
    rows = fetch_all("""
        SELECT
            co.id AS checkout_id,
            co.checkout_date,
            co.expected_return_date,
            co.borrower_name,
            co.borrower_email,
            co.borrower_group,
            co.created_at,
            u.username AS created_by_username,
            i.name AS item_name,
            cl.id AS line_id,
            cl.qty,
            cl.returned_qty,
            (cl.qty - cl.returned_qty) AS outstanding_qty
        FROM checkout_lines cl
        JOIN checkouts co ON co.id = cl.checkout_id
        JOIN items i ON i.id = cl.item_id
        JOIN users u ON u.id = co.created_by
        WHERE (cl.qty - cl.returned_qty) > 0
        ORDER BY co.checkout_date DESC, co.id DESC, i.name ASC
    """)

    if not rows:
        st.success("Nothing is currently checked out.")
        return

    df = pd.DataFrame([dict(r) for r in rows])
    # Make it nice
    df = df[[
        "checkout_id", "checkout_date", "expected_return_date",
        "borrower_name", "borrower_email", "borrower_group",
        "item_name", "outstanding_qty",
        "created_by_username"
    ]]
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Return items (update actual return date per line)")

    # Select a line to return
    # Build options for returning
    return_rows = fetch_all("""
        SELECT
            cl.id AS line_id,
            co.id AS checkout_id,
            i.name AS item_name,
            co.borrower_name,
            (cl.qty - cl.returned_qty) AS outstanding_qty
        FROM checkout_lines cl
        JOIN checkouts co ON co.id = cl.checkout_id
        JOIN items i ON i.id = cl.item_id
        WHERE (cl.qty - cl.returned_qty) > 0
        ORDER BY co.id DESC, i.name ASC
    """)
    option_ids = [r["line_id"] for r in return_rows]
    label_map = {
        r["line_id"]: f"Checkout #{r['checkout_id']} — {r['item_name']} — {r['borrower_name']} (outstanding: {r['outstanding_qty']})"
        for r in return_rows
    }
    selected_line_id = st.selectbox("Select a checkout line", option_ids, format_func=lambda x: label_map[x])

    line = fetch_one("""
        SELECT cl.id, cl.checkout_id, cl.item_id, cl.qty, cl.returned_qty,
               co.checkout_date, co.expected_return_date,
               co.borrower_name, i.name AS item_name
        FROM checkout_lines cl
        JOIN checkouts co ON co.id = cl.checkout_id
        JOIN items i ON i.id = cl.item_id
        WHERE cl.id=?
    """, (selected_line_id,))
    if not line:
        st.error("Line not found.")
        return

    outstanding = int(line["qty"] - line["returned_qty"])
    st.write(f"**Selected:** Checkout #{line['checkout_id']} — {line['item_name']} — {line['borrower_name']}")
    st.write(f"**Outstanding quantity:** {outstanding}")

    with st.form("return_form"):
        return_qty = st.number_input("Quantity being returned now", min_value=1, max_value=max(1, outstanding), step=1, value=min(1, outstanding))
        actual_return = st.date_input("Actual return date", value=date.today())
        submit = st.form_submit_button("Record return")

    if submit:
        if outstanding <= 0:
            st.error("Nothing outstanding for this line.")
            return
        if int(return_qty) > outstanding:
            st.error("Cannot return more than outstanding.")
            return

        new_returned = int(line["returned_qty"]) + int(return_qty)
        execute("""
            UPDATE checkout_lines
            SET returned_qty=?, returned_at=?
            WHERE id=?
        """, (new_returned, datetime.combine(actual_return, datetime.min.time()).isoformat(), selected_line_id))

        # If the entire checkout has no outstanding lines, set a convenience actual_return_date on header
        remain = fetch_one("""
            SELECT SUM(qty - returned_qty) AS remain
            FROM checkout_lines
            WHERE checkout_id=?
        """, (line["checkout_id"],))
        remain_qty = int(remain["remain"] or 0)
        if remain_qty == 0:
            execute("""
                UPDATE checkouts
                SET actual_return_date=?
                WHERE id=?
            """, (actual_return.isoformat(), line["checkout_id"]))

        st.success("Return recorded.")
        st.rerun()

def page_reports():
    require_login()
    st.header("Reports")

    st.subheader("Inventory snapshot")
    rows = fetch_all("""
        SELECT i.id, i.name, i.total_qty, c.name AS category
        FROM items i
        LEFT JOIN categories c ON c.id = i.category_id
        ORDER BY i.name ASC
    """)
    outstanding = get_outstanding_by_item()
    data = []
    for r in rows:
        out = int(outstanding.get(r["id"], 0))
        total = int(r["total_qty"])
        avail = max(total - out, 0)
        data.append({
            "item": r["name"],
            "category": r["category"] or "",
            "total_qty": total,
            "checked_out": out,
            "available": avail,
        })
    df = pd.DataFrame(data) if data else pd.DataFrame(columns=["item","category","total_qty","checked_out","available"])
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Checkout history (latest 200)")
    hist = fetch_all("""
        SELECT
            co.id AS checkout_id,
            co.checkout_date,
            co.expected_return_date,
            co.actual_return_date,
            co.borrower_name,
            co.borrower_email,
            co.borrower_group,
            u.username AS created_by,
            co.created_at
        FROM checkouts co
        JOIN users u ON u.id = co.created_by
        ORDER BY co.id DESC
        LIMIT 200
    """)
    hdf = pd.DataFrame([dict(r) for r in hist]) if hist else pd.DataFrame(columns=[
        "checkout_id","checkout_date","expected_return_date","actual_return_date",
        "borrower_name","borrower_email","borrower_group","created_by","created_at"
    ])
    st.dataframe(hdf, use_container_width=True, hide_index=True)

def page_logout():
    st.session_state.clear()
    st.success("Logged out.")
    st.rerun()

# ---------------------------
# App Shell
# ---------------------------
def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")

    init_db()

    st.session_state.setdefault("logged_in", False)
    st.session_state.setdefault("user_id", None)
    st.session_state.setdefault("username", None)
    st.session_state.setdefault("role", None)

    # ✅ Logo at the very top of the sidebar, theme-aware
    render_sidebar_logo()

    if not st.session_state.logged_in:
        page_login()
        return

       # Sidebar navigation
    with st.sidebar:




        st.markdown(f"### {APP_TITLE}")
        st.write(f"Logged in as **{st.session_state.username}** ({st.session_state.role})")
        st.divider()

        pages = ["Checkout", "Currently Checked Out", "Items", "Categories", "Reports"]
        if is_admin():
            pages.insert(0, "Admin: Users")
        pages.append("Logout")

        choice = st.radio("Navigation", pages, label_visibility="collapsed")


    if choice == "Admin: Users":
        page_admin_users()
    elif choice == "Categories":
        page_categories()
    elif choice == "Items":
        page_items()
    elif choice == "Checkout":
        page_checkout()
    elif choice == "Currently Checked Out":
        page_checked_out()
    elif choice == "Reports":
        page_reports()
    elif choice == "Logout":
        page_logout()

if __name__ == "__main__":
    main()
