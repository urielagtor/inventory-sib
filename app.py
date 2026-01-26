import streamlit as st
import sqlite3
import hashlib
import hmac
import secrets
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo
import pandas as pd

# ✅ PDF
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

APP_TITLE = "SIB Inventory Supply Checkout System!"
DB_PATH = "inventory_checkout.db"

# ---------------------------
# Security / Password hashing
# ---------------------------
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

# ------------------------------
# BREAK GLASS (token-gated)
# ------------------------------
def reset_admin_password_to_default():
    token_expected = st.secrets.get("admin_reset", {}).get("token")
    default_pw = st.secrets.get("admin_reset", {}).get("default_password", "admin123")

    if not token_expected:
        st.error("Admin reset is not configured (missing admin_reset.token in Secrets).")
        return

    st.subheader("Emergency admin reset")
    st.caption("This will set the 'admin' password back to the default and re-activate the account.")

    entered = st.text_input("Reset token", type="password", key="admin_reset_token_entered")
    if st.button("Reset admin password", type="primary", use_container_width=True):
        if entered != token_expected:
            st.error("Invalid reset token.")
            return

        row = fetch_one("SELECT id FROM users WHERE username=?", ("admin",))
        if not row:
            st.error("No 'admin' user found in the database.")
            return

        execute(
            "UPDATE users SET password_hash=?, active=1 WHERE username=?",
            (hash_password(default_pw), "admin")
        )
        st.success("Admin password reset. You can now log in with the default password.")

# ---------------------------
# PDF helpers
# ---------------------------
def build_table_pdf(title: str, subtitle_lines: list[str], table_data, col_widths=None) -> bytes:
    """
    table_data should be a list of rows (including header row),
    where cells can be strings or ReportLab Paragraphs.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    story = []
    story.append(Paragraph(title, styles["Title"]))
    story.append(Spacer(1, 10))

    for line in subtitle_lines:
        story.append(Paragraph(line, styles["Normal"]))
    story.append(Spacer(1, 12))

    if not table_data or len(table_data) <= 1:
        story.append(Paragraph("No records found.", styles["Normal"]))
        doc.build(story)
        return buffer.getvalue()

    table = Table(table_data, repeatRows=1, colWidths=col_widths)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))

    story.append(table)
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

def build_ticket_pdf(checkout_id: int) -> bytes:
    """
    Printable PDF for ANY ticket (open or closed),
    includes return log per line.
    """
    styles = getSampleStyleSheet()

    header = fetch_one("""
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
        WHERE co.id = ?
    """, (checkout_id,))
    if not header:
        return build_table_pdf(
            "Ticket",
            [f"Ticket #{checkout_id}", "Not found."],
            [["Message"], ["Ticket not found."]]
        )

    # Lines (include returned/outstanding)
    lines = fetch_all("""
        SELECT
            cl.id AS line_id,
            i.name AS item_name,
            cl.qty,
            cl.returned_qty,
            (cl.qty - cl.returned_qty) AS outstanding_qty
        FROM checkout_lines cl
        JOIN items i ON i.id = cl.item_id
        WHERE cl.checkout_id = ?
        ORDER BY i.name ASC
    """, (checkout_id,))

    # Return events (audit log)
    events = fetch_all("""
        SELECT
            re.line_id,
            re.qty AS returned_qty,
            re.returned_at,
            u.username AS returned_by
        FROM return_events re
        JOIN users u ON u.id = re.returned_by
        WHERE re.checkout_id = ?
        ORDER BY re.returned_at ASC, re.id ASC
    """, (checkout_id,))

    # Map line_id -> list of "when by who: qty"
    ev_map = {}
    for e in events:
        lid = int(e["line_id"])
        when = to_local_display(e["returned_at"])
        who = str(e["returned_by"])
        qty = int(e["returned_qty"] or 0)
        ev_map.setdefault(lid, []).append(f"{when} — {who} — qty {qty}")

    subtitle = [
        f"Ticket #: {header['checkout_id']}",
        f"Borrower: {header['borrower_name']} ({header['borrower_email']})",
        f"Group: {header['borrower_group']}",
        f"Checkout date: {header['checkout_date']}    Expected return: {header['expected_return_date']}",
        f"Recorded by: {header['created_by']}    Created at: {to_local_display(header['created_at'])}",
        f"Actual return date: {header['actual_return_date'] or '(not fully returned yet)'}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]

    # Build table rows with wrapped "Return Log"
    table_data = [[
        "Item", "Qty Out", "Returned", "Outstanding", "Return Log (who/when/qty)"
    ]]

    for r in lines:
        lid = int(r["line_id"])
        log_lines = ev_map.get(lid, [])
        log_text = "<br/>".join(log_lines) if log_lines else "(no returns recorded)"
        table_data.append([
            str(r["item_name"]),
            str(int(r["qty"] or 0)),
            str(int(r["returned_qty"] or 0)),
            str(int(r["outstanding_qty"] or 0)),
            Paragraph(log_text, styles["Normal"]),
        ])

    # column widths tuned for letter page
    col_widths = [140, 45, 50, 60, 200]

    return build_table_pdf("SIB Supply Checkout System", subtitle, table_data, col_widths=col_widths)

def build_checkout_receipt_pdf(checkout_id: int) -> bytes:
    """
    Keep this for the "Checkout Receipt" button — uses ticket PDF format,
    but it’ll naturally show empty return logs initially.
    """
    return build_ticket_pdf(checkout_id)

# ---------------------------
# Database
# ---------------------------
LOGO_LIGHT_URL = "https://www.oit.edu/sites/default/files/styles/inline_media_300w/public/2023-03/ot-sib-4c-text.png.webp"
LOGO_DARK_URL  = "https://www.oit.edu/sites/default/files/styles/inline_media_300w/public/2023-03/ot-sib-4c-text.png.webp"

def render_sidebar_logo():
    theme_type = None
    try:
        theme_type = st.context.theme.get("type", None)
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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

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
            actual_return_date TEXT,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS checkout_lines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checkout_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,
            returned_qty INTEGER NOT NULL DEFAULT 0,
            returned_at TEXT,
            FOREIGN KEY(checkout_id) REFERENCES checkouts(id),
            FOREIGN KEY(item_id) REFERENCES items(id)
        )
    """)

    # ✅ Audit log of check-ins (who, when, qty) per line
    cur.execute("""
        CREATE TABLE IF NOT EXISTS return_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checkout_id INTEGER NOT NULL,
            line_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,
            returned_at TEXT NOT NULL,
            returned_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(checkout_id) REFERENCES checkouts(id),
            FOREIGN KEY(line_id) REFERENCES checkout_lines(id),
            FOREIGN KEY(returned_by) REFERENCES users(id)
        )
    """)
        # ---------------------------
    # Reservations (staging queue)
    # ---------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            borrower_name TEXT NOT NULL,
            borrower_email TEXT NOT NULL,
            borrower_group TEXT NOT NULL,

            est_checkout_date TEXT NOT NULL,          -- YYYY-MM-DD
            est_checkout_time TEXT,                   -- optional, store as "HH:MM"
            expected_return_date TEXT NOT NULL,       -- "Check-In Date" (expected return)

            status TEXT NOT NULL DEFAULT 'waiting',   -- waiting | ready | converted
            notes TEXT,

            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,

            actual_checkout_date TEXT,                -- set when converted
            actual_checkout_time TEXT,                -- optional
            checkout_id INTEGER,                      -- link to real checkout ticket

            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(checkout_id) REFERENCES checkouts(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reservation_lines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reservation_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,

            FOREIGN KEY(reservation_id) REFERENCES reservations(id),
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
        """, (default_user, hash_password(default_pass), now_iso()))
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

from zoneinfo import ZoneInfo
from datetime import date, datetime, timezone

APP_TZ = ZoneInfo("America/Los_Angeles")

def now_iso():
    # Store all timestamps in UTC
    return datetime.now(timezone.utc).isoformat()

def to_local_display(dt_str: str) -> str:
    if not dt_str:
        return ""
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(APP_TZ).strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        return str(dt_str)

def local_returned_at_iso(d: date) -> str:
    # Midnight in America/Los_Angeles -> converted to UTC for storage
    local_dt = datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=APP_TZ)
    return local_dt.astimezone(timezone.utc).isoformat()




# ---------------------------
# Inventory availability math
# ---------------------------
def get_outstanding_by_item():
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
# Ticket helpers
# ---------------------------
def get_open_checkouts_summary(limit: int = 500):
    rows = fetch_all(f"""
        SELECT
            co.id AS checkout_id,
            co.borrower_name,
            co.borrower_email,
            co.borrower_group,
            co.checkout_date,
            co.expected_return_date,
            SUM(cl.qty - cl.returned_qty) AS outstanding_total
        FROM checkouts co
        JOIN checkout_lines cl ON cl.checkout_id = co.id
        GROUP BY co.id
        HAVING SUM(cl.qty - cl.returned_qty) > 0
        ORDER BY co.checkout_date DESC, co.id DESC
        LIMIT {int(limit)}
    """)
    return rows

def get_open_checkout_ids(limit: int = 500):
    rows = get_open_checkouts_summary(limit=limit)
    return [int(r["checkout_id"]) for r in rows]

def get_checkout_outstanding_lines(checkout_id: int):
    return fetch_all("""
        SELECT
            cl.id AS line_id,
            i.name AS item_name,
            (cl.qty - cl.returned_qty) AS outstanding_qty
        FROM checkout_lines cl
        JOIN items i ON i.id = cl.item_id
        WHERE cl.checkout_id = ?
          AND (cl.qty - cl.returned_qty) > 0
        ORDER BY i.name ASC
    """, (checkout_id,))

# ---------------------------
# Reservation helpers
# ---------------------------
RES_STATUS = ["waiting", "ready", "converted"]

def get_reservations_summary(limit: int = 500):
    rows = fetch_all(f"""
        SELECT
            r.id AS reservation_id,
            r.borrower_name,
            r.borrower_email,
            r.borrower_group,
            r.est_checkout_date,
            r.est_checkout_time,
            r.expected_return_date,
            r.status,
            r.checkout_id,
            r.created_at
        FROM reservations r
        ORDER BY r.id DESC
        LIMIT {int(limit)}
    """)
    return rows

def get_reservation_lines(reservation_id: int):
    return fetch_all("""
        SELECT
            rl.id AS line_id,
            rl.item_id,
            i.name AS item_name,
            rl.qty
        FROM reservation_lines rl
        JOIN items i ON i.id = rl.item_id
        WHERE rl.reservation_id = ?
        ORDER BY i.name ASC
    """, (reservation_id,))

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

    with st.expander("Forgot admin password?", expanded=False):
        reset_admin_password_to_default()

def page_admin_users():
    require_login()
    if not is_admin():
        st.error("Admins only.")
        st.stop()

    st.header("Admin: User Management")
    st.caption("Create users, reset passwords, and activate/deactivate accounts.")

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

        selected_id = st.selectbox(
            "Select user",
            options=[x[0] for x in user_options],
            format_func=lambda uid: dict(user_options).get(uid, str(uid))
        )
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
                new_cat = st.selectbox(
                    "Category",
                    ["(none)"] + [c["name"] for c in cats],
                    index=(["(none)"] + [c["name"] for c in cats]).index(current_cat) if current_cat in (["(none)"] + [c["name"] for c in cats]) else 0
                )
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

    if "last_checkout_receipt" not in st.session_state:
        st.session_state.last_checkout_receipt = None

    if st.session_state.last_checkout_receipt:
        rec = st.session_state.last_checkout_receipt
        st.success(f"Checkout submitted successfully! Receipt ready for Ticket #{rec['checkout_id']}.")

        st.download_button(
            "Download / Print Ticket (PDF)",
            data=rec["pdf_bytes"],
            file_name=f"ticket_{rec['checkout_id']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        st.caption("Tip: Open the downloaded PDF and print it from your browser/PDF viewer.")

        colA, colB = st.columns([1, 1], gap="large")
        with colA:
            if st.button("Start New Checkout", use_container_width=True):
                st.session_state.last_checkout_receipt = None
                st.rerun()
        with colB:
            st.info("Scroll down to create another checkout (or click Start New Checkout).")

        st.divider()

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

    st.caption("Build a checkout cart (multiple items), then submit as one ticket.")

    if "cart" not in st.session_state:
        st.session_state.cart = []

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

        for c in st.session_state.cart:
            avail = get_available_qty(c["item_id"])
            if c["qty"] > avail:
                st.error(f"Not enough available for: {c['item_label']} (need {c['qty']}, available {avail})")
                return

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

        params = []
        for c in st.session_state.cart:
            params.append((checkout_id, c["item_id"], int(c["qty"])))
        execute_many("""
            INSERT INTO checkout_lines (checkout_id, item_id, qty)
            VALUES (?, ?, ?)
        """, params)

        pdf_bytes = build_checkout_receipt_pdf(checkout_id)
        st.session_state.last_checkout_receipt = {
            "checkout_id": checkout_id,
            "pdf_bytes": pdf_bytes,
        }

        st.session_state.cart = []
        st.success(f"Checkout submitted (Ticket #: {checkout_id}). Ticket PDF generated.")
        st.rerun()

def page_currently_checked_out():
    require_login()
    st.header("Currently Checked Out")

    tickets = get_open_checkouts_summary(limit=500)
    if not tickets:
        st.success("Nothing is currently checked out.")
        return

    df = pd.DataFrame([dict(r) for r in tickets])
    df = df[[
        "checkout_id",
        "borrower_name",
        "borrower_group",
        "checkout_date",
        "expected_return_date",
        "outstanding_total",
    ]].rename(columns={
        "checkout_id": "Ticket #",
        "borrower_name": "Borrower",
        "borrower_group": "Group",
        "checkout_date": "Checkout Date",
        "expected_return_date": "Expected Return",
        "outstanding_total": "Outstanding (Total)"
    })

    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Ticket details (expand a ticket)")

    for r in tickets:
        ticket_id = int(r["checkout_id"])
        outstanding_total = int(r["outstanding_total"] or 0)
        label = f"Ticket #{ticket_id} — {r['borrower_name']} — {r['borrower_group']} (Outstanding: {outstanding_total})"
        with st.expander(label, expanded=False):
            lines = get_checkout_outstanding_lines(ticket_id)
            ldf = pd.DataFrame([dict(x) for x in lines]) if lines else pd.DataFrame(columns=["line_id","item_name","outstanding_qty"])
            if not ldf.empty:
                ldf = ldf.rename(columns={
                    "line_id": "Line ID",
                    "item_name": "Item",
                    "outstanding_qty": "Qty Not Checked In"
                })
            st.dataframe(ldf, use_container_width=True, hide_index=True)

            # Optional: print open ticket from here too
            pdf_bytes = build_ticket_pdf(ticket_id)
            st.download_button(
                "Download / Print Ticket (PDF)",
                data=pdf_bytes,
                file_name=f"ticket_{ticket_id}.pdf",
                mime="application/pdf",
                use_container_width=True,
                key=f"print_open_ticket_{ticket_id}"
            )

def page_checkin():
    require_login()
    st.header("Check In")
    st.caption("Select (or type) a Ticket #. Enter Return Now per item. Ticket closes automatically when fully returned.")

    open_ids = get_open_checkout_ids(limit=500)

    colA, colB = st.columns([2, 1], gap="large")
    with colA:
        selected_id = None
        if open_ids:
            selected_id = st.selectbox(
                "Select an open Ticket #",
                options=[None] + open_ids,
                format_func=lambda x: "(choose one)" if x is None else f"Ticket #{x}",
                key="checkin_select_ticket"
            )
        else:
            st.info("No open tickets found.")

    with colB:
        typed_id = st.text_input("Or type Ticket #", value="", key="checkin_typed_ticket").strip()

    ticket_id = None
    if typed_id:
        if typed_id.isdigit():
            ticket_id = int(typed_id)
        else:
            st.error("Typed Ticket # must be a number.")
            return
    elif selected_id is not None:
        ticket_id = int(selected_id)

    if not ticket_id:
        st.stop()

    header = fetch_one("""
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
        WHERE co.id = ?
    """, (ticket_id,))

    if not header:
        st.error(f"Ticket #{ticket_id} not found.")
        return

    if header["actual_return_date"]:
        st.info(f"Ticket #{ticket_id} is already CLOSED (Actual return: {header['actual_return_date']}).")
        # Still allow printing closed ticket
        pdf_bytes = build_ticket_pdf(ticket_id)
        st.download_button(
            "Download / Print Ticket (PDF)",
            data=pdf_bytes,
            file_name=f"ticket_{ticket_id}.pdf",
            mime="application/pdf",
            use_container_width=True,
            key=f"print_closed_from_checkin_{ticket_id}"
        )
        return

    st.subheader(f"Ticket #{ticket_id}")
    st.write(
        f"**Borrower:** {header['borrower_name']} ({header['borrower_email']})  \n"
        f"**Group:** {header['borrower_group']}  \n"
        f"**Checkout date:** {header['checkout_date']}  \n"
        f"**Expected return:** {header['expected_return_date']}  \n"
        f"**Created by:** {header['created_by']}  \n"
        f"**Created at:** {to_local_display(header['created_at'])}"
    )

    rows = fetch_all("""
        SELECT
            cl.id AS line_id,
            i.name AS item_name,
            cl.qty AS qty,
            cl.returned_qty AS returned,
            (cl.qty - cl.returned_qty) AS outstanding
        FROM checkout_lines cl
        JOIN items i ON i.id = cl.item_id
        WHERE cl.checkout_id = ?
        ORDER BY i.name ASC
    """, (ticket_id,))

    df = pd.DataFrame([dict(r) for r in rows]) if rows else pd.DataFrame(columns=["line_id","item_name","qty","returned","outstanding"])
    if df.empty:
        st.warning("No lines found on this ticket.")
        return

    df = df.rename(columns={
        "line_id": "Line ID",
        "item_name": "Item",
        "qty": "Qty",
        "returned": "Returned",
        "outstanding": "Outstanding",
    })

    if "Return Now" not in df.columns:
        df["Return Now"] = 0

    st.divider()
    st.subheader("Enter quantities being returned")

    edited = st.data_editor(
        df[["Line ID", "Item", "Qty", "Returned", "Outstanding", "Return Now"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "Line ID": st.column_config.NumberColumn(disabled=True),
            "Item": st.column_config.TextColumn(disabled=True),
            "Qty": st.column_config.NumberColumn(disabled=True),
            "Returned": st.column_config.NumberColumn(disabled=True),
            "Outstanding": st.column_config.NumberColumn(disabled=True),
            "Return Now": st.column_config.NumberColumn(min_value=0, step=1),
        },
        disabled=["Line ID", "Item", "Qty", "Returned", "Outstanding"],
        key=f"checkin_editor_{ticket_id}"
    )

    col1, col2 = st.columns([1, 2], gap="large")
    with col1:
        actual_return = st.date_input("Return date", value=date.today(), key=f"checkin_date_{ticket_id}")
    with col2:
        st.caption("Enter 0 for lines not being returned today. Partial returns are allowed.")

    if st.button("Process Return", type="primary", use_container_width=True):
        updates = []
        for _, row in edited.iterrows():
            line_id = int(row["Line ID"])
            outstanding = int(row["Outstanding"])
            try:
                return_now = int(row["Return Now"])
            except Exception:
                st.error("Return Now must be a whole number.")
                return

            if return_now < 0:
                st.error("Return Now cannot be negative.")
                return
            if return_now > outstanding:
                st.error(f"Line {line_id}: Return Now ({return_now}) exceeds Outstanding ({outstanding}).")
                return
            if return_now > 0:
                updates.append((return_now, line_id))

        if not updates:
            st.warning("No returns entered. Set at least one Return Now > 0.")
            return

        returned_at_iso = local_returned_at_iso(actual_return)

        # ✅ Update returned_qty AND write return_events for audit ("who checked in and when")
        for return_now, line_id in updates:
            execute("""
                UPDATE checkout_lines
                SET returned_qty = returned_qty + ?,
                    returned_at = ?
                WHERE id = ?
            """, (return_now, returned_at_iso, line_id))

            execute("""
                INSERT INTO return_events (checkout_id, line_id, qty, returned_at, returned_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ticket_id, line_id, return_now, returned_at_iso, st.session_state.user_id, now_iso()))

        remain = fetch_one("""
            SELECT SUM(qty - returned_qty) AS remain
            FROM checkout_lines
            WHERE checkout_id = ?
        """, (ticket_id,))
        remain_qty = int(remain["remain"] or 0)

        if remain_qty == 0:
            execute("""
                UPDATE checkouts
                SET actual_return_date = ?
                WHERE id = ?
            """, (actual_return.isoformat(), ticket_id))
            st.success(f"Ticket #{ticket_id} CLOSED — everything returned.")
        else:
            st.success(f"Return processed. Ticket #{ticket_id} remains OPEN — {remain_qty} still outstanding.")

        # Offer a fresh PDF immediately after return
        pdf_bytes = build_ticket_pdf(ticket_id)
        st.download_button(
            "Download / Print Updated Ticket (PDF)",
            data=pdf_bytes,
            file_name=f"ticket_{ticket_id}.pdf",
            mime="application/pdf",
            use_container_width=True,
            key=f"print_updated_ticket_after_checkin_{ticket_id}"
        )

        st.rerun()

def page_reports():
    require_login()
    st.header("Reports")

    st.subheader("Print ticket (open or closed)")
    ticket_to_print = st.text_input("Ticket # to print", value="", key="report_ticket_print").strip()
    if ticket_to_print:
        if not ticket_to_print.isdigit():
            st.error("Ticket # must be a number.")
        else:
            tid = int(ticket_to_print)
            header = fetch_one("SELECT id FROM checkouts WHERE id=?", (tid,))
            if not header:
                st.error(f"Ticket #{tid} not found.")
            else:
                pdf_bytes = build_ticket_pdf(tid)
                st.download_button(
                    "Download / Print Ticket (PDF)",
                    data=pdf_bytes,
                    file_name=f"ticket_{tid}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key=f"report_print_ticket_{tid}"
                )

    st.divider()
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
def page_reservations():
    require_login()
    st.header("Reservations (Staging Queue)")
    st.caption("Reservations do NOT reduce inventory. Convert to a real checkout when ready for pickup.")

    # For success flow (like checkout receipts)
    if "last_converted_reservation" not in st.session_state:
        st.session_state.last_converted_reservation = None

    if st.session_state.last_converted_reservation:
        rec = st.session_state.last_converted_reservation
        st.success(
            f"Reservation #{rec['reservation_id']} converted to Ticket #{rec['checkout_id']}."
        )
        st.download_button(
            "Download / Print Ticket (PDF)",
            data=rec["pdf_bytes"],
            file_name=f"ticket_{rec['checkout_id']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
        if st.button("Convert another reservation / continue", use_container_width=True):
            st.session_state.last_converted_reservation = None
            st.rerun()

        st.divider()

    # ---------------------------------
    # Create a reservation (manual entry)
    # ---------------------------------
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
        label = f"{it['name']} (available now: {avail} / total: {total})"
        item_options.append((it["id"], label, avail))

    if "res_cart" not in st.session_state:
        st.session_state.res_cart = []

    with st.expander("1) Create reservation (manual staging entry)", expanded=True):
        colA, colB = st.columns(2, gap="large")

        with colA:
            r_name = st.text_input("Name", key="res_name")
            r_email = st.text_input("Email", key="res_email")
            r_group = st.text_input("Group / organization", key="res_group")

        with colB:
            est_checkout_date = st.date_input("Check-Out Date (estimated)", value=date.today(), key="res_est_checkout_date")

            specify_time = st.checkbox("Specify estimated check-out time (optional)", value=False, key="res_specify_time")
            est_time_str = None
            if specify_time:
                t = st.time_input("Estimated Check Out Time", value=datetime.now().time().replace(second=0, microsecond=0), key="res_est_time")
                est_time_str = t.strftime("%H:%M")

            expected_return_date = st.date_input("Check-In Date (expected return)", value=date.today(), key="res_expected_return_date")

        st.divider()
        st.caption("Add items to the reservation cart (availability is shown as a reference only).")

        col1, col2, col3 = st.columns([3, 1, 1], gap="large")
        id_list = [x[0] for x in item_options]
        label_map = {x[0]: x[1] for x in item_options}

        with col1:
            selected_item_id = st.selectbox(
                "Item",
                options=id_list,
                format_func=lambda i: label_map[i],
                key="res_selected_item_id"
            )
        with col2:
            qty = st.number_input("Qty", min_value=1, step=1, value=1, key="res_selected_qty")
        with col3:
            add = st.button("Add to reservation cart", use_container_width=True)

        if add:
            found = False
            for line in st.session_state.res_cart:
                if line["item_id"] == selected_item_id:
                    line["qty"] = int(line["qty"]) + int(qty)
                    found = True
                    break
            if not found:
                st.session_state.res_cart.append({
                    "item_id": selected_item_id,
                    "item_label": label_map[selected_item_id],
                    "qty": int(qty),
                })
            st.success("Added to reservation cart.")
            st.rerun()

        st.subheader("Reservation cart")
        if not st.session_state.res_cart:
            st.info("Cart is empty.")
        else:
            cart_df = pd.DataFrame([{"item": c["item_label"], "qty": c["qty"]} for c in st.session_state.res_cart])
            st.dataframe(cart_df, use_container_width=True, hide_index=True)

            colx, coly = st.columns([1, 1], gap="large")
            with colx:
                if st.button("Clear reservation cart", use_container_width=True):
                    st.session_state.res_cart = []
                    st.rerun()
            with coly:
                remove_idx = st.number_input("Remove line # (1..n)", min_value=1, step=1, value=1, max_value=len(st.session_state.res_cart))
                if st.button("Remove line", use_container_width=True):
                    idx = int(remove_idx) - 1
                    if 0 <= idx < len(st.session_state.res_cart):
                        st.session_state.res_cart.pop(idx)
                        st.rerun()

        st.divider()
        notes = st.text_area("Notes (optional)", key="res_notes")

        if st.button("Create reservation", type="primary", use_container_width=True):
            if not r_name.strip():
                st.error("Name is required.")
                return
            if not r_email.strip():
                st.error("Email is required.")
                return
            if not r_group.strip():
                st.error("Group/organization is required.")
                return
            if expected_return_date < est_checkout_date:
                st.error("Check-In Date cannot be before Check-Out Date.")
                return
            if not st.session_state.res_cart:
                st.error("Add at least one item to the reservation cart.")
                return

            reservation_id = execute("""
                INSERT INTO reservations (
                    borrower_name, borrower_email, borrower_group,
                    est_checkout_date, est_checkout_time, expected_return_date,
                    status, notes,
                    created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?)
            """, (
                r_name.strip(),
                r_email.strip(),
                r_group.strip(),
                est_checkout_date.isoformat(),
                est_time_str,
                expected_return_date.isoformat(),
                notes.strip() or None,
                st.session_state.user_id,
                now_iso()
            ))

            params = []
            for c in st.session_state.res_cart:
                params.append((reservation_id, c["item_id"], int(c["qty"])))
            execute_many("""
                INSERT INTO reservation_lines (reservation_id, item_id, qty)
                VALUES (?, ?, ?)
            """, params)

            st.session_state.res_cart = []
            st.success(f"Reservation created (Reservation #: {reservation_id}).")
            st.rerun()

    st.divider()

    # -----------------------------
    # View / manage reservations
    # -----------------------------
    st.subheader("Manage reservations")

    # Filter
    colF1, colF2 = st.columns([1, 2], gap="large")
    with colF1:
        status_filter = st.selectbox("Status filter", ["(all)"] + RES_STATUS, index=0, key="res_status_filter")
    with colF2:
        search = st.text_input("Search (name, email, group)", value="", key="res_search").strip().lower()

    rows = get_reservations_summary(limit=500)
    data = []
    for r in rows:
        if status_filter != "(all)" and r["status"] != status_filter:
            continue
        blob = f"{r['borrower_name']} {r['borrower_email']} {r['borrower_group']}".lower()
        if search and search not in blob:
            continue
        data.append(dict(r))

    df = pd.DataFrame(data) if data else pd.DataFrame(columns=[
        "reservation_id","borrower_name","borrower_email","borrower_group",
        "est_checkout_date","est_checkout_time","expected_return_date",
        "status","checkout_id","created_at"
    ])

    if df.empty:
        st.info("No matching reservations.")
        return

    df = df.rename(columns={
        "reservation_id": "Reservation #",
        "borrower_name": "Name",
        "borrower_email": "Email",
        "borrower_group": "Group",
        "est_checkout_date": "Est. Checkout Date",
        "est_checkout_time": "Est. Checkout Time",
        "expected_return_date": "Expected Return (Check-In)",
        "status": "Status",
        "checkout_id": "Ticket # (if converted)",
        "created_at": "Created At (UTC)"
    })
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Reservation details (expand)")

    # Expanders (newest first)
    for r in data:
        rid = int(r["reservation_id"])
        label = f"Reservation #{rid} — {r['borrower_name']} — {r['borrower_group']} (Status: {r['status']})"
        with st.expander(label, expanded=False):
            st.write("**Estimated checkout:**", r["est_checkout_date"], r["est_checkout_time"] or "(time not provided)")
            st.write("**Expected return (check-in):**", r["expected_return_date"])
            st.write("**Email:**", r["borrower_email"])
            st.write("**Created at:**", to_local_display(r["created_at"]))

            lines = get_reservation_lines(rid)
            ldf = pd.DataFrame([dict(x) for x in lines]) if lines else pd.DataFrame(columns=["item_name","qty"])
            if not ldf.empty:
                ldf = ldf.rename(columns={"item_name": "Item", "qty": "Qty"})
                st.dataframe(ldf[["Item","Qty"]], use_container_width=True, hide_index=True)

            st.divider()

            # Update status
            current_status = r["status"]
            status_idx = RES_STATUS.index(current_status) if current_status in RES_STATUS else 0

            colS1, colS2 = st.columns([1, 1], gap="large")
            with colS1:
                new_status = st.selectbox(
                    "Update status",
                    RES_STATUS,
                    index=status_idx,
                    key=f"res_status_{rid}"
                )
            with colS2:
                if st.button("Save status", use_container_width=True, key=f"res_save_status_{rid}"):
                    execute("UPDATE reservations SET status=? WHERE id=?", (new_status, rid))
                    st.success("Status updated.")
                    st.rerun()

            # Convert to checkout
            if r.get("checkout_id"):
                st.info(f"Already converted to Ticket #{r['checkout_id']}.")
                pdf_bytes = build_ticket_pdf(int(r["checkout_id"]))
                st.download_button(
                    "Download / Print Ticket (PDF)",
                    data=pdf_bytes,
                    file_name=f"ticket_{int(r['checkout_id'])}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key=f"res_print_converted_{rid}"
                )
                continue

            if current_status != "ready":
                st.warning("To convert to a real checkout, set status to **ready** first.")
                continue

            st.subheader("Convert to Checkout (creates a real ticket)")
            colC1, colC2 = st.columns(2, gap="large")
            with colC1:
                actual_checkout_date = st.date_input(
                    "Actual checkout date",
                    value=date.today(),
                    key=f"res_actual_date_{rid}"
                )
            with colC2:
                use_actual_time = st.checkbox(
                    "Record actual checkout time (optional)",
                    value=False,
                    key=f"res_use_actual_time_{rid}"
                )
                actual_time_str = None
                if use_actual_time:
                    t2 = st.time_input(
                        "Actual checkout time",
                        value=datetime.now().time().replace(second=0, microsecond=0),
                        key=f"res_actual_time_{rid}"
                    )
                    actual_time_str = t2.strftime("%H:%M")

            if st.button("Convert reservation to checkout", type="primary", use_container_width=True, key=f"res_convert_{rid}"):
                # Pull full reservation header + lines fresh
                header = fetch_one("SELECT * FROM reservations WHERE id=?", (rid,))
                if not header:
                    st.error("Reservation not found.")
                    return
                lines = get_reservation_lines(rid)
                if not lines:
                    st.error("Reservation has no items.")
                    return

                # Validate availability NOW (since reservation doesn't reserve stock)
                for ln in lines:
                    need = int(ln["qty"] or 0)
                    avail = get_available_qty(int(ln["item_id"]))
                    if need > avail:
                        st.error(f"Not enough available for: {ln['item_name']} (need {need}, available {avail})")
                        return

                checkout_id = execute("""
                    INSERT INTO checkouts (
                        checkout_date, expected_return_date,
                        borrower_name, borrower_email, borrower_group,
                        created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    actual_checkout_date.isoformat(),
                    header["expected_return_date"],
                    header["borrower_name"],
                    header["borrower_email"],
                    header["borrower_group"],
                    st.session_state.user_id,
                    now_iso()
                ))

                params = []
                for ln in lines:
                    params.append((checkout_id, int(ln["item_id"]), int(ln["qty"])))
                execute_many("""
                    INSERT INTO checkout_lines (checkout_id, item_id, qty)
                    VALUES (?, ?, ?)
                """, params)

                # Mark reservation converted + store actual checkout date/time + link ticket
                execute("""
                    UPDATE reservations
                    SET status='converted',
                        actual_checkout_date=?,
                        actual_checkout_time=?,
                        checkout_id=?
                    WHERE id=?
                """, (actual_checkout_date.isoformat(), actual_time_str, checkout_id, rid))

                pdf_bytes = build_checkout_receipt_pdf(checkout_id)
                st.session_state.last_converted_reservation = {
                    "reservation_id": rid,
                    "checkout_id": checkout_id,
                    "pdf_bytes": pdf_bytes
                }
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

    render_sidebar_logo()

    if not st.session_state.logged_in:
        page_login()
        return

    with st.sidebar:
        st.markdown(f"### {APP_TITLE}")
        st.write(f"Logged in as **{st.session_state.username}** ({st.session_state.role})")
        st.divider()

        pages = ["Checkout", "Reservations", "Check In", "Currently Checked Out", "Items", "Categories", "Reports"]
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
    elif choice == "Check In":
        page_checkin()
    elif choice == "Currently Checked Out":
        page_currently_checked_out()
    elif choice == "Reports":
        page_reports()
    elif choice == "Logout":
        page_logout()
    elif choice == "Reservations":
        page_reservations()

if __name__ == "__main__":
    main()
