from db import db_setup
import sqlite3
import json
import hashlib

# Process of registering a user 

def hash_password(password):
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()
def register_user(username, password):
    import sqlite3
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
            (username, hash_password(password), 0)
        )
        conn.commit()
        print (f"User '{username}' is now registered!")
    except sqlite3.IntegrityError:
        print ("Username already in use")
    finally:
        conn.close()

# Process of a User Login

def login_user(username, password):
    import sqlite3
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?",
        (username,)
    )
    result = c.fetchone()
    conn.close()
    if result and result[0] == hash_password(password):
        print(f"User '{username}' logged in!")
        return True
    print("Login failed.")
    return False

#Process of Creating a shared wallet

def create_shared_wallet(wallet_name, admin_username):
    import sqlite3
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO shared_wallets (wallet_name, balance) VALUES (?, ?)",
            (wallet_name, 0)
        )
        c.execute(
            "INSERT INTO wallet_members (wallet_name, username) VALUES (?, ?)",
            (wallet_name, admin_username)
        )
        conn.commit()
        print(f"Shared wallet '{wallet_name}' created with admin '{admin_username}'")
    except sqlite3.IntegrityError:
        print("Wallet already exists.")
    finally:
        conn.close()

#Process of adding a member to the shared wallet 

def add_member(wallet_name, username):
    import sqlite3
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO wallet_members (wallet_name, username) VALUES (?, ?)",
            (wallet_name, username)
        )
        conn.commit()
        print(f"User '{username}' added to wallet '{wallet_name}'")
    except sqlite3.IntegrityError:
        print("User already a member.")
    finally:
        conn.close()


#process of inittiation of a transaction

def initiate_transaction(wallet_name, initiated_by, amount, recipient):
    import sqlite3, json
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    approvals = json.dumps([initiated_by])  # automatically approved by proposer
    status = "pending"
    c.execute(
        "INSERT INTO transactions (wallet_name, initiated_by, amount, recipient, approvals, status) VALUES (?, ?, ?, ?, ?, ?)",
        (wallet_name, initiated_by, amount, recipient, approvals, status)
    )
    conn.commit()
    conn.close()
    print("Transaction initiated.")


#aprroving transaction

def approve_transaction(transaction_id, username):
    import sqlite3, json
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute(
        "SELECT approvals, status, wallet_name, amount FROM transactions WHERE id=?",
        (transaction_id,)
    )
    tx = c.fetchone()
    if not tx:
        print("Transaction not found.")
        return
    if tx[1] == "completed":
        print("Transaction already completed.")
        return
    approvals = json.loads(tx[0])
    if username in approvals:
        print("User already approved.")
        return
    approvals.append(username)
    # simple rule: 2 approvals = completed
    status = "completed" if len(approvals) >= 2 else "pending"
    if status == "completed":
        c.execute(
            "UPDATE shared_wallets SET balance = balance - ? WHERE wallet_name=?",
            (tx[3], tx[2])
        )
    c.execute(
        "UPDATE transactions SET approvals=?, status=? WHERE id=?",
        (json.dumps(approvals), status, transaction_id)
    )
    conn.commit()
    conn.close()
    print(f"Transaction status: {status}")

register_user("Jonathan", "727")
register_user("Bro Code", "222")
login_user("Jonathan", "727")
create_shared_wallet("Roommates", "Jonathan")
add_member("Roommates", "Bro Code")
initiate_transaction("Roommates", "Jonathan", 50, "Bro Code")
approve_transaction(1, "Bro code")



import sqlite3
import json
import hashlib

# -------- Helper Functions --------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# -------- User Functions --------
def register_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
            (username, hash_password(password), 0)
        )
        conn.commit()
        print(f"User '{username}' registered!\n")
    except sqlite3.IntegrityError:
        print("Username already exists.\n")
    finally:
        conn.close()

def login_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result and result[0] == hash_password(password):
        print(f"User '{username}' logged in!\n")
        return username
    else:
        print("Login failed.\n")
        return None

# -------- Shared Wallet Functions --------
def create_shared_wallet(current_user):
    wallet_name = input("Enter new wallet name: ")
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO shared_wallets (wallet_name, balance) VALUES (?, ?)", (wallet_name, 0))
        c.execute("INSERT INTO wallet_members (wallet_name, username) VALUES (?, ?)", (wallet_name, current_user))
        conn.commit()
        print(f"Shared wallet '{wallet_name}' created with admin '{current_user}'\n")
    except sqlite3.IntegrityError:
        print("Wallet already exists.\n")
    finally:
        conn.close()

def add_member():
    wallet_name = input("Wallet name: ")
    username = input("Username to add: ")
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO wallet_members (wallet_name, username) VALUES (?, ?)", (wallet_name, username))
        conn.commit()
        print(f"User '{username}' added to wallet '{wallet_name}'\n")
    except sqlite3.IntegrityError:
        print("User already a member or wallet doesn't exist.\n")
    finally:
        conn.close()

# -------- Transaction Functions --------
def initiate_transaction(current_user):
    wallet_name = input("Wallet name: ")
    amount = float(input("Amount: "))
    recipient = input("Recipient username: ")
    approvals = json.dumps([current_user])
    status = "pending"
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute(
        "INSERT INTO transactions (wallet_name, initiated_by, amount, recipient, approvals, status) VALUES (?, ?, ?, ?, ?, ?)",
        (wallet_name, current_user, amount, recipient, approvals, status)
    )
    conn.commit()
    conn.close()
    print("Transaction initiated.\n")

def approve_transaction(current_user):
    tx_id = int(input("Transaction ID to approve: "))
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("SELECT approvals, status, wallet_name, amount FROM transactions WHERE id=?", (tx_id,))
    tx = c.fetchone()
    if not tx:
        print("Transaction not found.\n")
        return
    if tx[1] == "completed":
        print("Transaction already completed.\n")
        return
    approvals = json.loads(tx[0])
    if current_user in approvals:
        print("You already approved this transaction.\n")
        return
    approvals.append(current_user)
    status = "completed" if len(approvals) >= 2 else "pending"
    if status == "completed":
        c.execute("UPDATE shared_wallets SET balance = balance - ? WHERE wallet_name=?", (tx[3], tx[2]))
    c.execute("UPDATE transactions SET approvals=?, status=? WHERE id=?", (json.dumps(approvals), status, tx_id))
    conn.commit()
    conn.close()
    print(f"Transaction status: {status}\n")

# -------- Main Menu --------
def main():
    current_user = None
    while True:
        print("===== Digital Wallet Menu =====")
        print("1. Register")
        print("2. Login")
        print("3. Create Shared Wallet")
        print("4. Add Member to Wallet")
        print("5. Initiate Transaction")
        print("6. Approve Transaction")
        print("7. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            current_user = login_user()
        elif choice == "3":
            if current_user:
                create_shared_wallet(current_user)
            else:
                print("Login first.\n")
        elif choice == "4":
            add_member()
        elif choice == "5":
            if current_user:
                initiate_transaction(current_user)
            else:
                print("Login first.\n")
        elif choice == "6":
            if current_user:
                approve_transaction(current_user)
            else:
                print("Login first.\n")
        elif choice == "7":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.\n")

if __name__ == "__main__":
    main()

"""=================================================================================="""
import tkinter as tk
from tkinter import simpledialog, messagebox
import sqlite3
import json
import hashlib

# ---------------- Backend Functions ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

current_user = None  # global variable to track logged-in user

def register_user():
    username = simpledialog.askstring("Register", "Enter username:")
    password = simpledialog.askstring("Register", "Enter password:", show="*")
    if not username or not password:
        return
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
                  (username, hash_password(password), 0))
        conn.commit()
        messagebox.showinfo("Success", f"User '{username}' registered!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")
    finally:
        conn.close()

def login_user():
    global current_user
    username = simpledialog.askstring("Login", "Enter username:")
    password = simpledialog.askstring("Login", "Enter password:", show="*")
    if not username or not password:
        return
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result and result[0] == hash_password(password):
        current_user = username
        messagebox.showinfo("Success", f"User '{username}' logged in!")
    else:
        messagebox.showerror("Error", "Login failed.")

# ---------------- Shared Wallet Functions ----------------
def create_shared_wallet():
    if not current_user:
        messagebox.showerror("Error", "Login first!")
        return
    wallet_name = simpledialog.askstring("Create Wallet", "Enter wallet name:")
    if not wallet_name:
        return
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO shared_wallets (wallet_name, balance) VALUES (?, ?)", (wallet_name, 0))
        c.execute("INSERT INTO wallet_members (wallet_name, username) VALUES (?, ?)", (wallet_name, current_user))
        conn.commit()
        messagebox.showinfo("Success", f"Wallet '{wallet_name}' created!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Wallet already exists!")
    finally:
        conn.close()

def add_member():
    wallet_name = simpledialog.askstring("Add Member", "Wallet name:")
    username = simpledialog.askstring("Add Member", "Username to add:")
    if not wallet_name or not username:
        return
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO wallet_members (wallet_name, username) VALUES (?, ?)", (wallet_name, username))
        conn.commit()
        messagebox.showinfo("Success", f"User '{username}' added to wallet '{wallet_name}'!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "User already a member or wallet does not exist.")
    finally:
        conn.close()

# ---------------- Transaction Functions ----------------
def initiate_transaction():
    if not current_user:
        messagebox.showerror("Error", "Login first!")
        return
    wallet_name = simpledialog.askstring("Transaction", "Wallet name:")
    recipient = simpledialog.askstring("Transaction", "Recipient username:")
    try:
        amount = float(simpledialog.askstring("Transaction", "Amount:"))
    except:
        messagebox.showerror("Error", "Invalid amount")
        return
    if not wallet_name or not recipient:
        return
    approvals = json.dumps([current_user])
    status = "pending"
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("INSERT INTO transactions (wallet_name, initiated_by, amount, recipient, approvals, status) VALUES (?, ?, ?, ?, ?, ?)",
              (wallet_name, current_user, amount, recipient, approvals, status))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Transaction initiated!")

def approve_transaction():
    if not current_user:
        messagebox.showerror("Error", "Login first!")
        return
    try:
        tx_id = int(simpledialog.askstring("Approve Transaction", "Transaction ID:"))
    except:
        messagebox.showerror("Error", "Invalid ID")
        return
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("SELECT approvals, status, wallet_name, amount FROM transactions WHERE id=?", (tx_id,))
    tx = c.fetchone()
    if not tx:
        messagebox.showerror("Error", "Transaction not found")
        return
    if tx[1] == "completed":
        messagebox.showinfo("Info", "Transaction already completed")
        return
    approvals = json.loads(tx[0])
    if current_user in approvals:
        messagebox.showinfo("Info", "You already approved this transaction")
        return
    approvals.append(current_user)
    status = "completed" if len(approvals) >= 2 else "pending"
    if status == "completed":
        c.execute("UPDATE shared_wallets SET balance = balance - ? WHERE wallet_name=?", (tx[3], tx[2]))
    c.execute("UPDATE transactions SET approvals=?, status=? WHERE id=?", (json.dumps(approvals), status, tx_id))
    conn.commit()
    conn.close()
    messagebox.showinfo("Info", f"Transaction status: {status}")

# ---------------- View Functions ----------------
def view_wallets():
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("SELECT wallet_name, balance FROM shared_wallets")
    wallets = c.fetchall()
    conn.close()
    msg = "\n".join([f"{w[0]}: ${w[1]:.2f}" for w in wallets]) or "No wallets found"
    messagebox.showinfo("Shared Wallets", msg)

def view_pending_transactions():
    conn = sqlite3.connect("wallet.db")
    c = conn.cursor()
    c.execute("SELECT id, wallet_name, initiated_by, amount, status FROM transactions WHERE status='pending'")
    txs = c.fetchall()
    conn.close()
    msg = "\n".join([f"ID {t[0]}: {t[2]} -> ${t[3]:.2f} in {t[1]} (Status: {t[4]})" for t in txs]) or "No pending transactions"
    messagebox.showinfo("Pending Transactions", msg)

# ---------------- GUI ----------------
root = tk.Tk()
root.title("Digital Wallet")
root.geometry("400x550")

tk.Label(root, text="Digital Wallet App", font=("Helvetica", 18)).pack(pady=15)

tk.Button(root, text="Register", width=30, command=register_user).pack(pady=5)
tk.Button(root, text="Login", width=30, command=login_user).pack(pady=5)
tk.Button(root, text="Create Shared Wallet", width=30, command=create_shared_wallet).pack(pady=5)
tk.Button(root, text="Add Member to Wallet", width=30, command=add_member).pack(pady=5)
tk.Button(root, text="Initiate Transaction", width=30, command=initiate_transaction).pack(pady=5)
tk.Button(root, text="Approve Transaction", width=30, command=approve_transaction).pack(pady=5)
tk.Button(root, text="View Wallet Balances", width=30, command=view_wallets).pack(pady=5)
tk.Button(root, text="View Pending Transactions", width=30, command=view_pending_transactions).pack(pady=5)
tk.Button(root, text="Exit", width=30, command=root.destroy).pack(pady=10)

root.mainloop()
