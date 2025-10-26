import hashlib
import uuid
import time
import tkinter as tk
from tkinter import messagebox

# Define custom colors inspired by the "UnityFund" design
BG_COLOR = "#F4F1FF" # Very light lavender background
PRIMARY_COLOR = "#6A5ACD" # Deep purple for accents
SECONDARY_COLOR = "#9370DB" # Medium purple for secondary buttons
TEXT_COLOR = "#2C1F1F" # Dark text
ACCENT_COLOR = "#8B008B" # Magenta/Darker accent for balance

# --- 1. Core Security and Utility Functions ---

def hash_password(password: str) -> str:
    """Hashes a password using SHA-256 (simplified for demo)."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verifies a stored password hash against one provided by the user."""
    return stored_hash == hash_password(provided_password)

# --- 2. Core Application Classes ---

class Wallet:
    """
    Manages the user's currency balance.
    Their wallet ID is public and anonymous.
    """
    def __init__(self, initial_balance=0.0):
        # Anonymous ID (public)
        self.wallet_id = str(uuid.uuid4())
        # Currency amount (private, stored internally)
        self._balance = initial_balance 
        print(f"DEBUG: NEW WALLET CREATED with ID: {self.wallet_id} at memory address: {hex(id(self))}")

    def deposit(self, amount: float) -> bool:
        """Adds funds to the wallet."""
        if amount > 0:
            self._balance += amount
            # CRITICAL LOG: Confirm which unique wallet object is being modified
            print(f"DEBUG: Wallet.deposit executed successfully on ID: {self.wallet_id} (Address: {hex(id(self))}). New Balance: {self._balance:,.2f}")
            return True
        return False

    def withdraw(self, amount: float) -> bool:
        """Removes funds from the wallet."""
        if 0 < amount <= self._balance:
            self._balance -= amount
            return True
        return False

    def get_balance(self) -> float:
        """Returns the current balance."""
        return self._balance

class User:
    """
    A user manages their wallet and personal security.
    """
    def __init__(self, username: str, password: str, initial_balance=0.0):
        self.username = username
        self.password_hash = hash_password(password)
        # CRITICAL FOR UNIQUE ACCOUNTS: Every user gets a separate Wallet instance.
        self.wallet = Wallet(initial_balance=initial_balance) 
        print(f"DEBUG: User {self.username} created (User Address: {hex(id(self))})")

    def authenticate(self, password: str) -> bool:
        """Authenticates the user's password."""
        return verify_password(self.password_hash, password)

class CommunityLedger:
    """
    Replicates the backend transaction logging system.
    Runs users and assists in tracking transactions.
    """
    def __init__(self):
        self._users = {} # Stores unique User objects by username
        self._wallets = {} # Stores unique User objects by wallet_id
        self.current_user: User | None = None
        
        # Pre-register a nonprofit account with a distinct balance ($500.00) 
        # to visually confirm account separation.
        self.register_user("community_pantry", "FoodHelp!Today!"
                           )


    def register_user(self, username: str, password: str, initial_balance=0.0) -> User | None:
        """Generates a new user in the system and their designated wallet."""
        if username in self._users:
            return None
        
        # Pass the initial balance to the User constructor
        new_user = User(username, password, initial_balance) 
        self._users[username]= new_user
        self._wallets[new_user.wallet.wallet_id] = new_user
        return new_user
    
    def user_login(self, username: str, password: str) -> bool:
        """Securely logs in a user, loading their unique User object."""
        user = self._users.get(username) # Retrieves the unique User object
        if user and user.authenticate(password):
            self.current_user = user # Sets the unique User object as current
            # CRITICAL LOG: Print which unique wallet object is now active
            print(f"DEBUG: LOGIN SUCCESS for {username}. User Address: {hex(id(user))}, Wallet ID: {user.wallet.wallet_id}")
            return True
        
        self.current_user = None
        return False
    
    def logout(self):
        """Logs out the current user."""
        if self.current_user:
            print(f"DEBUG: LOGOUT for {self.current_user.username}")
        self.current_user = None

    def send_money(self, recipient_wallet_id: str, amount: float) -> str:
        """
        Safely sends funds using the user's public ID.
        This function handles the actual fund transfer between unique wallets.
        Returns a status message string.
        """
        if not self.current_user:
            return "Transaction Error: You must be logged in to send funds."
        
        if amount <= 0:
            return "Transaction Error: Amount must be positive."

        # Looks up the RECIPIENT's unique User object using their public Wallet ID
        recipient = self._wallets.get(recipient_wallet_id)

        if not recipient:
            return "Status: Failed. Recipient ID not found."
        
        if recipient == self.current_user:
            return "Status: Failed. You cannot send funds to yourself."
        
        # Attempt to remove funds from the SENDER's unique wallet
        if self.current_user.wallet.withdraw(amount):
            # If successful, deposit funds into RECIPIENT's unique wallet
            recipient.wallet.deposit(amount)
            # Vague confirmation for privacy
            return f"Status: Transaction completed successfully. ${amount:.2f} sent."
        else:
            return "Status: Transaction was unsuccessful because of insufficient funds."

# --- 3. Tkinter GUI Application ---

class SecureWalletApp:
    def __init__(self, master):
        self.master = master
        master.title("UnityFund Wallet Demo")
        master.geometry("450x700") # Increased height for new section
        master.config(bg=BG_COLOR)

        self.ledger = CommunityLedger()

        self.status_text = tk.StringVar(value="Welcome to UnityFund! Log in or Register.")
        self.balance_text = tk.StringVar(value="Balance: $--.--")
        self.wallet_id_text = tk.StringVar(value="ID: Not Logged In")

        # Frame setup with themed background
        self.auth_frame = tk.Frame(master, padx=30, pady=30, bg=BG_COLOR)
        self.dashboard_frame = tk.Frame(master, padx=30, pady=30, bg=BG_COLOR)
        
        self.show_auth_frame()

        # Universal Status Bar
        status_label = tk.Label(master, textvariable=self.status_text, 
                                bg=BG_COLOR, fg=PRIMARY_COLOR, relief=tk.FLAT, anchor="w",
                                font=('Arial', 10, 'italic'), padx=10)
        status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # --- Frame Management ---

    def show_auth_frame(self):
        """Displays the Login/Register screen."""
        self.dashboard_frame.pack_forget()
        self.auth_frame.pack(fill=tk.BOTH, expand=True)
        self.build_auth_ui()


    def show_dashboard_frame(self):
        """Displays the main user dashboard."""
        self.auth_frame.pack_forget()
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
        self.build_dashboard_ui()
        self.update_dashboard()

    # --- Authentication UI ---

    def build_auth_ui(self):
        """Creates widgets for the Login/Register frame with new styling."""
        for widget in self.auth_frame.winfo_children():
            widget.destroy()

        # Title
        tk.Label(self.auth_frame, text="UnityFund", 
                 font=('Arial', 24, 'bold'), fg=PRIMARY_COLOR, bg=BG_COLOR).pack(pady=(20, 5))
        tk.Label(self.auth_frame, text="Secure Wallet Access", 
                 font=('Arial', 14), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=10)

        # Username Input
        tk.Label(self.auth_frame, text="Username:", bg= BG_COLOR, fg=TEXT_COLOR, anchor="center").pack(fill=tk.X, pady=(10, 0))
        self.username_entry = tk.Entry(self.auth_frame, width=30, bg= "white" ,relief=tk.SUNKEN, bd=2, highlightthickness=1, highlightcolor=PRIMARY_COLOR)
        self.username_entry.pack(pady=5, ipady=4)

        # Password Input
        tk.Label(self.auth_frame, text="Password:", bg= BG_COLOR, fg=TEXT_COLOR, anchor="center").pack(fill=tk.X, pady=(10, 0))
        self.password_entry = tk.Entry(self.auth_frame, width=30, show="*", bg="white" ,relief=tk.SUNKEN, bd=2, highlightthickness=1, highlightcolor=PRIMARY_COLOR)
        self.password_entry.pack(pady=5, ipady=4)

        # Buttons
        button_frame = tk.Frame(self.auth_frame, pady=20, bg=BG_COLOR)
        button_frame.pack()

        # Text color is black as requested
        button_style = {'padx': 20, 'pady': 10, 'fg': 'black', 'relief': tk.FLAT, 'font': ('Arial', 10, 'bold')}

        tk.Button(button_frame, text="Login", command=self.handle_login, 
                  bg=PRIMARY_COLOR, **button_style).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Register", command=self.handle_register, 
                  bg=SECONDARY_COLOR, **button_style).pack(side=tk.LEFT, padx=10)
        
        # Note about test user
        tk.Label(self.auth_frame, text="Test User: community_pantry / FoodHelp!Today! ",
                 font=('Arial', 8, 'italic'), fg="gray", bg=BG_COLOR).pack(pady=(50, 0))

    def handle_login(self):
        """Processes login attempt."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if self.ledger.user_login(username, password):
            self.status_text.set(f"Welcome back, {username}!")
            self.show_dashboard_frame()
        else:
            self.status_text.set("Login failed. Check credentials.")
            messagebox.showerror("Login Error", "Invalid Username or Password.")

    def handle_register(self):
        """Processes user registration."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
             self.status_text.set("Registration failed: Fields cannot be empty.")
             messagebox.showwarning("Input Error", "Username and Password are required.")
             return

        # New user registration defaults to initial_balance=0.0
        if self.ledger.register_user(username, password):
            self.status_text.set(f"Successfully registered {username}. Please log in.")
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
        else:
            self.status_text.set(f"Registration failed: Username '{username}' taken.")
            messagebox.showerror("Registration Error", "Username already exists.")
            
    # --- Dashboard UI ---

    def copy_wallet_id (self):
        """Copies current user's unique user wallet id to system clipboard"""
        if self.ledger.current_user:
            wallet_id = self.ledger.current_user.wallet.wallet_id
            # Use execCommand('copy') as navigator.clipboard might fail in an iframe environment
            try:
                # In a real environment, you'd use navigator.clipboard.writeText(wallet_id)
                # For this Tkinter example, we just set the clipboard property
                self.master.clipboard_clear()
                self.master.clipboard_append(wallet_id)
                self.status_text.set("Wallet ID successfully copied to clipboard")
            except Exception:
                self.status_text.set("Error: Could not copy ID.")
        else:
            self.status_text.set("Error: Cannot copy ID, User is not logged in")

    def build_dashboard_ui(self):
        """Creates widgets for the main dashboard frame."""
        for widget in self.dashboard_frame.winfo_children():
            widget.destroy()

        # 1. Header (User and ID)
        header_frame = tk.Frame(self.dashboard_frame, bg=BG_COLOR)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(header_frame, text="DASHBOARD", font=('Arial', 18, 'bold'), 
                 fg=PRIMARY_COLOR, bg=BG_COLOR).pack(side=tk.LEFT)
        
        # Text color is black as requested
        tk.Button(header_frame, text="Logout", command=self.handle_logout, 
                  padx=10, bg="#F44336", fg="black", relief=tk.FLAT).pack(side=tk.RIGHT)
        
        # User Details
        tk.Label(self.dashboard_frame, text=f"User: {self.ledger.current_user.username}", 
                 font=('Arial', 12, 'bold'), fg=TEXT_COLOR, bg=BG_COLOR).pack(anchor="w")
        
        # Frame to hold ID and copy button
        id_row_frame = tk.Frame(self.dashboard_frame, bg= BG_COLOR)
        id_row_frame.pack(fill=tk.X, anchor="w")
        tk.Label(id_row_frame, textvariable=self.wallet_id_text, 
                 font=('Courier', 9), fg="black", bg=BG_COLOR, wraplength=300).pack(side=tk.LEFT, anchor="w")
        
        # NEW COPY ID BUTTON (Text color is black as requested)
        tk.Button(id_row_frame, text="Copy ID", command=self.copy_wallet_id, 
                  padx=5, pady=0, bg=SECONDARY_COLOR, fg="black", relief=tk.FLAT, font=('Arial', 8, 'bold')).pack(side=tk.LEFT, padx=5)


        # 2. Balance Display Card
        balance_card = tk.Frame(self.dashboard_frame, bg=BG_COLOR, padx=20, pady=15, 
                                bd=1, relief=tk.SUNKEN)
        balance_card.pack(fill=tk.X, pady=20)
        tk.Label(balance_card, text="Current Balance", 
                 font=('Arial', 12), fg="gray", bg=BG_COLOR).pack(anchor="w")
        tk.Label(balance_card, textvariable=self.balance_text, 
                                 font=('Arial', 30, 'bold'), fg=ACCENT_COLOR, bg=BG_COLOR).pack(anchor="w")


        # 3. Add Funds (Deposit) Section
        deposit_frame = tk.LabelFrame(self.dashboard_frame, text="Add Funds (Deposit)", 
                                      padx=15, pady=10, bg=BG_COLOR, fg=PRIMARY_COLOR, font=('Arial', 10, 'bold'))
        deposit_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(deposit_frame, text="Amount ($):", bg=BG_COLOR).pack(anchor="w")
        self.deposit_amount_entry = tk.Entry(deposit_frame, width=15, bg="white" ,relief=tk.SUNKEN, bd=2, highlightthickness=2, highlightcolor=PRIMARY_COLOR, highlightbackground=TEXT_COLOR)
        self.deposit_amount_entry.pack(pady=5, ipady=2)
        self.deposit_amount_entry.insert(0, "50.00")

        # Text color is black as requested
        tk.Button(deposit_frame, text="Deposit Funds", command=self.handle_add_funds, 
                  padx=15, pady=5, bg=PRIMARY_COLOR, fg="black", relief=tk.FLAT).pack(pady=5)


        # 4. Transfer Funds Section
        transfer_frame = tk.LabelFrame(self.dashboard_frame, text="Transfer Funds (Anonymous Send)", 
                                       padx=15, pady=10, bg=BG_COLOR, fg=PRIMARY_COLOR, font=('Arial', 10, 'bold'))
        transfer_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(transfer_frame, text="Recipient Anonymous Wallet ID:", bg=BG_COLOR).pack(anchor="w")
        self.recipient_id_entry = tk.Entry(transfer_frame, width=45, bg= "white", relief=tk.SUNKEN, bd=2, highlightthickness=2, highlightcolor=PRIMARY_COLOR,  highlightbackground=TEXT_COLOR)
        self.recipient_id_entry.pack(pady=5, ipady=2)
        
        # Example ID help
        pantry_user = self.ledger._users.get("community_pantry")
        if pantry_user:
            pantry_id = pantry_user.wallet.wallet_id
            tk.Label(transfer_frame, text=f"Test ID: {pantry_id[:20]}...", 
                    font=('Arial', 8), fg="gray", bg=BG_COLOR).pack(anchor="w")

        tk.Label(transfer_frame, text="Amount ($):", bg=BG_COLOR).pack(anchor="w", pady=(10, 0))
        self.amount_entry = tk.Entry(transfer_frame, width=15, bg="white", relief=tk.SUNKEN, bd=2, highlightthickness=1, highlightcolor=PRIMARY_COLOR)
        self.amount_entry.pack(pady=5, ipady=2)
        self.amount_entry.insert(0, "25.00")

        # Text color is black as requested
        tk.Button(transfer_frame, text="Send Anonymous Transfer", command=self.handle_send_money, 
                  padx=15, pady=5, bg=PRIMARY_COLOR, fg="black",  relief=tk.FLAT).pack(pady=5)

        
    def update_dashboard(self):
        """Refreshes the balance and user ID display."""
        if self.ledger.current_user:
            balance = self.ledger.current_user.wallet.get_balance()
            wallet_id = self.ledger.current_user.wallet.wallet_id
            
            self.balance_text.set(f"${balance:,.2f}")
            self.wallet_id_text.set(f"Wallet ID: {wallet_id}")
        else:
            self.balance_text.set("$--.--")
            self.wallet_id_text.set("ID: Not Logged In")

    def handle_add_funds(self):
        """Processes a deposit (Add Funds)."""
        
        # CRITICAL GUARD RAIL: Ensure user is logged in before processing a deposit
        if not self.ledger.current_user:
            self.status_text.set("Error: Must be logged in to deposit funds.")
            messagebox.showerror("Authentication Required", "Please log in before depositing.")
            return

        try:
            amount = float(self.deposit_amount_entry.get())
        except ValueError:
            self.status_text.set("Deposit Error: Invalid amount.")
            messagebox.showerror("Input Error", "Please enter a valid numeric amount.")
            return

        if amount <= 0:
            self.status_text.set("Deposit Error: Amount must be positive.")
            messagebox.showerror("Input Error", "Deposit amount must be greater than zero.")
            return
        
        # DEBUG LOG: Confirm the current wallet's ID before executing deposit
        print(f"DEBUG: Attempting deposit of ${amount:.2f} on current wallet ID: {self.ledger.current_user.wallet.wallet_id}")


        if self.ledger.current_user.wallet.deposit(amount):
            self.status_text.set(f"Successfully added ${amount:.2f} to your balance.")
            messagebox.showinfo("Deposit Success", f"Your new balance reflects the deposit.")
            self.update_dashboard()
        else:
            self.status_text.set("Deposit Error: Could not process transaction.")
            messagebox.showerror("Deposit Failed", "Could not process transaction.")

    def handle_send_money(self):
        """Processes a money transfer."""
        recipient_id = self.recipient_id_entry.get().strip()
        try:
            amount = float(self.amount_entry.get())
        except ValueError:
            self.status_text.set("Transaction Error: Invalid amount.")
            messagebox.showerror("Input Error", "Please enter a valid numeric amount.")
            return

        # Execute transaction logic
        status_message = self.ledger.send_money(recipient_id, amount)
        self.status_text.set(status_message)
        
        self.update_dashboard()

        if "successfully" in status_message:
            messagebox.showinfo("Transaction Success", status_message)
        elif "Error" in status_message or "Failed" in status_message:
            messagebox.showerror("Transaction Failed", status_message)


    def handle_logout(self):
        """Logs out the user and returns to the authentication screen."""
        if self.ledger.current_user:
            username = self.ledger.current_user.username
            self.ledger.logout()
            self.status_text.set(f"Successfully logged out {username}.")
            self.show_auth_frame()
        else:
            self.status_text.set("Already logged out.")
            self.show_auth_frame()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureWalletApp(root)
    root.mainloop()