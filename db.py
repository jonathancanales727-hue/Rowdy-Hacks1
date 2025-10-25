# SQLite setup
#database
import sqlite3
import json
import hashlib
def db_setup():
    conn = sqlite3.connect ("wallet.db")
    c = conn.cursor()
    c.execute ("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, balance REAL DEFAULT 0)")
    c.execute ("CREATE TABLE IF NOT EXISTS shared_wallets (wallet_name TEXT PRIMARY KEY,balance REAL DEFAULT 0)")
    c.execute ("CREATE TABLE IF NOT EXISTS wallet_members (wallet_name TEXT,username TEXT,PRIMARY KEY (wallet_name, username))")
    c.execute ("CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT,wallet_name TEXT,initiated_by TEXT,amount REAL,recipient TEXT,approvals TEXT, status TEXT)")
    conn.commit()
    conn.close()
db_setup()