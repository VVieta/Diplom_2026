# storage/database.py

import sqlite3
import threading
import datetime

DB_NAME = "ids.db"

db_lock = threading.Lock()


# =====================================================
# CONNECTION
# =====================================================
def get_connection():
    return sqlite3.connect(DB_NAME)


# =====================================================
# INIT DATABASE
# =====================================================
def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # =================================================
    # PACKETS
    # =================================================
    cursor.execute("""
     CREATE TABLE IF NOT EXISTS packets (

         id INTEGER PRIMARY KEY AUTOINCREMENT,

         timestamp TEXT,

         src_ip TEXT,
         dst_ip TEXT,

         src_port INTEGER,
         dst_port INTEGER,

         protocol TEXT,

         size INTEGER
     )
     """)

    # =================================================
    # ALERTS
    # =================================================
    cursor.execute("""
     CREATE TABLE IF NOT EXISTS alerts (

         id INTEGER PRIMARY KEY AUTOINCREMENT,

         timestamp TEXT,

         alert_type TEXT,
         severity TEXT,

         description TEXT,

         score REAL
     )
     """)

    # =================================================
    # FLOWS
    # =================================================
    cursor.execute("""
     CREATE TABLE IF NOT EXISTS flows (

         id INTEGER PRIMARY KEY AUTOINCREMENT,

         timestamp TEXT,

         src_ip TEXT,
         dst_ip TEXT,

         src_port INTEGER,
         dst_port INTEGER,

         protocol TEXT,

         packet_count INTEGER,
         total_bytes INTEGER,

         duration REAL
     )
     """)

    # =================================================
    # INDEXES
    # =================================================
    cursor.execute("""
     CREATE INDEX IF NOT EXISTS idx_packets_timestamp
     ON packets(timestamp)
     """)

    cursor.execute("""
     CREATE INDEX IF NOT EXISTS idx_packets_src_ip
     ON packets(src_ip)
     """)

    conn.commit()
    conn.close()

    print("[DB] Database initialized")


# =====================================================
# SAVE PACKET
# =====================================================
def save_packet(packet):
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
         INSERT INTO packets (

             timestamp,

             src_ip,
             dst_ip,

             src_port,
             dst_port,

             protocol,

             size

         )
         VALUES (?, ?, ?, ?, ?, ?, ?)
         """, (

            packet["timestamp"].strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            packet["src_ip"],
            packet["dst_ip"],

            packet["src_port"],
            packet["dst_port"],

            packet["protocol"],

            packet["size"]
        ))

        conn.commit()
        conn.close()


# =====================================================
# SAVE ALERT
# =====================================================
def save_alert(alert_type,
               severity,
               description,
               score):
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
         INSERT INTO alerts (

             timestamp,

             alert_type,
             severity,

             description,

             score

         )
         VALUES (?, ?, ?, ?, ?)
         """, (

            datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            alert_type,
            severity,
            description,
            score
        ))

        conn.commit()
        conn.close()


# =====================================================
# SAVE FLOW
# =====================================================
def save_flow(flow):
    with db_lock:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
         INSERT INTO flows (

             timestamp,

             src_ip,
             dst_ip,

             src_port,
             dst_port,

             protocol,

             packet_count,
             total_bytes,

             duration

         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         """, (

            datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            flow["src_ip"],
            flow["dst_ip"],

            flow["src_port"],
            flow["dst_port"],

            flow["protocol"],

            flow["packet_count"],
            flow["total_bytes"],

            flow["duration"]
        ))

        conn.commit()
        conn.close()