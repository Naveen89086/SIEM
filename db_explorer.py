import sqlite3
import json
import io
import sys

# Set encoding for stdin and stdout to utf-8 if possible
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

DB_PATH = 'siem.db'
OUTPUT_PATH = 'db_content.md'

def explore_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write("# Database Content Overview\n\n")
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row['name'] for row in cursor.fetchall()]
        
        f.write("## Tables\n")
        for table in tables:
            f.write(f"- {table}\n")
        
        for table in tables:
            f.write(f"\n## Table: {table}\n")
            
            # Schema
            f.write("### Schema\n")
            f.write("| Column | Type |\n| --- | --- |\n")
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            for col in columns:
                f.write(f"| {col['name']} | {col['type']} |\n")

            # Sample Data
            f.write(f"\n### Sample Data (Last 5 records)\n")
            cursor.execute(f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT 5")
            rows = cursor.fetchall()
            
            if not rows:
                f.write("*No data found in this table.*\n")
                continue

            # Headers
            headers = rows[0].keys()
            f.write("| " + " | ".join(headers) + " |\n")
            f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")
            
            for row in rows:
                values = []
                for val in row:
                    # Handle potentially long or complex values
                    s_val = str(val).replace("\n", " ").replace("|", "\\|")
                    if len(s_val) > 100:
                        s_val = s_val[:97] + "..."
                    values.append(s_val)
                f.write("| " + " | ".join(values) + " |\n")

    conn.close()
    print(f"Database content successfully exported to {OUTPUT_PATH}")

if __name__ == "__main__":
    explore_db()
