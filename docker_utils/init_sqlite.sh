#!/bin/bash

APP_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PATH_DB=$APP_DIR/../var/db
DB_NAME="predator.db"
TABLE_NAME="threats"

mkdir -p $PATH_DB

TABLE_STRUCTURE="id VARCHAR(32) PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, src_ip VARCHAR(15), src_port SMALLINT, dst_ip VARCHAR(15), dst_port SMALLINT, protocol VARCHAR(10), flags VARCHAR(10), content_whitelisted CHAR(1), content_size INTEGER, content_session_id VARCHAR(40), event VARCHAR(100), reporting VARCHAR(100), sni VARCHAR(100), host VARCHAR(100), payload TEXT, rdata VARCHAR(100), qname VARCHAR(100)"

# Verifica se SQLite è installato
if ! command -v sqlite3 &> /dev/null; then
  echo "Error: SQLite not installed."
  exit 1
fi

echo "Creating database '$DB_NAME' and table '$TABLE_NAME'..."
sqlite3 "${PATH_DB}/$DB_NAME" <<EOF
CREATE TABLE IF NOT EXISTS $TABLE_NAME (
    $TABLE_STRUCTURE
);
EOF

if [ $? -eq 0 ]; then
  echo "Table '$TABLE_NAME' created '$DB_NAME'."
else
  echo "Error during table creation."
  exit 1
fi
