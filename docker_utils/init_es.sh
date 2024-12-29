#!/bin/bash

until curl -ks -u $ELASTIC_USERNAME:$ELASTIC_PASSWORD "https://localhost:9200"; do
  echo "Waiting for Elasticsearch..."
  sleep 5
done

# Creare il template
curl -ks -X PUT -u $ELASTIC_USERNAME:$ELASTIC_PASSWORD "https://localhost:9200/_template/predator?pretty" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["predator-*"],
  "settings": {
    "number_of_shards": 1
  },
  "mappings": {
    "_source": {
      "enabled": true
    },
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "src_ip": {
        "type": "keyword"
      },
      "src_port": {
        "type": "keyword"
      },
      "dst_ip": {
        "type": "keyword"
      },
      "dst_port": {
        "type": "keyword"
      },
      "protocol": {
        "type": "keyword"
      },
      "flags": {
        "type": "keyword"
      },
      "event": {
        "type": "keyword"
      },
      "content_size": {
        "type": "keyword"
      },
      "content_session_id": {
        "type": "keyword"
      },
      "content_whitelisted": {
        "type": "keyword"
      },
      "reporting": {
        "type": "keyword"
      },
      "sni": {
        "type": "keyword"
      },
      "host": {
        "type": "keyword"
      },
      "payload": {
        "type": "text"
      },
      "rdata": {
        "type": "keyword"
      },
      "fqdn": {
        "type": "keyword"
      }
    }
  }
}
'
