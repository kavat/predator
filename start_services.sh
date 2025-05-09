#!/bin/bash

/usr/bin/redis-server /etc/redis/redis.conf 2>&1 &

tail -f /dev/null
