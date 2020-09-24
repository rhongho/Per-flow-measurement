gcc -I/usr/include/json-c/ -o rflow rflow.c hash_table.c queue.c rule_matcher.c utility.c stat_update.c -lpcap -lpthread -ljson-c
