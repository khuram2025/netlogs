"""Bounded online index maintenance; always restore normal compaction settings."""
import json
import time
from fastapi_app.db.clickhouse import ClickHouseClient as CH

c = CH.get_client()
name = 'max_bytes_to_merge_at_max_space_in_pool'
create = c.query("SELECT create_table_query FROM system.tables WHERE database='default' AND name='syslogs'").result_rows[0][0]
import re
existing = re.search(r'\b'+name+r' = (\d+)', create)
original = int(existing[1]) if existing else int(c.query(f"SELECT value FROM system.merge_tree_settings WHERE name='{name}'").result_rows[0][0])
try:
    # Avoid starving the additive index mutation behind repeated multi-GB merges.
    # The short maintenance window still permits small merges and all inserts.
    c.command(f'ALTER TABLE syslogs MODIFY SETTING {name}=1048576, number_of_free_entries_in_pool_to_execute_mutation=8, max_number_of_mutations_for_replica=1')
    c.command('SYSTEM STOP MERGES syslogs')
    c.command('SYSTEM START MERGES syslogs')
    deadline = time.monotonic()+300
    while time.monotonic() < deadline:
        remaining = c.query("SELECT max(parts_to_do) FROM system.mutations WHERE table='syslogs' AND mutation_id='mutation_103251.txt'").result_rows[0][0]
        print(json.dumps({'remaining_parts':remaining}), flush=True)
        if remaining == 0:
            break
        time.sleep(10)
finally:
    c.command(f'ALTER TABLE syslogs MODIFY SETTING {name}={original}, number_of_free_entries_in_pool_to_execute_mutation=20, max_number_of_mutations_for_replica=0')
    c.command('SYSTEM START MERGES syslogs')
    print(json.dumps({'normal_compaction_restored':True, 'original_merge_bytes':original}), flush=True)
    CH.close_client()
