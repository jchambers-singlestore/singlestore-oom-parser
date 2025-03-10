#!/usr/bin/env python3
import re
import sys
from collections import defaultdict
from datetime import datetime

class OOMEventParser:
    def __init__(self):
        self.oom_events = []
    
    def parse_file(self, filename):
        # Dictionary to track events by thread identifiers
        events = {}
        
        with open(filename, 'r') as file:
            for line in file:
                # Extract thread ID and NTID
                thread_match = re.search(r'Thread (\d+) \(ntid (\d+), conn id (\d+)\)', line)
                if not thread_match:
                    continue
                    
                thread_id, ntid, conn_id = thread_match.groups()
                thread_key = f"{thread_id}_{ntid}"
                
                timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})', line)
                if not timestamp_match:
                    continue
                    
                timestamp_str = timestamp_match.group(1)
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                
                # Create a new event if this thread key hasn't been seen before
                if thread_key not in events:
                    events[thread_key] = {
                        'thread_id': thread_id,
                        'ntid': ntid,
                        'conn_id': conn_id,
                        'timestamp': timestamp,
                        'allocator_data': [],
                        'query_memory': defaultdict(float),
                        'query_names': {}
                    }
                
                current_event = events[thread_key]
                
                # Process trace_SendRow lines (memory allocator dumps)
                trace_match = re.search(r'trace_SendRow: (.*)', line)
                if trace_match:
                    full_trace = trace_match.group(1)
                    parts = full_trace.split(' : ', 1)
                    
                    if len(parts) == 2:
                        key, value = parts
                        current_event['allocator_data'].append((key.strip(), value.strip()))
                    else:
                        # Some lines have different format
                        key = parts[0].strip()
                        value = ""
                        current_event['allocator_data'].append((key, value))
                
                # Process query memory information
                query_memory_match = re.search(r'Current query memory: (\d+\.\d+).*Activity name: (.*?) agg name: (.*?) Query text:', line)
                if query_memory_match:
                    memory, activity_name, agg_name = query_memory_match.groups()
                    memory_value = float(memory)
                    current_event['query_memory'][agg_name] += memory_value
                    current_event['query_names'][agg_name] = activity_name
        
        # Convert to list and sort by timestamp
        return [event for event in events.values() if event['allocator_data']]
    
    def get_total_memory_usage(self, event):
        """Calculate total memory used by all queries in an event"""
        return sum(event['query_memory'].values())
    
    def build_memory_tree(self, event):
        """Build a hierarchical representation of memory allocations"""
        allocator_dict = {}

        # Convert to dictionary for easier lookup
        for key, value in event['allocator_data']:
            allocator_dict[key] = value

        # Define the hierarchy structure (parent -> children)
        hierarchy = {
            'Total_server_memory': [
                'Alloc_thread_stacks',
                'Malloc_active_memory',
                'Buffer_manager_memory',
                'Total_io_pool_memory',
                'Alloc_replication_large',
                'Alloc_durability_large',
                'Alloc_mmap_memory',
                'Alloc_compiled_unit_sections',
                'Alloc_object_code_images',
                'Alloc_unit_ifn_thunks',
                'Alloc_unit_images'
            ],
            'Buffer_manager_memory': [
                'Buffer_manager_cached_memory',
                'Alloc_query_execution',
                'Alloc_table_memory'
            ],
            'Alloc_table_memory': [
                'Alloc_skiplist_tower',
                'Alloc_variable',
                'Alloc_large_variable',
                'Alloc_table_primary',
                'Alloc_deleted_version',
                'Alloc_internal_key_node',
                'Alloc_hash_buckets',
                'Alloc_table_autostats'
            ]
        }

        # Entries that are not included in their parent's memory calculation
        not_included = ['Alloc_large_variable', 'Alloc_hash_buckets']

        # Build the tree representation
        tree = []

        def format_entry(key, indent):
            if key in allocator_dict:
                return f"{indent}| {key} | {allocator_dict[key]} |"
            else:
                return f"{indent}{key} (not found)"

        # Start with the root (Total_server_memory)
        tree.append(format_entry('Total_server_memory', ""))

        def add_children(parent, indent_prefix=""):
            if parent not in hierarchy:
                return
                
            children = hierarchy[parent]
            for i, child in enumerate(children):
                is_last_child = (i == len(children) - 1)
                
                # Determine the prefix for this child
                if is_last_child:
                    child_prefix = f"{indent_prefix}└─ "
                    next_level_prefix = f"{indent_prefix}   "
                else:
                    child_prefix = f"{indent_prefix}├─ "
                    next_level_prefix = f"{indent_prefix}│  "
                
                # Add the child entry
                if child in allocator_dict:
                    entry = format_entry(child, child_prefix)
                    # Add note for items not included in parent calculation
                    if child in not_included:
                        entry += f" * NOT included in {parent}"
                    tree.append(entry)
                    
                    # Add this child's children
                    add_children(child, next_level_prefix)
                else:
                    tree.append(f"{child_prefix}{child} (not found)")

        add_children('Total_server_memory', "")
        
        # Add variable buffer information
        if 'Alloc_variable_cached_buffers' in allocator_dict:
            tree.append(f"├─ | Alloc_variable_cached_buffers | {allocator_dict['Alloc_variable_cached_buffers']} |")
        
        if 'Alloc_variable_allocated' in allocator_dict:
            tree.append(f"└─ | Alloc_variable_allocated | {allocator_dict['Alloc_variable_allocated']} |")
        
        return tree


def main():
    if len(sys.argv) < 2:
        print("Usage: python oom_parser.py <logfile>")
        sys.exit(1)
    
    logfile = sys.argv[1]
    parser = OOMEventParser()
    oom_events = parser.parse_file(logfile)
    
    # Sort events by timestamp
    oom_events.sort(key=lambda e: e['timestamp'])
    
    print(f"Found {len(oom_events)} OOM events")
    print("=" * 50)
    
    for i, event in enumerate(oom_events, 1):
        print(f"OOM Event #{i} - {event['timestamp']}")
        print(f"Thread ID: {event['thread_id']}, NTID: {event['ntid']}, Connection ID: {event['conn_id']}")
        print("-" * 50)
        
        # Print query memory usage
        print("Query Memory Usage:")
        total_memory = parser.get_total_memory_usage(event)
        
        if total_memory > 0:
            for agg_name, memory in sorted(event['query_memory'].items(), key=lambda x: x[1], reverse=True):
                activity_name = event['query_names'].get(agg_name, "Unknown")
                print(f"  {agg_name} ({activity_name}): {memory:.2f} MB ({(memory/total_memory)*100:.1f}%)")
        else:
            print("  No query memory information available")
        
        print(f"  Total Query Memory: {total_memory:.2f} MB")
        print()
        
        # Print memory tree
        print("Memory Allocator Tree:")
        for line in parser.build_memory_tree(event):
            print(line)
        
        print("\n" + "=" * 50)

if __name__ == "__main__":
    main()
