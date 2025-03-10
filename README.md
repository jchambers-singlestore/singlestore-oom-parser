# SingleStore OOM Parser

A tool for parsing and analyzing Out-Of-Memory (OOM) events from SingleStore engine logs.

## Features

- Identifies OOM events by thread ID and NTID
- Extracts memory allocation information in a hierarchical format
- Summarizes query memory usage by aggregator
- Visualizes memory allocator data in a tree-like structure
- Supports output to file or console

## Installation

Clone the repository:

```
git clone https://github.com/yourusername/singlestore-oom-parser.git
cd singlestore-oom-parser
```

No additional dependencies required beyond Python 3.6+.

## Usage

Basic usage:

```
python oom_parser.py path/to/engine.log
```

Save output to a file:

```
python oom_parser.py path/to/engine.log -o analysis.txt
```

## Example Output

```
Found 2 OOM events
==================================================
OOM Event #1 - 2025-03-03 14:25:07.454000
Thread ID: 99909, NTID: 3336646, Connection ID: 23162
--------------------------------------------------
Query Memory Usage:
  Select_glblFahBusEventDtl_005aefe35e8db03d (Select_glblFahBusEventDtl__et_al_a09e285ecf8008b3): 10987.43 MB (70.3%)
  Select_glblLyltTrans_89c7b2ae8f7a8e3f (Select_glblLyltTrans__et_al_793ec16293fc6c9a): 4638.51 MB (29.7%)
  Total Query Memory: 15625.94 MB

Memory Allocator Tree:
| Total_server_memory | 56810.1 (+24520.9) MB |
├─ | Alloc_thread_stacks | 3645.000 (-19.000) MB |
├─ | Malloc_active_memory | 4779.286 (+834.264) MB |
├─ | Buffer_manager_memory | 46044.6 (+23410.0) MB |
│  ├─ | Buffer_manager_cached_memory | 0.4 (-8872.4) MB |
│  ├─ | Alloc_query_execution | 42153.969 (+32386.211) MB |
│  ├─ | Alloc_table_memory | 4050.887 (+363.627) MB |
│     ├─ | Alloc_skiplist_tower | 411.125 (+3.125) MB |
│     ├─ | Alloc_variable | 1889.750 (+73.750) MB |
│     ├─ | Alloc_large_variable | 8.784 MB | * NOT included in Alloc_table_memory
│     ├─ | Alloc_table_primary | 1129.625 (+267.500) MB |
│     ├─ | Alloc_deleted_version | 240.375 (+19.875) MB |
│     ├─ | Alloc_internal_key_node | 59.125 MB |
│     ├─ | Alloc_hash_buckets | 268.145 MB | * NOT included in Alloc_table_memory
│     ├─ | Alloc_table_autostats | 43.959 (-0.623) MB |
├─ | Total_io_pool_memory | 53.5 MB |
├─ Alloc_replication_large (not found)
├─ Alloc_durability_large (not found)
├─ | Alloc_mmap_memory | 276.532 (+235.032) MB |
├─ | Alloc_compiled_unit_sections | 688.415 (+63.532) MB |
├─ Alloc_object_code_images (not found)
├─ | Alloc_unit_ifn_thunks | 3.047 (+0.040) MB |
├─ | Alloc_unit_images | 88.112 (+2.484) MB |
├─ | Alloc_variable_cached_buffers | 62.5 (-2.0) MB |
└─ | Alloc_variable_allocated | 925.4 MB |

==================================================
```

## Structure

The OOM events are identified by thread ID and network thread ID (NTID). For each event, the script outputs:

1. **Event metadata**: Timestamp, Thread ID, NTID, and Connection ID
2. **Query memory usage**: Memory consumed by each query/aggregator
3. **Memory allocator tree**: Hierarchical view of memory allocations

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
