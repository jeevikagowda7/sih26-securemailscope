"""
add_source_pcap.py
-------------------
What this does, in plain words:

Your all_summaries.json is organized like this:
  [
    { "pcap": "bad_capture1.pcap", "streams": [ {...}, {...} ] },
    { "pcap": "good_capture1.pcap", "streams": [ {...} ] },
    ...
  ]

The filename ("pcap") is only written ONCE per group, at the top.
Jeevika asked for it to be written INSIDE every individual stream
entry too, as a field called "source_pcap" - so that if she ever
looks at one stream by itself (without the surrounding group), she
still knows which pcap file it came from.

This script:
  1. Opens all_summaries.json
  2. For every group, copies the "pcap" filename into every stream
     inside it, under a new field called "source_pcap"
  3. Saves the result back to the same file (a backup of the
     original is made first, just in case)

Usage:
    python add_source_pcap.py
(run it from inside the folder that has all_summaries.json, or
 pass the path as an argument:)
    python add_source_pcap.py path\to\all_summaries.json
"""

import json
import sys
import shutil
import os


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "all_summaries.json"

    if not os.path.exists(path):
        print(f"File not found: {path}")
        print("Tip: run this script from inside the 'extracted_streams' folder,")
        print("or pass the full path to all_summaries.json as an argument.")
        sys.exit(1)

    # Make a backup first, so nothing is ever lost by mistake.
    backup_path = path + ".backup"
    shutil.copy(path, backup_path)
    print(f"Backup saved as: {backup_path}")

    with open(path, "r") as f:
        data = json.load(f)

    stream_count = 0
    for group in data:
        pcap_name = group.get("pcap")
        for stream in group.get("streams", []):
            stream["source_pcap"] = pcap_name
            stream_count += 1

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Done. Added 'source_pcap' to {stream_count} stream(s) across {len(data)} pcap group(s).")
    print(f"Saved to: {path}")


if __name__ == "__main__":
    main()
