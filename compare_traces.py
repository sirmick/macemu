#!/usr/bin/env python3
"""
Compare CPU instruction traces from UAE and Unicorn backends.
Finds the first point where the traces diverge.
"""

import sys

def main():
    uae_file = "uae_100k.log"
    unicorn_file = "unicorn_100k.log"

    print(f"Opening {uae_file} and {unicorn_file}...")

    with open(uae_file, 'r') as uae, open(unicorn_file, 'r') as unicorn:
        line_num = 0
        match_count = 0

        while True:
            uae_line = uae.readline()
            unicorn_line = unicorn.readline()

            # Check if either file ended
            if not uae_line and not unicorn_line:
                print(f"\n✓ Files are identical! All {match_count} lines match.")
                return 0
            elif not uae_line:
                print(f"\n⚠ UAE trace ended at line {line_num}, but Unicorn continues")
                print(f"Next Unicorn line: {unicorn_line.rstrip()}")
                return 1
            elif not unicorn_line:
                print(f"\n⚠ Unicorn trace ended at line {line_num}, but UAE continues")
                print(f"Next UAE line: {uae_line.rstrip()}")
                return 1

            line_num += 1

            # Compare lines
            if uae_line == unicorn_line:
                match_count += 1
                if match_count % 1000 == 0:
                    print(f"  {match_count} lines match so far...")
            else:
                # Found divergence!
                print(f"\n✗ DIVERGENCE at line {line_num}")
                print(f"\nUAE     : {uae_line.rstrip()}")
                print(f"Unicorn : {unicorn_line.rstrip()}")

                # Show a few lines of context before
                print(f"\n--- Context (last 3 matching lines) ---")
                uae.seek(0)
                unicorn.seek(0)
                lines = []
                for i in range(line_num):
                    u = uae.readline()
                    lines.append(u)
                    unicorn.readline()

                for i in range(max(0, len(lines) - 3), len(lines)):
                    print(f"  [{i+1}] {lines[i].rstrip()}")

                # Show a few lines after
                print(f"\n--- Next few lines ---")
                print(f"UAE:")
                for i in range(3):
                    next_line = uae.readline()
                    if next_line:
                        print(f"  [{line_num + i + 1}] {next_line.rstrip()}")

                print(f"\nUnicorn:")
                unicorn.seek(0)
                for i in range(line_num):
                    unicorn.readline()
                for i in range(3):
                    next_line = unicorn.readline()
                    if next_line:
                        print(f"  [{line_num + i + 1}] {next_line.rstrip()}")

                return 1

if __name__ == "__main__":
    sys.exit(main())
