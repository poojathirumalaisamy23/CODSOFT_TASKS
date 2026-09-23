"""Command-line argument parsing."""
import argparse


def parse_args():
    p = argparse.ArgumentParser(
        prog="packet-analyzer",
        description="Mid-level network packet analyzer with threat detection",
    )
    p.add_argument("-i", "--iface", help="Network interface (overrides config)")
    p.add_argument("-f", "--filter", help="BPF filter (overrides config)")
    p.add_argument("-c", "--count", type=int, help="Stop after N packets (0=infinite)")
    p.add_argument("--config", default="config/config.yaml", help="Config file path")
    p.add_argument("-v", "--verbose", action="store_true", help="Print every packet")
    p.add_argument("--list-ifaces", action="store_true", help="List interfaces and exit")
    return p.parse_args()