"""Entry point for the network packet analyzer."""
import yaml
from core.capture import PacketCapture
from core.detector import DetectionEngine
from output.logger import AlertLogger
from output.pcap_writer import PcapWriter
from ui.cli import parse_args


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    args = parse_args()

    if args.list_ifaces:
        for iface in PacketCapture.list_interfaces():
            print(f"  • {iface}")
        return

    config = load_config(args.config)

    # Apply CLI overrides
    if args.iface:
        config["capture"]["interface"] = args.iface
    if args.filter:
        config["capture"]["bpf_filter"] = args.filter
    if args.count is not None:
        config["capture"]["packet_count"] = args.count

    engine = DetectionEngine(config)
    logger = AlertLogger(config["output"]["log_file"])
    pcap = PcapWriter(config["output"]["pcap_file"])

    counter = {"packets": 0, "alerts": 0}

    def handle(packet):
        counter["packets"] += 1
        pcap.add(packet)

        info, alert = engine.handle(packet)

        if args.verbose and info:
            print(
                f"  {info['protocol']:5} "
                f"{str(info['src_ip']):15} -> {str(info['dst_ip']):15} "
                f"{info.get('dst_port') or ''}"
            )

        if alert:
            counter["alerts"] += 1
            print(alert.pretty())
            logger.write(alert)

    cap = PacketCapture(**config["capture"])
    print(f"🛡️  Sniffing on {config['capture']['interface']} "
          f"(filter: {config['capture']['bpf_filter']})")
    print("   Ctrl+C to stop\n")

    try:
        cap.start(handle)
    except KeyboardInterrupt:
        print("\n⏹  Stopping...")
    finally:
        pcap.flush()
        logger.close()
        print(f"\n📊 Captured {counter['packets']} packets, {counter['alerts']} alerts")


if __name__ == "__main__":
    main()