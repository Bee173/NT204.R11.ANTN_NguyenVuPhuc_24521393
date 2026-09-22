import argparse
from itertools import count

from src.capture import capture_live, capture_pcap
from src.pipeline import parse_packet
from src.logger import prepare_output, log_event


def build_parser():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface")
    source.add_argument("--pcap")
    parser.add_argument("--output", default="output/events.jsonl")
    parser.add_argument("--count", type=int, default=0)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    prepare_output(args.output)
    packet_counter = count(1)

    def handle_packet(packet):
        packet_id = next(packet_counter)
        event = parse_packet(packet, packet_id)
        log_event(event, args.output)
        print(
            f"[{packet_id}] "
            f"{event['src_ip']} -> {event['dst_ip']} "
            f"{event['transport_protocol']} "
            f"{event['application_protocol']}"
        )

    if args.interface:
        capture_live(args.interface, handle_packet, args.count)

    if args.pcap:
        capture_pcap(args.pcap, handle_packet)


if __name__ == "__main__":
    main()