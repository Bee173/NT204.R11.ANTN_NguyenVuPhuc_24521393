import argparse
import math
import time
from itertools import count
from pathlib import Path
from threading import Event, Lock, Thread

from src.capture import capture_live, capture_pcap
from src.core_engine.core_engine import CoreEngine
from src.pipeline import parse_packet
from src.decoder import decode_event
from src.preprocessor import preprocess_event
from src.flow_tracker import FlowTracker
from src.logger import prepare_output, log_event


def positive_timeout(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("Timeout must be positive and finite")
    return number


def positive_integer(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Value must be greater than 0")
    return number


def build_parser():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface")
    source.add_argument("--pcap")
    parser.add_argument("--output", default="output/events.jsonl")
    parser.add_argument("--flow-output", default="output/flows.jsonl")
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--tcp-timeout", type=positive_timeout, default=120)
    parser.add_argument("--udp-timeout", type=positive_timeout, default=30)
    parser.add_argument(
        "--max-decode-bytes", type=positive_integer, default=1048576
    )
    parser.add_argument(
        "--max-form-fields", type=positive_integer, default=1000
    )
    parser.add_argument("--allow-invalid", action="store_true")
    parser.add_argument("--allow-unsupported", action="store_true")
    parser.add_argument(
        "--rules",
        nargs="+",
        help="Snort rule files used by the Core Engine",
    )
    parser.add_argument(
        "--detection-output",
        default="output/detections.jsonl",
        help="JSONL output for Detection Events",
    )
    return parser


def evaluate_event(engine, event):
    if (
        engine is None
        or not isinstance(event, dict)
        or event.get("processing_action") != "continue"
    ):
        return ()
    return engine.process_event(event)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if Path(args.output).resolve() == Path(args.flow_output).resolve():
        parser.error("--output and --flow-output must be different files")
    if args.rules and Path(args.detection_output).resolve() in {
        Path(args.output).resolve(),
        Path(args.flow_output).resolve(),
    }:
        parser.error(
            "--detection-output must be different from event and flow outputs"
        )

    prepare_output(args.output)
    prepare_output(args.flow_output)

    engine = None
    if args.rules:
        prepare_output(args.detection_output)
        engine = CoreEngine.from_rule_files(args.rules)
        for issue in engine.load_issues:
            print(f"[RULE LOAD WARNING] {issue.source}: {issue.reason}")
        for rule in engine.rejected_rules:
            reasons = ", ".join(rule.reasons) or "disabled"
            print(
                f"[RULE {rule.status.value.upper()}] "
                f"{rule.source}:{rule.line_number}: {reasons}"
            )

    packet_counter = count(1)
    tracker = FlowTracker(args.tcp_timeout, args.udp_timeout)
    lock = Lock()
    stop_timer = Event()

    def write_finished():
        for flow in tracker.drain_finished():
            log_event(flow, args.flow_output)

    def handle_packet(packet):
        packet_id = next(packet_counter)
        event = parse_packet(packet, packet_id)
        event["packet_length"] = len(packet)
        event = decode_event(event, config={
            "max_decode_bytes": args.max_decode_bytes,
            "max_form_fields": args.max_form_fields,
        })
        event = preprocess_event(event, config={
            "skip_invalid": not args.allow_invalid,
            "skip_unsupported": not args.allow_unsupported,
        })

        detections = ()
        with lock:
            # PCAP dùng timestamp packet; live dùng thời gian hiện tại.
            now = time.time() if args.interface else event.get("timestamp")
            if now is not None:
                tracker.expire_flows(now)

            event = tracker.track_event(event)

            detections = evaluate_event(engine, event)
            for detection in detections:
                log_event(detection, args.detection_output)

            # Xuất ngay flow vừa CLOSED/RESET.
            if now is not None:
                tracker.expire_flows(now)

            write_finished()
            log_event(event, args.output)

        print(
            f"[{packet_id}] "
            f"{event.get('src_ip')} -> {event.get('dst_ip')} "
            f"{event.get('transport_protocol')} "
            f"{event.get('application_protocol')}"
        )
        for detection in detections:
            print(
                f"[ALERT] sid={detection['sid']} "
                f"msg={detection['msg']} "
                f"{detection['src_ip']}:{detection['src_port']} -> "
                f"{detection['dst_ip']}:{detection['dst_port']}"
            )

    def check_live_timeout():
        while not stop_timer.wait(1):
            with lock:
                tracker.expire_flows(time.time())
                write_finished()

    timer = None
    if args.interface:
        timer = Thread(target=check_live_timeout, daemon=True)
        timer.start()

    try:
        if args.interface:
            capture_live(args.interface, handle_packet, args.count)
        else:
            capture_pcap(args.pcap, handle_packet)
    except KeyboardInterrupt:
        print("\nStopping capture")
    finally:
        stop_timer.set()
        if timer is not None:
            timer.join()

        with lock:
            tracker.flush()
            write_finished()


if __name__ == "__main__":
    main()
