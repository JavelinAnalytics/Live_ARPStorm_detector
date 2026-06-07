from scapy.all import ARP, sniff, wrpcap, conf
from scapy.error import Scapy_Exception


CAPTURE_SECONDS = 30 #adjust live packet capture sniffing time
THRESHOLD = 20 #adjust arp requests/second threshold rate definition of an arp storm


def filter_arp_requests(packets):
    """
    Filter and return only ARP request packets (op == 1).

    Args:
        packets: list of Scapy packet objects

    Returns:
        list of ARP request packets
    """

    arp_requests = [
        p for p in packets
        if ARP in p and p[ARP].op == 1
    ]

    return arp_requests


def calculate_arp_request_rate(arp_requests):
    """
    Calculate the average ARP request rate in requests per second.

    Args:
        arp_requests: list of ARP request packets

    Returns:
        float: average requests per second
    """

    if len(arp_requests) < 2:
        return 0.0

    first_time = arp_requests[0].time
    last_time = arp_requests[-1].time

    duration = last_time - first_time

    if duration == 0:
        return 0.0

    rate = len(arp_requests) / duration

    return rate


def detect_arp_storm(arp_requests, threshold=20):
    """
    Detect an ARP request storm and print a summary if detected.

    Args:
        arp_requests: list of ARP request packets
        threshold: int, requests/sec above which a storm is declared

    Returns:
        bool: True if storm detected, False otherwise
    """

    rate = calculate_arp_request_rate(arp_requests)

    if rate > threshold:
        source_macs = set()
        unique_ips = set()

        for packet in arp_requests:
            source_macs.add(packet[ARP].hwsrc)
            unique_ips.add(packet[ARP].psrc)
            unique_ips.add(packet[ARP].pdst)

        print(f"ARP STORM DETECTED")
        print(f"Rate: {rate:.2f} req/s")
        print(f"Total ARP requests: {len(arp_requests)}")
        print(f"Unique source MAC addresses: {len(source_macs)}")
        print(f"Unique IP addresses: {len(unique_ips)}")
        print(f"Source MAC address(es): {source_macs}")

        return True

    else:
        print(f"No ARP storm detected. Rate: {rate:.2f} req/s")

        return False


def run_live_detection(interface, duration, threshold):
    """
    Sniff ARP packets on the given interface for the given duration,
    save them to a pcap file named live_capture_<STUDENT_ID>.pcap,
    then run detect_arp_storm() on the captured packets.
    """

    print(f"Starting live ARP capture on interface: {interface}")
    print(f"Capture duration: {duration} seconds")

    captured = sniff(
        iface=interface,
        filter="arp",
        timeout=duration
    )

    print(f"Live packets captured: {len(captured)}")

    output_file = "live_capture.pcap"
    wrpcap(output_file, captured)

    print(f"Saved live capture to: {output_file}")

    arp_requests = filter_arp_requests(captured)

    print(f"Live ARP requests found: {len(arp_requests)}")

    detect_arp_storm(arp_requests, threshold)


def main():
    try:
        interfaces = list(conf.ifaces.values())
        print("Available network interfaces:")

        for index, iface in enumerate(interfaces, start=1):
            print(f"{index}. {iface.description}")
            print(f"Scapy name: {iface.name}")

        choice = input("\nEnter the network interface number to use: ").strip()

        if not choice:
            print("Error: Interface selection cannot be empty.")
            return

        if not choice.isdigit():
            print(f"Error: Please enter a valid number.")
            return

        choice = int(choice)

        if choice < 1 or choice > len(interfaces):
            print("Error: Interface number is out of range.")
            return

        selected_interface = interfaces[choice -1]

        print(f"\nSelected interface: {selected_interface.description}")

        run_live_detection(selected_interface.name, CAPTURE_SECONDS, THRESHOLD)

    except KeyboardInterrupt:
        print("\nCapture cancelled by user.")

    except PermissionError:
        print("Permission error: Run this script with administrator/root privileges.")

    except Scapy_Exception as e:
        print(f"Scapy error: {e}")

    except Exception as e:
        print(f"Unexpected Error: {e}")


if __name__ == "__main__":
    main()