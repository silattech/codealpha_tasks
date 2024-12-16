import argparse
import scapy.all as scapy


def sniffNetwork(interface=None,filter=""):        
    try:
        scapy.sniff(iface=interface,prn=process_packet,filter=filter)
    except ValueError as e:
        print(e)

def process_packet(x):
    print(x.summary())


def main():
    parser = argparse.ArgumentParser(description="Wasila's Network sniffer")
    parser.add_argument('-i','--interface', type=str, required=False, help="Specify the interface to sniff")
    parser.add_argument('-f',"--filter",type=str, required=False, help="Sniffer Filter")

    # Parse the arguments
    args = parser.parse_args()

    if args:
        if args.interface or args.filter:
            filter = ""

            if args.filter:
                print(f" ########## Showing packets for filter : {args.filter} ##########")
                filter = args.filter
            
            sniffNetwork(args.interface, filter)
        else:
            sniffNetwork()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()