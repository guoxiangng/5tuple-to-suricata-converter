import csv
import sys

def convert_to_suricata_rule_tcp(action, protocol, src_ip, src_port, dest_ip, dest_port, host_header_domain, msg, sid, rev):
    sid = int(sid)
    # Construct Suricata rule
    suricata_rule = (
        f"{action} {protocol} {src_ip} any -> {dest_ip} {dest_port} "
        f"(http.host; content:\"{host_header_domain}\"; endswith; "
        f"flow:to_server, established; msg:\"{msg}\"; sid:{sid+1}; rev:{rev};)"
    )
    return suricata_rule

def convert_to_suricata_rule_tls(action, protocol, src_ip, src_port, dest_ip, dest_port, host_header_domain, msg, sid, rev):
    # Construct Suricata rule
    suricata_rule = (
        f"{action} tls {src_ip} any -> {dest_ip} {dest_port} "
        f"(tls.sni; content:\"{host_header_domain}\"; endswith; "
        f"flow:to_server, established; msg:\"{msg}\"; sid:{sid}; rev:{rev};)"
    )
    return suricata_rule

def convert_to_suricata_rule_nofqdncheck(action, protocol, src_ip, src_port, dest_ip, dest_port, host_header_domain, msg, sid, rev):
    # Construct Suricata rule
    suricata_rule = (
        f"{action} tls {src_ip} any -> {dest_ip} {dest_port} "
        f"(flow:to_server, established; msg:\"{msg}\"; sid:{sid}; rev:{rev};)"
    )
    return suricata_rule

def process_csv(csv_file):
    try:
        with open(csv_file, mode='r', newline='') as file, open(rules_file, mode='w') as rules_out:
            csv_reader = csv.DictReader(file)
            headers = csv_reader.fieldnames  # Get the headers from the CSV
            # print(f"CSV Headers: {headers}")  # Print headers for debugging
            
            for row in csv_reader:
                # print(f"Processing row: {row}")  # Print each row for debugging
                
                action = row['Action']
                protocol = row['Protocol']
                src_ip = row['Src_IP']
                src_port = row['Src_Port']
                dest_ip = row['Dest_IP']
                dest_port = row['Dest_Port']
                host_header_domain = row['http host header domain to match']
                msg = row['msg']
                sid = row['sid']
                rev = row['rev']

                if host_header_domain == "":
                    suricata_rule_nofqdncheck = convert_to_suricata_rule_nofqdncheck(action, protocol, src_ip, src_port, dest_ip, dest_port, host_header_domain, msg, sid, rev)
                    rules_out.write(suricata_rule_nofqdncheck + '\n')
                else: 
                    # Generate Suricata rule
                    suricata_rule_tcp = convert_to_suricata_rule_tcp(action, protocol, src_ip, src_port, dest_ip, dest_port, host_header_domain, msg, sid, rev)
                    suricata_rule_tls = convert_to_suricata_rule_tls(action, protocol, src_ip, src_port, dest_ip, dest_port, host_header_domain, msg, sid, rev)
                    # Write the rule to the rules file
                    rules_out.write(suricata_rule_tls + '\n')
                    rules_out.write(suricata_rule_tcp + '\n')

    except FileNotFoundError:
        print(f"Error: CSV file '{csv_file}' not found.")
    except KeyError as e:
        print(f"Error: Missing column in CSV file: {str(e)}")
    except Exception as e:
        print(f"Error occurred while processing CSV file: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_suricata_rules.py <path_to_csv_file>")
        sys.exit(1)

    csv_file = sys.argv[1]
    rules_file = sys.argv[2]
    process_csv(csv_file)
