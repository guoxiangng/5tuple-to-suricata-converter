# 5 Tuple to Suricata Converter Script

- This is a simple python script to convert 5 tuple firewall rules into suricata format. 
- It assumes typical http/https traffic and caters for a specific pattern of 5 tuple + domain filtering per rule. 
- The script converts each TCP rule which has a whitelisted domain indicated into 2 rules - 
- One with a TLS SNI check and another with a http.host check (this would require decryption and inspecting the packet)

## To run the script

```
python csv_to_suricata.py suricata.csv suricata.rules
```
