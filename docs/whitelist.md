# Whitelists IP and domains
Predator allows filters to whitelist events raised.
File is in JSON format and placed in HOME_PREDATOR/conf/json/whitelist.json

Filter can be grouped as:
- **layer4**: array with key *all* or specific IP and key *procotolo_port* (one or multiple comma separated)
- **fqdn** -> dns_requests: array with values specific DNS resolutions
- **fqdn** -> all -> wild: array with values domains with wildcard as prefix
- **fqdn** -> all -> static: array with values specific domains

Below is reported the example of JSON used to whitelist IPs and domains

  ```json
{
  "layer4": {
    "all": "tcp_43,udp_123",
    "8.8.8.8": "udp_53,tcp_53,tcp_443,udp_443",
    "8.8.4.4": "udp_53,tcp_53,tcp_443,udp_443",
    "192.229.221.95": "tcp_80",
    "239.255.255.250": "udp_1900,udp_3702"
  },
  "fqdn": {
    "dns_requests": [
      "drive.google.com.",
      "raw.githubusercontent.com.",
      "github.com."
    ],
    "all": {
      "wild": [
        "*.update.microsoft.com.",
        "*.windowsupdate.com.",
        ...
      ],
      "static": [
        "safebrowsing.googleapis.com.",
        "download.docker.com.",
        "definitionupdates.microsoft.com.",
        "go.microsoft.com.",
        ...
      ]
    }
  }
}
  ```
