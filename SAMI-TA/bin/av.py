import socket

# Define the host names to check
hostnames = [
    "sfqpit75pjh525siewar2dtgt5.avts.mcafee.com",
    "4z9p5tjmcbnblehp4557z1d136.avqs.mcafee.com" ]

# Attempt to resolve the host names to IP addresses, capturing any failures
for hostname in hostnames:
    try:
        print socket.gethostbyname(hostname)
    except socket.error:
        print "DNS Query Failed"
