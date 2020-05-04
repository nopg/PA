import api_lib_pa as pa_api

print(f"xpath for security rules = {pa_api.XPATH_SECURITYRULES}")

pa_ip = "192.168.77.254"
username = "apiuser"
password = "!apiuser!"

pa = pa_api.api_lib_pa(pa_ip, username, password)

XPATH = pa_api.XPATH_NETWORK_INTERFACES

interfaces = pa.grab_api_output("xml", XPATH, "output/interfaces-output.xml")
