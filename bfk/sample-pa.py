import api_lib_pa as pa_api

print(f"xpath for security rules = {pa_api.XPATH_SECURITYRULES}")

pa_ip = "10.20.30.40"
username = "username"
password = "password"

pa = pa_api.api_lib_pa(pa_ip, username, password)

XPATH = pa_api.XPATH_NETWORK_INTERFACES

interfaces = pa.grab_api_output("xml", XPATH, "output/interfaces-output.xml")
