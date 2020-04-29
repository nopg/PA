import copy

def modify(security_rules):

    modified_rules = []
    print("\nBob's Modifying...\n")

    if not security_rules:
        return None
    elif isinstance(security_rules, str):
        modified_string = security_rules.replace("me", "You")
        return modified_string

    for oldrule in security_rules:

        newrule = copy.deepcopy(oldrule)

        from_zone = oldrule["from"]["member"]
        to_zone = oldrule["to"]["member"]
        src_addr = oldrule["source"]["member"]
        dst_addr = oldrule["destination"]["member"]

        # Check and modify to intra-zone based rules
        # modify("source", "from", from_zone,src_addr)
        # modify("destination", "to", to_zone,dst_addr)

        print(f"From Zone = {from_zone}")
        print(f"To Zone = {to_zone}")
        print(f"Source Addresses = {src_addr}")
        print(f"Destination Addresses = {dst_addr}")

        newrule["source"]["member"] = "MODIFIED!"
        newrule["from"]["member"] = ["zone1"]
        newrule["from"]["member"].append("zone2")

        modified_rules.append(newrule)

    print("..Done.")
    return modified_rules

if __name__ == "__main__":
    print("\nYou called Bob directly...")
    x = modify("me")
    print(x)
    print()