import json

with open("fixtures/policies/invoices_readonly.json") as f:
    policy = json.load(f)

for statement in policy["Statement"]:

    print("Effect:", statement["Effect"])
    print("Action:", statement["Action"])
    print("Resource:", statement["Resource"])
