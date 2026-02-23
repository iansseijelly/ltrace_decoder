import json
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, required=True) # the file to touch
    parser.add_argument("--binary", type=str, required=True) # the binary name to modify
    parser.add_argument("--asid_range", type=str, required=True) # the ASID range to add
    args = parser.parse_args()

    with open(args.config, "r") as f:
        config = json.load(f)

    # modify the config
    start, end = args.asid_range.split("-")
    for user_binary in config["user_binaries"]:
        if user_binary["binary"] == args.binary:
            user_binary["asids"] = list(range(int(start), int(end)))
            break

    with open(args.config, "w") as f:
        json.dump(config, f, indent=4)