import subprocess, rich, serial, re, sys, datetime
import pandas as pd

if len(sys.argv) < 2:
    print(f"Please provide an output folder, e.g. python3 {sys.argv[0]} ../data_analysis/results")
    exit(1)
now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
output_file = sys.argv[1] + f"/memory-{now}.csv"
print(f"Will write to {output_file}")

def run_cmd(cmd):
    print(f"Will run: {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        raise Exception(f"Failed to run: {cmd}")
    print(f"Run ok.")
    return res.stdout

def get_memory_sizes(res):
    def get_dict(res):
        res = res.split("\n")[-3:-1]
        headers = res[0].split('\t')
        values = res[1].split('\t')
        headers = [h.strip() for h in headers]
        values = [v.strip() for v in values]
        values = [int(v) for v in values[:-2]] + values[-2:]
        res_dict = dict(zip(headers, values))
        # rich.print(res_dict)
        return res_dict
    res_dict = get_dict(res)
    return {"flash": res_dict["text"] + res_dict["data"], "ram-static": res_dict["data"] + res_dict["bss"]}

def run_riot_shell(cmd, port):
    print(f"Will run at {port}: {cmd}")
    with serial.Serial(port, 115200, timeout=1) as ser:
        ser.write(f"{cmd}\n".encode())
        res = ser.read(1000).decode()
        print(f"Run ok: {res}")
        return res

def get_stack_size(boards, protocol):
    # run the responder/server first, then the initiator/client
    run_riot_shell(boards[1][f"{protocol}_cmd"], boards[1]["port"])
    res_init_client = run_riot_shell(boards[0][f"{protocol}_cmd"], boards[0]["port"])
    if not "end handshake ok" in res_init_client:
        raise Exception(f"Failed to run {protocol} ci: {res_init_client}")

    # run ps and parse the stack size
    res_ps = run_riot_shell("ps", boards[0]["port"])
    ps_sum = [r for r in res_ps.split("\n") if "SUM" in r][0]
    ps_match = re.search(r'\(\s*\d+\)', ps_sum)
    if not ps_match:
        raise Exception(f"Failed to parse ps output: {res_ps}")

    return int(ps_match.group(0)[1:-1])

protocols = ["edhoc", "dtls"]
# modes = ["shell", "eval"]
mode = "shell"

data = {
    "protocol": [],
    "flash": [],
    "ram-static": [],
    "ram-stack": [],
}

boards = [
    { # initiator / client,
        "id": "000683380505", "port": "/dev/ttyACM0",
        "edhoc_cmd": "edhoci", "dtls_cmd": "dtlsc fe80::b834:d60b:796f:8de0",
    },
    { # responder / server,
        "id": "001050283894", "port": "/dev/ttyACM1",
        "edhoc_cmd": "edhocr", "dtls_cmd": "dtlss",
    },
]

for protocol in protocols:
    # Step 1 -- compile and measure flash and static ram
    cmd = f"make BOARD=nrf52840dk SEC={protocol} MODE={mode}"
    res = run_cmd(cmd)
    sizes = get_memory_sizes(res)
    rich.print(f"Sizes:", sizes)
    data["protocol"].append(protocol)
    data["flash"].append(sizes["flash"])
    data["ram-static"].append(sizes["ram-static"])

    # Step 2 -- flash
    run_cmd(f"DEBUG_ADAPTER_ID={boards[0]['id']} {cmd} flash")
    run_cmd(f"DEBUG_ADAPTER_ID={boards[1]['id']} {cmd} flash")

    run_riot_shell(f"reboot", boards[0]["port"])
    run_riot_shell(f"reboot", boards[1]["port"])

    # Step 3 -- run and measure stack
    stack_size = get_stack_size(boards, protocol)

    data["ram-stack"].append(stack_size)
    # break

df = pd.DataFrame(data)
df.to_csv(output_file, index=False)
rich.print(df)
print(f"Wrote results to csv: {output_file}")
