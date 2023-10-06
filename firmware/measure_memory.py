import subprocess, rich, serial, re, sys, datetime, os
import pandas as pd

if len(sys.argv) < 2:
    print(f"Please provide an output folder, e.g. python3 {sys.argv[0]} ../data_analysis/results")
    exit(1)
if os.path.isdir(sys.argv[1]):
    now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    output_file = sys.argv[1] + f"/memory-{now}.csv"
else:
    output_file = sys.argv[1]
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
    for unused_field in ["dec", "hex", "filename"]:
        del res_dict[unused_field]
    # return {"flash": res_dict["text"] + res_dict["data"], "ram-static": res_dict["data"] + res_dict["bss"]}
    return res_dict

def run_riot_shell(cmd, port):
    print(f"Will run at {port}: {cmd}")
    with serial.Serial(port, 115200, timeout=1) as ser:
        ser.write(f"{cmd}\n".encode())
        res = ser.read(1000).decode()
        print(f"Run ok: {res}")
        return res

def get_stack_size(boards, protocol):
    if protocol is not "nosec":
        # run the responder/server first, then the initiator/client
        run_riot_shell(boards[1][f"{protocol}_cmd"], boards[1]["port"])
        res_init_client = run_riot_shell(boards[0][f"{protocol}_cmd"], boards[0]["port"])
        if not "end handshake ok" in res_init_client:
            raise Exception(f"Failed to run {protocol} ci: {res_init_client}")

    # run ps and parse the stack size
    res_ps = run_riot_shell("ps", boards[0]["port"])
    line_to_filter = "main"
    ps_target_line = [line for line in res_ps.split("\n") if line_to_filter in line][0]
    ps_match = re.search(r'\(\s*\d+\)', ps_target_line) # search for something like "( 7480) (  712)"
    if not ps_match:
        raise Exception(f"Failed to parse ps output: {res_ps}")

    return int(ps_match.group(0)[1:-1]) # get the first match, e.g. 7480

def get_heap_size(boards, protocol):
    res_heap = run_riot_shell("heap", boards[0]["port"])
    heap_general_line = [line for line in res_heap.split("\n") if "Heap usage GENERAL:" in line][0]
    heap_io_line = [line for line in res_heap.split("\n") if "Heap usage IO:" in line][0]
    return int(heap_general_line.split(" ")[-2]) + int(heap_io_line.split(" ")[-2])

protocols = ["edhoc", "dtls_rpk", "dtls_rpk_mutual", "dtls_cert", "dtls_cert_mutual"]
# modes = ["shell", "eval"]
mode = "shell"

data = {
    "protocol": [],
    "text": [],
    "data": [],
    "bss": [],
    "stack": [],
    "heap": [],
}

dtls_client_cmd = "dtlsc fe80::5c0d:cee5:5196:8be8"
dtls_server_cmd = "dtlss"

connected_boards = run_cmd("for d in $(ls /dev/ttyACM*); do echo $d $(udevadm info $d | grep ID_SERIAL_SHORT | sed -E 's/.*=(.*)/\\1/g'); done | sort -u -k2,2 | sort")
connected_boards = connected_boards.strip().split("\n")
rich.print("Connected boards:", connected_boards)
boards = [
    { # initiator / client,
        "port": connected_boards[0].split(" ")[0],
        "id": connected_boards[0].split(" ")[1],
        "edhoc_cmd": "edhoci",
        "dtls_rpk_cmd": dtls_client_cmd,
        "dtls_cert_cmd": dtls_client_cmd,
        "dtls_rpk_mutual_cmd": dtls_client_cmd,
        "dtls_cert_mutual_cmd": dtls_client_cmd,
    },
    { # responder / server,
        "port": connected_boards[1].split(" ")[0],
        "id": connected_boards[1].split(" ")[1],
        "edhoc_cmd": "edhocr",
        "dtls_rpk_cmd": dtls_server_cmd,
        "dtls_cert_cmd": dtls_server_cmd,
        "dtls_rpk_mutual_cmd": dtls_server_cmd,
        "dtls_cert_mutual_cmd": dtls_server_cmd,
    },
]
rich.print("Board config:", boards)

rich.print("======== First pass with NOSEC ========")
# Step 1 -- compile and measure flash and static ram
cmd = f"make BOARD=nrf52840dk SEC=none MODE=shell"
res = run_cmd(cmd)
sizes_nosec = get_memory_sizes(res)
data["protocol"].append("nosec")
data["text"].append(sizes_nosec["text"])
data["data"].append(sizes_nosec["data"])
data["bss"].append(sizes_nosec["bss"])
# Step 2 -- flash
run_cmd(f"DEBUG_ADAPTER_ID={boards[0]['id']} {cmd} flash")
run_cmd(f"DEBUG_ADAPTER_ID={boards[1]['id']} {cmd} flash")
run_riot_shell(f"reboot", boards[0]["port"])
run_riot_shell(f"reboot", boards[1]["port"])
# Step 3 -- run and measure stack
stack_size_nosec = get_stack_size(boards, "nosec")
data["stack"].append(stack_size_nosec)
data["heap"].append(0)
df = pd.DataFrame(data)
rich.print(df)


for protocol in protocols:
    rich.print(f"======== Run with {protocol} ========")
    # Step 1 -- compile and measure flash and static ram
    cmd = f"make BOARD=nrf52840dk SEC={protocol} MODE={mode}"
    res = run_cmd(cmd)
    sizes = get_memory_sizes(res)
    sizes["text"] = sizes["text"]# - sizes_nosec["text"]
    sizes["data"] = sizes["data"]# - sizes_nosec["data"]
    sizes["bss"] = sizes["bss"]# - sizes_nosec["bss"]
    rich.print(f"Sizes:", sizes)
    data["protocol"].append(protocol)
    data["text"].append(sizes["text"])
    data["data"].append(sizes["data"])
    data["bss"].append(sizes["bss"])

    # Step 2 -- flash
    run_cmd(f"DEBUG_ADAPTER_ID={boards[0]['id']} {cmd} flash")
    run_cmd(f"DEBUG_ADAPTER_ID={boards[1]['id']} {cmd} flash")

    run_riot_shell(f"reboot", boards[0]["port"])
    run_riot_shell(f"reboot", boards[1]["port"])

    # Step 3 -- run and measure stack
    stack_size = get_stack_size(boards, protocol)# - stack_size_nosec
    data["stack"].append(stack_size)

    if protocol != "edhoc":
        # Step 4 -- run and measure heap
        heap_size = get_heap_size(boards, protocol)
        data["heap"].append(heap_size)
    else:
        data["heap"].append(0)

    df = pd.DataFrame(data)
    rich.print(df)

df.to_csv(output_file, index=False)
# rich.print(df)
print(f"Wrote results to csv: {output_file}")
