from itertools import groupby

# this file is WIP

cosy_dir = "/home/gfedrech/Developer/inria/dev/RIOT-FORK/build/pkg/cosy"
firmware_dir = "/home/gfedrech/Developer/inria/paper-edhoc-tls/code-edhoc-dtls-comparison/firmware"
riot_dir = "/home/gfedrech/Developer/inria/dev/RIOT-FORK"

symbols_filter = {
    "edhoc": [""],
    "dtls": [
        "", "internal.o", "aes.o", "tls13.o", "asn.o", "tls.o", "ssl.o", "dtls13.o", "ecc.o",
        "md5.o", "keys.o", "dtls.o", "sha.o", "hmac.o", "memory.o", "hash.o", "wc_port.o"
    ],
}

def find_sizes_lib(protocol):
    pass
    mode = "shell"

    cmd = f"""\
    {cosy_dir}/cosy.py -d \\
    --riot-base {riot_dir} \\
    {firmware_dir} \\
    nrf52840dk \\
    {firmware_dir}/bin/nrf52840dk/edhoc-dtls-1_3-comparison-{protocol}-{mode}.elf \\
    {firmware_dir}/bin/nrf52840dk/edhoc-dtls-1_3-comparison-{protocol}-{mode}.map \\
    | egrep "^\\{{'sym'" \\
    # | head
    """

    symbols = []
    res = run_cmd(cmd)
    for item in res.split("\n"):
        try:
            item = eval(item.strip())
        except:
            continue
        # print(">>>", item["sym"], item["size"])
        symbols.append(item)

    # group symbols by 'obj'
    # symbols = [(k, list(v)) for k, v in groupby(symbols, lambda x: x["obj"])]
    # symbols = {k: list(v) for k, v in groupby(symbols, lambda x: x["obj"])}

    symbols = [e for e in symbols if e["obj"] in symbols_filter[protocol]]
    rich.print(symbols)

    lib_size = sum([e["size"] for e in symbols])
    rich.print(f"Lib size: {lib_size}")


find_sizes_lib("edhoc")
# find_sizes_lib("dtls")
