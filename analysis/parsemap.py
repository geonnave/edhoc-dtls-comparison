import re, subprocess, rich, sys, os, datetime
import pandas as pd

def run_cmd(cmd):
    print_debug(f"Will run: {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        raise Exception(f"Failed to run: {cmd}")
    print_debug(f"Run ok.")
    return res.stdout

def print_debug(*args):
    return
    rich.print(*args)

def get_between(marker_start, marker_end):
    return run_cmd(f"sed -n '/{marker_start}/,/{marker_end}/{{ /{marker_end}/!p }}' {map_file}")

def get_section(section_name):
    return run_cmd(f"sed -E -n '/^\.{section_name}/,${{p;/^$/q}}' {map_file}")

def run(map_file, section_names):
    memory_config = get_between("Memory Configuration", "Linker script and memory map")
    print_debug(memory_config)

    sections = {k: get_section(k) for k in section_names}

    # sections = {
    #     # "text": get_section("text"),
    #     # "bss": get_section("bss"),
    #     # "stack": get_section("stack"),
    #     "relocate": get_section("relocate"), # data
    # }

    for section_name, section in sections.items():
        print_debug("\n\n\n\n====================================")
        print_debug(section)

    def parse_section(section_text, section_name):
        print_debug("\n\n\n\n------------------------------------")
        lines = [line for line in section_text.split("\n") if len(line) > 0]
        first_line = [e for e in lines[0].strip().split(" ") if e != ""]
        section_size = int(first_line[2], 16)
        print_debug(f"Section {section_name} size: {section_size}")
        print_debug("------------------------------------")

        def still_in_header(line, in_header):
            sec_name = re.match(f"^\.{section_name}\s+", line)
            hex_addr = re.match(f"^\s*0x[0-9a-f]+", line)
            return sec_name or (in_header and hex_addr)

        current_symbol = None
        in_header = True
        symbols_content = {}
        for line in lines:
            if still_in_header(line, in_header):
                continue
            in_header = False

            new_symbol = re.match(" \.([a-z]+\.)?([-_\.A-Za-z0-9$.]+)", line)
            if new_symbol:
                current_symbol = new_symbol.group(2)
                symbols_content[current_symbol] = line
                continue

            if current_symbol:
                hex_addr = re.match(f"^\s*0x[0-9a-f]+", line)
                fill_bytes = re.match(f"^ \*fill\*", line)
                if hex_addr or fill_bytes:
                    symbols_content[current_symbol] += "\n "+line
                continue

        symbols_data = {}
        for name, content in symbols_content.items():
            lines = [line for line in content.split("\n")]
            size = 0
            address = None
            compilation_unit = None
            print_debug("\n<", name, "\n", content)
            for line in lines:
                line = [e for e in line.split(" ") if e != ""]
                if line[0][0] == "." and len(line) == 4:
                    # nice line with symbol name, like:
                    #  .bss.netreg    0x0000000020018388       0x14 /home/gfedrech/Developer/inria/paper-edhoc-tls/code-edhoc-dtls-comparison/firmware/bin/nrf52840dk/gnrc_netreg/gnrc_netreg.o
                    size += int(line[2], 16)
                    address = line[1]
                    compilation_unit = line[3]
                    print_debug("##", size)
                    print_debug("##", compilation_unit)
                elif line[0][:2] == "0x" and line[1][:2] == "0x" and len(line) == 3:
                    # line that was broken after symbol name, starting with address, like:
                    #                 0x0000000020019ba8        0x2 /home/gfedrech/Developer/inria/paper-edhoc-tls/code-edhoc-dtls-comparison/firmware/bin/nrf52840dk/gnrc_pktbuf_static/gnrc_pktbuf_static.o
                    size += int(line[1], 16)
                    address = line[0]
                    compilation_unit = line[2]
                    print_debug("##", size)
                    print_debug("##", compilation_unit)
                elif line[0] == "*fill*":
                    # fill line like:
                    #  *fill*         0x0000000020019baa        0x2
                    size += int(line[2], 16)
                    print_debug("##", size)
            print_debug(">")

            # if compilation_unit in symbols_data.keys():
            #     symbols_data[compilation_unit]

            symbols_data[name] = {
                "size": size,
                "address": address,
                "compilation_unit": compilation_unit,
            }
        # rich.print(symbols_data)
        # return section_size, symbols_data
        return {"size": section_size, "data": symbols_data}

    res = {k: parse_section(sections[k], k) for k in section_names}
    return res
    # parse_section(sections["relocate"], "relocate")


section_names = ["text", "bss", "relocate"]
# section_names = ["bss"]

# map_file = "../firmware/bin/nrf52840dk/edhoc-dtls-1_3-comparison-edhoc-shell.map"
map_files = {
    "edhoc": "../firmware/bin/nrf52840dk/edhoc-dtls-1_3-comparison-edhoc-shell.map",
    "dtls_rpk": "../firmware/bin/nrf52840dk/edhoc-dtls-1_3-comparison-dtls_rpk-shell.map",
    "dtls_cert": "../firmware/bin/nrf52840dk/edhoc-dtls-1_3-comparison-dtls_cert-shell.map",
    "dtls_rpk_mutual": "../firmware/bin/nrf52840dk/edhoc-dtls-1_3-comparison-dtls_rpk_mutual-shell.map",
    "dtls_cert_mutual": "../firmware/bin/nrf52840dk/edhoc-dtls-1_3-comparison-dtls_cert_mutual-shell.map",
}

# the objects in the pattern below where obtained with this command (with parsemap.py modified to print a unique list of compilation units):
# for s in $(python3 parsemap.py | egrep "edhoc-dtls-1_3-comparison|libedhoc_rs" --color | grep "(" | sed -E "s/.*\((.*)\).*/\1/g" | sort | uniq); do [ ! -z "$(grep -a "$s" /home/gfedrech/Developer/inria/dev/edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts/libnrf_cc310_0.9.13.a)" ] && echo -n "$s|"; done
cc310_objects_pattern = ".*(aesccm_driver.c.obj|aes_driver.c.obj|bypass_driver.c.obj|crys_aesccm.c.obj|crys_common_conv_endian.c.obj|crys_common_math.c.obj|crys_ecdh.c.obj|crys_ecpki_build_priv.c.obj|crys_ecpki_build_publ.c.obj|crys_ecpki_domain.c.obj|crys_ecpki_kg.c.obj|crys_hash.c.obj|crys_hkdf.c.obj|crys_hmac.c.obj|crys_rnd.c.obj|ec_wrst.c.obj|ec_wrst_genkey.c.obj|hash_driver.c.obj|llf_rnd.c.obj|llf_rnd_trng90b.c.obj|pka.c.obj|pka_ec_wrst.c.obj|pka_ec_wrst_smul_scap.c.obj|pki_modular_arithmetic.c.obj|sns_silib.c.obj|ssi_aes.c.obj|ssi_ecpki_domain_secp160k1.c.obj|ssi_ecpki_domain_secp160r1.c.obj|ssi_ecpki_domain_secp160r2.c.obj|ssi_ecpki_domain_secp192k1.c.obj|ssi_ecpki_domain_secp192r1.c.obj|ssi_ecpki_domain_secp224k1.c.obj|ssi_ecpki_domain_secp224r1.c.obj|ssi_ecpki_domain_secp256k1.c.obj|ssi_ecpki_domain_secp256r1.c.obj|ssi_ecpki_domain_secp384r1.c.obj|ssi_ecpki_domain_secp521r1.c.obj|ssi_ecpki_info.c.obj|ssi_hal.c.obj|ssi_pal_abort.c.obj|ssi_pal.c.obj|ssi_pal_dma.c.obj|ssi_pal_mem.c.obj|ssi_pal_mutex.c.obj|ssi_pal_trng.c.obj|ssi_rng_plat.c.obj|sw_hash_common.c.obj|sw_llfcd_hash_sha512.c.obj|sw_llf_hash_sha512.c.obj).*"

edhoc_rs_compilation_units_pattern = ".*(edhoc-dtls-1_3-comparison|libedhoc_rs).*"
wolfssl_compilation_units_pattern = ".*(edhoc-dtls-1_3-comparison|wolfcrypt|wolfssl).*"

wolfssl_heap_buffers_symbol_pattern = ".*(wolfssl_general_memory|wolfssl_io_memory).*"

edhoc_rs_cc310_rng_buffers_symbol_pattern = ".*(rnd_context|rnd_work_buffer).*"
wolfssl_cc310_rng_buffers_symbol_pattern = ".*(wc_rndState|wc_rndWorkBuff).*"

def check_pattern_comp_unit(comp_unit, configuration):
    if type(comp_unit) is not str:
        return False
    if configuration == "edhoc":
        return re.match(edhoc_rs_compilation_units_pattern, comp_unit) and not re.match(cc310_objects_pattern, comp_unit)
    else:
        return re.match(wolfssl_compilation_units_pattern, comp_unit)

def check_pattern_symbol(symbol, configuration):
    if type(symbol) is not str:
        return False
    if configuration == "edhoc":
        # return True
        return not re.match(edhoc_rs_cc310_rng_buffers_symbol_pattern, symbol) # discard cc310 rng buffers
    else:
        # discard heap and cc310 rng buffers
        return not re.match(wolfssl_heap_buffers_symbol_pattern, symbol) and \
            not re.match(wolfssl_cc310_rng_buffers_symbol_pattern, symbol)

def print_like_gnu_size(configuration, sections, sections_lib_only):
    rich.print(f"------------------------------------ only lib - {configuration}")
    rich.print("\t".join([sec for sec in sections_lib_only.keys()]))
    rich.print(
        "\t".join([str(sum([e["size"] for e in v.values()])) for v in [d for d in sections_lib_only.values()]])
    )

    rich.print("------------------------------------ total")
    rich.print("\t".join([sec for sec in sections.keys()]))
    rich.print("\t".join([str(value["size"]) for value in sections.values()]))

    rich.print("====================================\n\n\n")

def print_unique_list_of_compilation_units(sections):
    cunits = set()
    for sec, value in sections.items():
        [
            cunits.add(v["compilation_unit"])
            for k, v in value["data"].items()
            if v["compilation_unit"] is not None
        ]
    rich.print("\n".join(cunits))
    # exit(0)

df_values = {
    k: [] for k in ["protocol"] + section_names
}

# print(df_values)

for configuration, map_file in map_files.items():
    sections = run(map_file, section_names)

    # print_unique_list_of_compilation_units(sections)

    # rich.print(sections)
    sections_lib_only = {}
    for sec, value in sections.items():
        sections_lib_only[sec] = {
            symbol_name: d
            for symbol_name, d in value["data"].items()
            if check_pattern_comp_unit(d["compilation_unit"], configuration) and check_pattern_symbol(symbol_name, configuration)
        }
        # rich.print(sec)
    # rich.print(sections_lib_only)

    print_like_gnu_size(configuration, sections, sections_lib_only)

    # save values
    df_values["protocol"].append(configuration)
    for sec in section_names:
        df_values[sec].append(sum([e["size"] for e in sections_lib_only[sec].values()]))

if "relocate" in df_values.keys():
    df_values["data"] = df_values["relocate"]
    del df_values["relocate"]

df = pd.DataFrame(df_values)
df.set_index("protocol", inplace=True)
rich.print(df)

if len(sys.argv) < 2:
    print(f"Please provide an output folder, e.g. python3 {sys.argv[0]} ../data_analysis/results")
    exit(1)
if os.path.isdir(sys.argv[1]):
    now = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    output_file = sys.argv[1] + f"/static-memory-{now}.csv"
else:
    output_file = sys.argv[1]
print(f"Will write to {output_file}")

df.to_csv(output_file)
