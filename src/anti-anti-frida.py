import lief
import sys
import random
import os

if __name__ == "__main__":
    input_file = sys.argv[1]
    print(f"[*] Patch frida-agent: {input_file}")
    random_name = "".join(random.sample("ABCDEFGHIJKLMNO", 5))
    print(f"[*] Patch `frida` to `{random_name}``")

    binary = lief.parse(input_file)

    if not binary:
        exit()

    for symbol in binary.symbols:
        if symbol.name == "frida_agent_main":
            symbol.name = "main"
        
        if "frida" in symbol.name:
            symbol.name = symbol.name.replace("frida", random_name)

        if "FRIDA" in symbol.name:
            symbol.name = symbol.name.replace("FRIDA", random_name)

    all_patch_string = ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]  # 字符串特征修改 尽量与源字符一样
    for section in binary.sections:
        print(section.name)
        if section.name != ".rodata":
            continue
        for patch_str in all_patch_string:
            addr_all = section.search_all(patch_str)  # Patch 内存字符串
            for addr in addr_all:
                patch = [ord(n) for n in list(patch_str)[::-1]]
                print(f"current section name={section.name} offset={hex(section.file_offset + addr)} {patch_str}-{''.join(list(patch_str)[::-1])}")
                binary.patch_address(section.file_offset + addr, patch)

    binary.write(input_file)
    # gum-js-loop thread
    random_name = "".join(random.sample("abcdefghijklmn", 11))
    print(f"[*] Patch `gum-js-loop` to `{random_name}`")
    os.system(f"sed -b -i s/gum-js-loop/{random_name}/g {input_file}")
    # gmain thread
    random_name = "".join(random.sample("abcdefghijklmn", 5))
    print(f"[*] Patch `gmain` to `{random_name}`")
    os.system(f"sed -b -i s/gmain/{random_name}/g {input_file}")
    # thread_gdbus
    random_name = "".join(random.sample("abcdefghijklmn", 5))
    print(f"[*] Patch `gdbus` to `{random_name}`")
    os.system(f"sed -b -i s/gdbus/{random_name}/g {input_file}")
