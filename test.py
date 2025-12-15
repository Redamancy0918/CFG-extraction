import angr


def get_import_name(addr, project):

    # 尝试从项目的符号表中获取符号名称
    for symbol in project.loader.symbols:

        if symbol.rebased_addr == addr:
            return symbol.name

    # 尝试从导入表中获取函数名称
    for dll in project.loader.main_object.imports:
        if addr == project.loader.main_object.imports[dll].rebased_addr:
            return project.loader.main_object.imports[dll].name


    return None

def extract_fcg_from_cfg(project):
    cfg = project.analyses.CFGFast(show_progressbar=True,
                             normalize=False,
                             resolve_indirect_jumps=False,
                             force_smart_scan=False,
                             symbols=False,
                             data_references=False)
    fcg = {}

    for node in cfg.graph.nodes():
        # 检查节点的每条指令，看是否是调用指令
        block = project.factory.block(node.addr)
        for insn in block.capstone.insns:
            if insn.mnemonic == 'call':
                # 这是一个函数调用，获取目标地址
                target_addr = insn.operands[0].imm
                target_name = get_import_name(target_addr, project)
                if target_name:
                    fcg[hex(node.addr)] = target_name
                    # print(target_name)
                    # print("111111111111111")
                else:
                    # 如果不是导入函数，可能是内部函数调用
                    fcg[hex(node.addr)] = f"sub_{hex(target_addr)}"
    return fcg

# 示例用法
binary_path = r"\\ZJNU-NSR\Malware\malware_last\00d1a80da41899a98f53d770444dfdd5"
project = angr.Project(binary_path, auto_load_libs=False)
fcg = extract_fcg_from_cfg(project)
print(fcg)
