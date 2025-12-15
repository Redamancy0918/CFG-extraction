import angr
import csv
import os
from tqdm import tqdm
from capstone import *
import binascii
from representation_method import malconv,n_gram_1,n_gram_2,n_gram_3,split_basicblock_byte,instruction_count,Asm2VecPlus,Asm2VecBase,Magic


def get_function_name(addr, project):
    # 查找给定地址的函数名称
    function_name = None
    try:
        # 尝试从符号表中获取函数名称
        function_name = project.kb.labels.get(addr)
    except Exception as e:
        print(f"Could not find function name for address {addr}: {e}")

    return function_name
# 定义提取CFG信息的函数
def extract_cfg_info(p):
    cfg = p.analyses.CFGFast(show_progressbar=True,
                             normalize=False,
                             resolve_indirect_jumps=False,
                             force_smart_scan=False,
                             symbols=False,
                             data_references=False)
    # 提取CFG边信息
    edges = [(edge[0].addr, edge[1].addr) for edge in cfg.graph.edges()]

    # print(edges)
    # edges = cfg.graph.edges()
    # print(edges)

    # 提取CFG中每个基本块的字节序列信息
    byte_sequences = []
    nodes_addr = []
    for node in cfg.graph.nodes():
        if node.is_call_site:
            call_targets = node.successors
            for target in call_targets:
                # 如果目标地址在项目的符号表中，则获取函数名
                target_name = get_function_name(target.addr, project)
                if target_name:
                    # 如果找到了函数名，则添加到函数调用图中
                    fcg[node.addr] = target_name
                else:
                    # 如果没有找到函数名，可能是内部函数或者没有符号信息的外部函数
                    # 在这种情况下，可以使用地址作为标识
                    fcg[node.addr] = f"sub_{target.addr}"
        print(fcg)
        exit()
        byte_info = p.loader.memory.load(node.addr, node.size)
        byte_sequences.append(byte_info.hex())
        nodes_addr.append(node.addr)
    # exit()
    return edges, nodes_addr,byte_sequences

def extract_cfg_info_magic(p):
    cfg = p.analyses.CFGFast(show_progressbar=True,
                             normalize=False,
                             resolve_indirect_jumps=False,
                             force_smart_scan=False,
                             symbols=False,
                             data_references=False)
    # 提取CFG边信息
    edges = [(edge[0].addr, edge[1].addr) for edge in cfg.graph.edges()]

    # 提取CFG中每个基本块的字节序列信息
    byte_sequences = []
    nodes_addr = []
    offspring_counts = {}  # 存储每个节点的子节点数量
    instructions_in_vertex = {}  # 存储每个节点的指令数量

    for node in cfg.graph.nodes():
        byte_info = p.loader.memory.load(node.addr, node.size)
        byte_sequences.append(byte_info.hex())
        nodes_addr.append(node.addr)

        # 计算每个节点的子节点（offspring）个数
        offspring_counts[node.addr] = len(list(cfg.graph.successors(node)))

        # 计算每个顶点中的指令数量
        block = p.factory.block(node.addr)
        instructions_in_vertex[node.addr] = len(block.capstone.insns)

    # 返回边信息、节点地址、字节序列信息、子节点数量信息和顶点中的指令数量信息
    return edges, nodes_addr, byte_sequences, offspring_counts, instructions_in_vertex
# 遍历文件夹并处理每个文件
def get_edges_msg(folder_path, shaixuan_list,output_csv_path):
    with open(output_csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['File Name','CFG Nodes', 'CFG Edges', 'Basicblock Byte Sequence','Basicblock Instructions Count'])

        # 遍历文件夹中的所有文件
        # for filename in tqdm(os.listdir(folder_path)):
        for filename in tqdm(shaixuan_list):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                try:
                    # 创建angr项目
                    p = angr.Project(file_path, auto_load_libs=False)
                    # 提取CFG信息
                    edges,nodes_addr,byte_sequences = extract_cfg_info(p)

                    instruction_counts=instruction_count(byte_sequences)
                    # 写入CSV文件
                    writer.writerow([filename, str(nodes_addr),str(edges), str(byte_sequences), str(instruction_counts).replace(" ", "")])
                except Exception as e:
                    print(f"Error processing file {filename}: {e}")



def split_basicblock_byte(asm_bytes):
    code_list = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    HexCode = binascii.unhexlify(asm_bytes)
    for item in md.disasm(HexCode, 0):
        hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
        code_list.append(hex_string)
    return code_list



def representation_method_func(basicblock_byte_seq,representation_method,offspring=1,instructions_in_vertex=1):
    basicblock_vec_list=[]
    if representation_method=="malconv":
        basicblock_vec_list=malconv(basicblock_byte_seq)
        return basicblock_vec_list
    elif representation_method == "n_gram_1":
        basicblock_vec_list=n_gram_1(dim=256, hex_asm=basicblock_byte_seq)
        return basicblock_vec_list
    elif representation_method == "n_gram_2":
        basicblock_vec_list=n_gram_2(dim=256, hex_asm=basicblock_byte_seq)
        return basicblock_vec_list
    elif representation_method == "n_gram_3":
        basicblock_vec_list=n_gram_3(dim=256, hex_asm=basicblock_byte_seq)
        return basicblock_vec_list
    elif representation_method == "Asm2VecPlus_8":
        Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list=Asm2VecPlus(hex_asm=basicblock_byte_seq)
        return Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list

    elif representation_method == "Asm2VecBase_8":
        Asm2VecBase_8_vec_list,Asm2VecBase_16_vec_list,Asm2VecBase_32_vec_list,Asm2VecBase_64_vec_list,Asm2VecBase_128_vec_list,Asm2VecBase_256_vec_list=Asm2VecBase(hex_asm=basicblock_byte_seq)
        return Asm2VecBase_8_vec_list,Asm2VecBase_16_vec_list,Asm2VecBase_32_vec_list,Asm2VecBase_64_vec_list,Asm2VecBase_128_vec_list,Asm2VecBase_256_vec_list

    elif representation_method == "Magic":
        basicblock_vec_list=Magic(hex_asm=basicblock_byte_seq,offspring=offspring,instructions_in_vertex=instructions_in_vertex)
        return basicblock_vec_list

def Asm2VecBase_get_basicblock_seq_vec_list(byte_sequences,representation_method="Asm2VecBase_8"):

    Asm2VecBase_8_vec_list,Asm2VecBase_16_vec_list,Asm2VecBase_32_vec_list,Asm2VecBase_64_vec_list,Asm2VecBase_128_vec_list,Asm2VecBase_256_vec_list\
        =representation_method_func(byte_sequences,representation_method)

    return  str(Asm2VecBase_8_vec_list).replace(" ", ""), str(Asm2VecBase_16_vec_list).replace(" ", ""), str(Asm2VecBase_32_vec_list).replace(" ", ""),\
    str(Asm2VecBase_64_vec_list).replace(" ", ""), str(Asm2VecBase_128_vec_list).replace(" ", ""), str(Asm2VecBase_256_vec_list).replace(" ", "")


def Asm2VecPlus_get_basicblock_seq_vec_list(byte_sequences,representation_method="Asm2VecPlus_8"):


    Asm2VecPlus_8_vec_list,Asm2VecPlus_16_vec_list,Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,Asm2VecPlus_128_vec_list,Asm2VecPlus_256_vec_list\
        =representation_method_func(byte_sequences,representation_method)

    return  str(Asm2VecPlus_8_vec_list).replace(" ", ""), str(Asm2VecPlus_16_vec_list).replace(" ", ""), str(Asm2VecPlus_32_vec_list).replace(" ", ""),\
    str(Asm2VecPlus_64_vec_list).replace(" ", ""), str(Asm2VecPlus_128_vec_list).replace(" ", ""), str(Asm2VecPlus_256_vec_list).replace(" ", "")



def get_basicblock_seq_vec_list(byte_sequences,representation_method="n_gram_1",offspring=1,instructions_in_vertex=1):
    seq_vec_list=[]
    for basicblock in byte_sequences:
        basicblock_byte_seq=split_basicblock_byte(basicblock)
        basicblock_vec_list=representation_method_func(basicblock_byte_seq,representation_method,offspring,instructions_in_vertex)
        seq_vec_list.append(basicblock_vec_list)
    return str(seq_vec_list).replace(" ", "")

import os

def make_csv_add(mulu,representation_methods=["malconv","n_gram_1"]):

    csvfile_dict={}
    csvfile_writer_dict={}
    for representation_method in representation_methods:
        path=os.path.join(mulu,representation_method+".csv")

        csvfile = open(path, 'a', newline='')
        csvfile_writer = csv.writer(csvfile)
        # csvfile_writer.writerow(['File Name', 'vec'])

        csvfile_dict[representation_method]=csvfile
        csvfile_writer_dict[representation_method]=csvfile_writer

    return csvfile_dict,csvfile_writer_dict

def make_csv(mulu,representation_methods=["malconv","n_gram_1"]):

    csvfile_dict={}
    csvfile_writer_dict={}
    for representation_method in representation_methods:
        path=os.path.join(mulu,representation_method+".csv")

        csvfile = open(path, 'w', newline='')
        csvfile_writer = csv.writer(csvfile)
        csvfile_writer.writerow(['File Name', 'vec'])

        csvfile_dict[representation_method]=csvfile
        csvfile_writer_dict[representation_method]=csvfile_writer

    return csvfile_dict,csvfile_writer_dict

def close_csv(representation_methods,csvfile_dict):
    for representation_method in representation_methods:
        csvfile_dict[representation_method].close()
def featured_cfg(folder_path,shaixuan_list,mulu,representation_methods=["malconv","n_gram_1","n_gram_2","n_gram_3"]):


    csvfile_dict,csvfile_writer_dict=make_csv(mulu,representation_methods)
    # csvfile_dict, csvfile_writer_dict = make_csv_add(mulu, representation_methods)

        # 遍历文件夹中的所有文件
    # for filename in tqdm(os.listdir(folder_path)):
    for filename in tqdm(shaixuan_list):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            # try:

                # 创建angr项目
                p = angr.Project(file_path, auto_load_libs=False)
                # 提取CFG信息
                edges,nodes_addr, byte_sequences = extract_cfg_info(p)
                # edges, nodes_addr, byte_sequences, offsprings, instructions_in_vertex = extract_cfg_info_magic(p)

                for representation_method in representation_methods:

                    if "Asm2VecPlus_8" == representation_method:
                        Asm2VecPlus_8_vec_list, Asm2VecPlus_16_vec_list, Asm2VecPlus_32_vec_list,Asm2VecPlus_64_vec_list,\
                        Asm2VecPlus_128_vec_list, Asm2VecPlus_256_vec_list = Asm2VecPlus_get_basicblock_seq_vec_list(byte_sequences,representation_method=representation_method)
                        csvfile_writer_dict["Asm2VecPlus_8"].writerow([filename, Asm2VecPlus_8_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_16"].writerow([filename, Asm2VecPlus_16_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_32"].writerow([filename, Asm2VecPlus_32_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_64"].writerow([filename, Asm2VecPlus_64_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_128"].writerow([filename, Asm2VecPlus_128_vec_list])
                        csvfile_writer_dict["Asm2VecPlus_256"].writerow([filename, Asm2VecPlus_256_vec_list])
                        break
                    elif "Asm2VecBase_8" == representation_method:
                        Asm2VecBase_8_vec_list, Asm2VecBase_16_vec_list, Asm2VecBase_32_vec_list, \
                        Asm2VecBase_64_vec_list, Asm2VecBase_128_vec_list, Asm2VecBase_256_vec_list \
                            = Asm2VecBase_get_basicblock_seq_vec_list(byte_sequences,
                                                                  representation_method=representation_method)


                        csvfile_writer_dict["Asm2VecBase_8"].writerow([filename, Asm2VecBase_8_vec_list])
                        csvfile_writer_dict["Asm2VecBase_16"].writerow([filename, Asm2VecBase_16_vec_list])
                        csvfile_writer_dict["Asm2VecBase_32"].writerow([filename, Asm2VecBase_32_vec_list])
                        csvfile_writer_dict["Asm2VecBase_64"].writerow([filename, Asm2VecBase_64_vec_list])
                        csvfile_writer_dict["Asm2VecBase_128"].writerow([filename, Asm2VecBase_128_vec_list])
                        csvfile_writer_dict["Asm2VecBase_256"].writerow([filename, Asm2VecBase_256_vec_list])


                        break
                    elif  "Magic" == representation_method:
                        a = get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method,offspring=offsprings,instructions_in_vertex=instructions_in_vertex)
                        csvfile_writer_dict[representation_method].writerow([filename, str(a).replace(" ", "")])
                    else:
                        a=get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method)
                        csvfile_writer_dict[representation_method].writerow([filename, str(a).replace(" ","")])


    close_csv(representation_methods,csvfile_dict)


def get_sample_list_from_csv(csv_save_path="../data/malware_msg_last.csv"):
    file_list = []
    with open(csv_save_path, 'r', encoding='utf-8') as f:
        # 经下述操作后，reader成为了一个可以迭代行的文件
        reader = csv.reader(f)
        # 先拿出csv文件的首行（一般是基本名称说明的行），此时指针指向下一行
        header = next(reader)
        for row in reader:
            file_name = row[0]
            file_list.append(file_name)
    return file_list

if __name__ == '__main__':

    # 调用函数，提取CFG信息并写入CSV
    # folder_path = r'\\ZJNU-NSR\Benign\benign_last1'  # 替换为您的文件夹路径
    # mulu = r"\\ZJNU-NSR\Malware\Microsoft\CFG_benign"
    # begnin_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\benign_msg_last.csv"))
    # for i in range(len(begnin_shaixuan_list)):
    #     begnin_shaixuan_list[i]=begnin_shaixuan_list[i].replace(".gexf","")




    folder_path = r'\\ZJNU-NSR\Malware\Microsoft\train_exe'  # 替换为您的文件夹路径
    output_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges2.csv'  # 替换为您的输出CSV文件路径
    mulu=r"\\ZJNU-NSR\Malware\Microsoft\CFG_test"
    malware_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\malware_msg_last.csv"))
    # get_edges_msg(folder_path,malware_shaixuan_list,output_csv_path)
    featured_cfg(folder_path,malware_shaixuan_list,mulu,["malconv","n_gram_1","n_gram_2","n_gram_3"])
    # featured_cfg(folder_path,malware_shaixuan_list,mulu,["Asm2VecPlus_8","Asm2VecPlus_16","Asm2VecPlus_32","Asm2VecPlus_64","Asm2VecPlus_128","Asm2VecPlus_256"])
    # featured_cfg(folder_path,malware_shaixuan_list,mulu,["Asm2VecBase_8","Asm2VecBase_16","Asm2VecBase_32","Asm2VecBase_64","Asm2VecBase_128","Asm2VecBase_256"])
    # folder_path = r'\\ZJNU-NSR\Benign\benign_last1'  # 替换为您的文件夹路径
    # output_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges.csv'  # 替换为您的输出CSV文件路径
    # benign_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\benign_msg_last.csv"))[:2]
