import angr
import csv
import os
from tqdm import tqdm
from capstone import *
import binascii
from representation_method import malconv,n_gram_1,n_gram_2,n_gram_3,split_basicblock_byte,instruction_count
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
    for node in cfg.graph.nodes():
        # print(node.addr)
        byte_info = p.loader.memory.load(node.addr, node.size)
        byte_sequences.append(byte_info.hex())
    # exit()
    return edges, byte_sequences

# 遍历文件夹并处理每个文件
def get_edges_msg(folder_path, shaixuan_list,output_csv_path):
    with open(output_csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['File Name', 'CFG Edges', 'Basicblock Byte Sequence','Basicblock Instructions Count'])

        # 遍历文件夹中的所有文件
        # for filename in tqdm(os.listdir(folder_path)):
        for filename in tqdm(shaixuan_list):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                try:
                    # 创建angr项目
                    p = angr.Project(file_path, auto_load_libs=False)
                    # 提取CFG信息
                    edges, byte_sequences = extract_cfg_info(p)

                    instruction_counts=instruction_count(byte_sequences)
                    # 写入CSV文件
                    writer.writerow([filename, str(edges), str(byte_sequences), str(instruction_counts).replace(" ", "")])
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



def representation_method_func(basicblock_byte_seq,representation_method):
    basicblock_vec_list=[]
    if representation_method=="malconv":
        basicblock_vec_list=malconv(basicblock_byte_seq)
    elif representation_method == "n_gram_1":
        basicblock_vec_list=n_gram_1(dim=256, hex_asm=basicblock_byte_seq)
    elif representation_method == "n_gram_2":
        basicblock_vec_list=n_gram_2(dim=256, hex_asm=basicblock_byte_seq)
    elif representation_method == "n_gram_3":
        basicblock_vec_list=n_gram_3(dim=256, hex_asm=basicblock_byte_seq)
    return basicblock_vec_list

def get_basicblock_seq_vec_list(byte_sequences,representation_method="n_gram_1"):
    seq_vec_list=[]
    for basicblock in byte_sequences:
        basicblock_byte_seq=split_basicblock_byte(basicblock)
        basicblock_vec_list=representation_method_func(basicblock_byte_seq,representation_method)
        seq_vec_list.append(basicblock_vec_list)
    return str(seq_vec_list).replace(" ", "")

import os

def make_csv(representation_methods=["malconv","n_gram_1"]):
    mulu=r"\\ZJNU-NSR\Malware\Microsoft\CFG"
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
def featured_cfg(folder_path,shaixuan_list,representation_methods=["malconv","n_gram_1","n_gram_2","n_gram_3"]):


    csvfile_dict,csvfile_writer_dict=make_csv(representation_methods)

        # 遍历文件夹中的所有文件
    # for filename in tqdm(os.listdir(folder_path)):
    for filename in tqdm(shaixuan_list):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            # try:
                # 创建angr项目
                p = angr.Project(file_path, auto_load_libs=False)
                # 提取CFG信息
                edges, byte_sequences = extract_cfg_info(p)


                for representation_method in representation_methods:
                    malconv=get_basicblock_seq_vec_list(byte_sequences, representation_method=representation_method)
                    csvfile_writer_dict[representation_method].writerow([filename, str(malconv)])






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
    folder_path = r'\\ZJNU-NSR\Malware\Microsoft\train_exe'  # 替换为您的文件夹路径
    output_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges2.csv'  # 替换为您的输出CSV文件路径

    malware_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\malware_msg_last.csv"))
    # get_edges_msg(folder_path,malware_shaixuan_list,output_csv_path)
    featured_cfg(folder_path,malware_shaixuan_list,["malconv","n_gram_1","n_gram_2","n_gram_3"])

    # folder_path = r'\\ZJNU-NSR\Benign\benign_last1'  # 替换为您的文件夹路径
    # output_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges.csv'  # 替换为您的输出CSV文件路径
    # benign_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\benign_msg_last.csv"))[:2]
