import angr
import csv
import dgl
# import torch
import angr
import csv
import os
from tqdm import tqdm
from capstone import *
import binascii
# from representation_method import malconv,n_gram_1,n_gram_2,n_gram_3,split_basicblock_byte,instruction_count,Asm2VecPlus,Asm2VecBase
def extract_cfg1(cfg):


    # 打开一个CSV文件来写入节点信息
    with open(r'\\ZJNU-NSR\Malware\Microsoft\CFG\nodes_test.csv', 'w', newline='') as nodes_file:
        nodes_writer = csv.writer(nodes_file)
        # 写入标题
        nodes_writer.writerow(['Node', 'Address', 'Byte Information', 'Ember', 'MAGIC', 'N-Gram1', 'N-Gram2', 'N-Gram3', 'Malconv', 'Asm2vecPlus', 'Asm2vecBase'])

        # 遍历CFG中的所有节点，并写入信息
        for node in cfg.graph.nodes():
            # 获取节点的字节信息，这可能需要额外的处理来适应你的需求
            byte_info = p.loader.memory.load(node.addr, node.size)
            nodes_writer.writerow([node, hex(node.addr), byte_info.hex()])

# # 打开一个CSV文件来写入节点信息
def extract_cfg_nodes(cfg):

    with open(r'\\ZJNU-NSR\Malware\Microsoft\CFG\nodes_test.csv', 'w', newline='') as nodes_file:
        nodes_writer = csv.writer(nodes_file)
        # 写入标题
        nodes_writer.writerow(['Node', 'Address', 'Byte Information', 'Basicblock Vector List'])

        # 遍历CFG中的所有节点，并写入信息
        for node in cfg.graph.nodes():
            # 获取节点的字节信息，这可能需要额外的处理来适应你的需求
            byte_info = p.loader.memory.load(node.addr, node.size)
            print(hex(node.addr))
            nodes_writer.writerow([node, hex(node.addr), byte_info.hex()])


# 打开一个CSV文件来写入边信息
def extract_cfg_edgs(cfg):

    with open(r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges_test.csv', 'w', newline='') as edges_file:
        edges_writer = csv.writer(edges_file)
        # 写入标题
        edges_writer.writerow(['Source', 'Destination'])

        # 遍历CFG中的所有边，并写入信息
        for edge in cfg.graph.edges():
            edges_writer.writerow([edge[0], edge[1]])


def read_cfg_from_csv(node_csv_path, edge_csv_path):
    # 从CSV文件读取节点信息，并创建从节点地址到索引的映射
    address_to_index = {}
    nodes_msg=[]
    with open(node_csv_path, 'r') as nodes_file:
        reader = csv.DictReader(nodes_file)
        for idx, row in enumerate(reader):
            address_to_index[row['Node']] = idx
            nodes_msg.append(row['Byte Information'])
    print(address_to_index)
    # exit()
    # 初始化DGL图
    g = dgl.DGLGraph()

    # 向图中添加节点
    g.add_nodes(len(address_to_index))

    # 从CSV文件读取边信息，并添加到图中
    with open(edge_csv_path, 'r') as edges_file:
        reader = csv.DictReader(edges_file)
        for row in reader:
            # print(row['Source'])
            # exit()
            src = address_to_index[row['Source']]

            dst = address_to_index[row['Destination']]
            g.add_edge(src, dst)

    return g,nodes_msg






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
        # print(node.addr)
        byte_info = p.loader.memory.load(node.addr, node.size)
        byte_sequences.append(byte_info.hex())
        nodes_addr.append(node.addr)
    # exit()
    return edges, nodes_addr,byte_sequences

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
                    edges,nodes_addr, byte_sequences = extract_cfg_info(p)

                    instruction_counts=instruction_count(byte_sequences)
                    # 写入CSV文件
                    writer.writerow([filename, str(nodes_addr),str(edges), str(byte_sequences), str(instruction_counts).replace(" ", "")])
                except Exception as e:
                    print(f"Error processing file {filename}: {e}")



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


def instruction_count(hex_asm):
    instruction_count_list = []
    for hex_asm_item in hex_asm:
        a = len(split_basicblock_byte(hex_asm_item))
        instruction_count_list.append(a)
    return instruction_count_list
def split_basicblock_byte(asm_bytes):
    code_list = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    HexCode = binascii.unhexlify(asm_bytes)
    for item in md.disasm(HexCode, 0):
        hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
        code_list.append(hex_string)
    return code_list

if __name__ == '__main__':
    # file_path = r"\\ZJNU-NSR\Malware\Microsoft\train_exe\3mpsxg2FODqCAXHbMKPi"
    # p = angr.Project(file_path, auto_load_libs=False)
    #
    # cfg = p.analyses.CFGFast(show_progressbar=True,
    #                          normalize=False,
    #                          resolve_indirect_jumps=False,
    #                          force_smart_scan=False,
    #                          symbols=False,
    #                          data_references=False)
    # extract_cfg_nodes(cfg)
    # extract_cfg_edgs(cfg)
    #
    # # 指定您的CSV文件路径
    # node_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\nodes_test.csv'
    # edge_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges_test.csv'
    #
    # # 创建DGL图
    # cfg_dgl_graph,nodes_msg = read_cfg_from_csv(node_csv_path, edge_csv_path)
    # print(cfg_dgl_graph.edges())
    # print(nodes_msg)
    # 调用函数，提取CFG信息并写入CSV
    folder_path = r'\\ZJNU-NSR\Malware\Microsoft\train_exe'  # 替换为您的文件夹路径
    output_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges.csv'  # 替换为您的输出CSV文件路径
    # mulu=r"\\ZJNU-NSR\Malware\Microsoft\CFG"
    malware_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\malware_msg_last.csv"))
    get_edges_msg(folder_path,malware_shaixuan_list,output_csv_path)