import angr
import csv
import dgl
import angr
import csv
import os
from tqdm import tqdm
from capstone import *
import binascii
import json
import ast

def read_edges():
    pass

def read_represenation_vec():
    pass

def read_single_cfg_from_csv(CFG_Nodes,CFG_Edges):
    # 从CSV文件读取节点信息，并创建从节点地址到索引的映射
    address_to_index = {}
    for idx in range(len(CFG_Nodes)):
        address_to_index[CFG_Nodes[idx]] = idx

    # 初始化DGL图
    g = dgl.DGLGraph()

    # 向图中添加节点
    g.add_nodes(len(address_to_index))

    # 从CSV文件读取边信息，并添加到图中

    for row in CFG_Edges:
        src = address_to_index[row[0]]
        dst = address_to_index[row[1]]
        g.add_edge(src, dst)

    return g

def read_cfg_from_csv(path=r"\\ZJNU-NSR\Malware\Microsoft\CFG",representation_method="malconv"):
    G=[]
    # address_to_index = {}
    nodes_msg_list=[]
    with open(os.path.join(path,"edges.csv") , 'r') as nodes_file:
        reader = csv.DictReader(nodes_file)
        for idx, row in enumerate(reader):
            File_Name=row['File Name']
            CFG_Nodes=ast.literal_eval(row['CFG Nodes'])
            CFG_Edges = ast.literal_eval(row['CFG Edges'])
            Basicblock_Instructions_Count=row['Basicblock Instructions Count']

            # print(CFG_Nodes)
            # print(CFG_Edges)

            g=read_single_cfg_from_csv(CFG_Nodes,CFG_Edges)
            # print(g)

            G.append(g)

    with open(os.path.join(path,representation_method+".csv") , 'r') as representation_file:
        reader = csv.DictReader(representation_file)
        for idx, row in enumerate(reader):
            File_Name = row['File Name']
            vec = ast.literal_eval(row['vec'])
            nodes_msg_list.append(vec)

    return G,nodes_msg_list

# def read_cfg_from_csv1(node_csv_path, edge_csv_path):
#     # 从CSV文件读取节点信息，并创建从节点地址到索引的映射
#     address_to_index = {}
#     nodes_msg=[]
#     with open(node_csv_path, 'r') as nodes_file:
#         reader = csv.DictReader(nodes_file)
#         for idx, row in enumerate(reader):
#             address_to_index[row['Node']] = idx
#             nodes_msg.append(row['Byte Information'])
#     # print(address_to_index)
#
#     # 初始化DGL图
#     g = dgl.DGLGraph()
#
#     # 向图中添加节点
#     g.add_nodes(len(address_to_index))
#
#     # 从CSV文件读取边信息，并添加到图中
#     with open(edge_csv_path, 'r') as edges_file:
#         reader = csv.DictReader(edges_file)
#         for row in reader:
#             src = address_to_index[row['Source']]
#             dst = address_to_index[row['Destination']]
#             g.add_edge(src, dst)
#
#     return g,nodes_msg


if __name__ == '__main__':
    print(read_cfg_from_csv())
    # 调用函数，提取CFG信息并写入CSV
    # folder_path = r'\\ZJNU-NSR\Malware\Microsoft\train_exe'  # 替换为您的文件夹路径
    # output_csv_path = r'\\ZJNU-NSR\Malware\Microsoft\CFG\edges.csv'  # 替换为您的输出CSV文件路径
    # malware_shaixuan_list = list(get_sample_list_from_csv(csv_save_path=r"C:\Users\Administrator\Desktop\Asm2VecPlus修改稿\代码\CFG特征赋予\malware_msg_last.csv"))
    # get_edges_msg(folder_path,malware_shaixuan_list,output_csv_path)