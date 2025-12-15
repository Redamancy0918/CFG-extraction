import os
import networkx as nx
import dgl
import json
import csv
from tqdm import tqdm  # 引入tqdm
import concurrent.futures
from sklearn.model_selection import train_test_split
import ast
import torch
from torch.nn.utils.rnn import pad_sequence, pack_padded_sequence
csv.field_size_limit(1310720000)
import multiprocessing as mp
from torch.utils.data import Dataset, DataLoader
from functools import partial

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


class MalwareDataset(Dataset):
    def __init__(self, graphs, features, labels):
        self.graphs = graphs
        self.features = features
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.graphs[idx], self.features[idx], self.labels[idx]



def avrage_2list(features):
    avrage_features=[]
    for item_file in features:
        item_avrage_features=[]
        for basicblock in item_file:
            # print(basicblock)
            ean_values = [sum(col) / len(col) for col in zip(*basicblock)]
            item_avrage_features.append(ean_values)
        avrage_features.append(item_avrage_features)
    return avrage_features
def check_features_length(features):
    """
    检查特征列表中每个子列表的长度，确保它们都是非空且长度一致。
    如果有长度不一致的情况，打印出不一致的子列表的索引和长度。
    """
    # 存储所有子列表的长度
    lengths = []
    for i, sublist in enumerate(features):
        # 检查子列表是否为空
        if not sublist:
            print(f"子列表 {i} 是空的。")
            print(sublist)
        else:
            # 记录非空子列表的长度
            lengths.append((i, len(sublist)))

    # 检查长度是否一致
    if lengths:
        first_length = lengths[0][1]
        for index, length in lengths:
            if length != first_length:
                print(f"子列表 {index} 的长度是 {length}，与第一个子列表的长度 {first_length} 不一致。")

    return lengths
def collate_Node(batch_data):
    """
    自定义collate_fn函数来处理图数据和特征的批次。
    """
    # 解包批次中的图，特征和标签
    graphs, features, labels = zip(*batch_data)




    # 将图数据批次化
    batched_graph = dgl.batch(graphs)
    # print(graphs)
    # 填充特征以创建一个统一的特征张量
    # 假设所有特征都是等长的，如果不是，你可能需要在这里填充它们
    # batched_features

    if type(features[0][0][0])==list:
        avrage_features=avrage_2list(features)
        avrage_features = [f for sublist in avrage_features for f in sublist]
        batched_features = torch.tensor(avrage_features)
    else:
        # print(features)
        features=[f for sublist in features for f in sublist]
        # print(features)
        # check_features_length(features)
        batched_features = torch.tensor(features)
        # print("good")
        # exit()
    # 将标签张量化

    batched_labels = torch.tensor(labels)
    # exit()
    return batched_graph.to(device), batched_features.to(device), batched_labels.to(device)


def collate_NodeSequence(batch_data):
    """
    自定义collate_fn函数来处理图数据和特征的批次。
    """
    # 解包批次中的图，特征和标签
    graphs, features, labels = zip(*batch_data)

    # 将图数据批次化
    batched_graph = dgl.batch(graphs)
    # print(graphs)
    # 填充特征以创建一个统一的特征张量
    # 假设所有特征都是等长的，如果不是，你可能需要在这里填充它们
    # print(features)
    # print(labels)
    # exit()
    # print(features)
    features = [torch.tensor(f, dtype=torch.float32) for sublist in features for f in sublist]

    batched_features = pad_sequence(features,
                                    batch_first=True,
                                    padding_value=0)
    # print(len(batched_features))
    # print(batched_features)
    # exit()
    # 将标签张量化
    batched_labels = torch.tensor(labels)

    return batched_graph.to(device), batched_features.to(device), batched_labels.to(device)


def change_dim(vec,input_dim):

    if type(vec[0][0])==list:
        for basicblock in range(len(vec)):
            for instruction in range(len(vec[basicblock])):
                vec[basicblock][instruction]=vec[basicblock][instruction][:input_dim]
    else:
        for basicblock in range(len(vec)):
            vec[basicblock]=vec[basicblock][:input_dim]
    return vec


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





from concurrent.futures import ThreadPoolExecutor, as_completed
# 这是你的处理函数，它将被多线程调用
def process_row(row, input_dim=None):
    vec = ast.literal_eval(row['vec'])
    if input_dim is not None:
        vec = change_dim(vec, input_dim)
    return vec

def process_edge_row(row):
    CFG_Nodes = ast.literal_eval(row['CFG Nodes'])
    CFG_Edges = ast.literal_eval(row['CFG Edges'])
    g = read_single_cfg_from_csv(CFG_Nodes, CFG_Edges)
    return g


def read_cfg_from_csv_mutiple_thread(path=r"\\ZJNU-NSR\Malware\Microsoft\CFG",representation_method="malconv",input_dim=None,num_samples=None):
    G=[]
    # address_to_index = {}
    nodes_msg_list=[]

    print("加载边信息...")
    with open(os.path.join(path, "edges.csv"), 'r') as edges_file:
        reader = list(csv.DictReader(edges_file))  # 读取所有行到内存

        # 创建进程池
        with mp.Pool(processes=8) as pool:
            # 使用 imap 处理每一行
            results = pool.imap(process_edge_row, reader, chunksize=10)

            try:
                for idx, g in enumerate(tqdm(results)):
                    G.append(g)
                    if num_samples is not None and idx + 1 == num_samples:
                        break
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                raise

    # 初始化进程中要处理的数据
    print("加载节点信息...")
    with open(os.path.join(path, representation_method + ".csv"), 'r') as representation_file:
        reader = csv.DictReader(representation_file)
        # Create a pool of workers equal to the number of CPU cores
        with mp.Pool(processes=8) as pool:
            # 使用 partial 来创建一个新的带有 input_dim 参数的函数
            process_row_with_dim = partial(process_row, input_dim=input_dim)
            # 使用 imap 并传入新的函数和数据
            results = pool.imap(process_row_with_dim, reader, chunksize=10)
            try:
                for idx, vec in enumerate(tqdm(results)):
                    nodes_msg_list.append(vec)
                    if num_samples is not None and idx + 1 == num_samples:
                        break
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                raise
    return G,nodes_msg_list


def read_cfg_from_csv(path=r"\\ZJNU-NSR\Malware\Microsoft\CFG",representation_method="malconv",input_dim=None,num_samples=None):
    G=[]
    # address_to_index = {}
    nodes_msg_list=[]

    print("加载边信息...")
    with open(os.path.join(path,"edges.csv") , 'r') as nodes_file:
        reader = csv.DictReader(nodes_file)

        edges_count=0
        for idx, row in tqdm(enumerate(reader)):

            # File_Name=row['File Name']
            CFG_Nodes=ast.literal_eval(row['CFG Nodes'])
            CFG_Edges = ast.literal_eval(row['CFG Edges'])
            Basicblock_Instructions_Count=row['Basicblock Instructions Count']

            g=read_single_cfg_from_csv(CFG_Nodes,CFG_Edges)
            G.append(g)


            edges_count+=1
            if num_samples != None:
                if edges_count==num_samples:
                    break


    print("加载节点信息...")
    with open(os.path.join(path,representation_method+".csv") , 'r') as representation_file:
        reader = csv.DictReader(representation_file)
        nodes_count=0
        for idx, row in tqdm(enumerate(reader)):
            vec = ast.literal_eval(row['vec'])

            if input_dim !=None:
                vec=change_dim(vec,input_dim)

            nodes_msg_list.append(vec)

            nodes_count+=1
            if num_samples != None:
                if nodes_count==num_samples:
                    break

    return G,nodes_msg_list

def load_cfg(input_dim,folder, label,feature_name, num_samples=None):

    # graphs, features = read_cfg_from_csv(path=folder,representation_method=feature_name,input_dim=input_dim,num_samples=num_samples)
    graphs, features = read_cfg_from_csv_mutiple_thread(path=folder,representation_method=feature_name,input_dim=input_dim,num_samples=num_samples)

    if num_samples !=None:
        labels = [label] * num_samples
    else:
        labels = [label] * len(features)
    return graphs, features, labels


def load_datasets(input_dim,malware_folder, benign_folder,feature_name, num_malware_samples=None, num_benign_samples=None, test_rate=0.2):
    print("加载良性CFG中:")
    benign_graphs, benign_features, benign_labels  = load_cfg(input_dim,benign_folder, 0, feature_name,num_benign_samples)
    print("加载恶意CFG中:")
    malware_graphs, malware_features, malware_labels  = load_cfg(input_dim,malware_folder, 1,feature_name, num_malware_samples)



    # 合并数据
    all_graphs = malware_graphs + benign_graphs
    all_features = malware_features + benign_features
    all_labels = malware_labels + benign_labels



    # 划分训练集和测试集
    train_graphs, test_graphs, train_features, test_features, train_labels, test_labels, = train_test_split(
        all_graphs, all_features, all_labels,
        test_size=test_rate,
        random_state=42  # 设置随机种子以确保可重复性，如需每次结果不同，可以设置为None
    )

    return train_graphs, train_features, train_labels, test_graphs, test_features, test_labels


if __name__ == '__main__':

    # 设置文件夹路径
    malware_folder = r'\\ZJNU-NSR\Malware\Microsoft\CFG_malware'
    benign_folder = r'\\ZJNU-NSR\Malware\Microsoft\CFG_benign'

    # 设置样本数量
    num_malware_samples = 500
    num_benign_samples = 500
    # feature_name="asm_code"
    # feature_name="n_gram_1"
    # feature_name="n_gram_2"
    # feature_name="n_gram_3"
    # feature_name="asm2vec_s372_base_256"
    feature_name="Asm2VecPlus_8"
    # 加载数据集
    train_graphs, train_features, train_labels, test_graphs, test_features, test_labels = load_datasets(input_dim=None,malware_folder=malware_folder,
                                                                benign_folder=benign_folder,feature_name=feature_name, num_malware_samples=num_malware_samples, num_benign_samples=num_benign_samples, test_rate=0.2)

    print(f"Loaded {len(train_labels)} train graphs with labels.")
    print(f"Loaded {len(test_labels)} val graphs with labels.")