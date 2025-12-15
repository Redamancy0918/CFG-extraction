import torch.nn as nn
from dgl.nn.pytorch import GraphConv
import torch.nn.functional as F
import dgl.nn as dglnn
from torch.nn.utils.rnn import pad_sequence, pack_padded_sequence
import torch
import dgl
import numpy as np
from transformers import BertConfig, BertModel


device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
def jiangwei(list):
    res=[]
    for each in list:
        mean_vector = torch.mean(each, dim=0)
        res.append(mean_vector.tolist())
    return  torch.tensor(res).to(device)



class MalwareDetectionModel_Node(nn.Module):
    def __init__(self, gnn_name, input_dim, gnn_out_feats, num_layers):
        super(MalwareDetectionModel_Node, self).__init__()
        if gnn_name=="GCN":
            self.gnn_model = GNNModel(input_dim, gnn_out_feats, num_layers)
        elif gnn_name=="GAT":
            self.gnn_model = GATModel(input_dim, gnn_out_feats, num_layers)
        elif gnn_name == "DGCNN":
            self.gnn_model = DGCNNModel(input_dim, gnn_out_feats, num_layers)
        self.classifier = nn.Linear(gnn_out_feats, 2)

    def forward(self, g, x):

        h = self.gnn_model(g, x)
        g.ndata['h'] = h
        hg = dgl.mean_nodes(g, 'h')
        return self.classifier(hg)




class MalwareDetectionModel_NodeSequence(nn.Module):
    def __init__(self, gnn_name,input_dim, hidden_dim, gnn_out_feats, num_layers):
        super(MalwareDetectionModel_NodeSequence, self).__init__()
        self.node_feature_model = NodeFeatureModel(input_dim, hidden_dim)
        if gnn_name=="GCN":
            self.gnn_model = GNNModel(hidden_dim, gnn_out_feats, num_layers)
        elif gnn_name=="GAT":
            self.gnn_model = GATModel(hidden_dim, gnn_out_feats, num_layers)
        elif gnn_name == "DGCNN":
            self.gnn_model = DGCNNModel(hidden_dim, gnn_out_feats, num_layers)
        self.classifier = nn.Linear(gnn_out_feats, 2)
    def forward(self, g, x,batch_lengths,seq_model):
        h = self.node_feature_model(x,batch_lengths,seq_model)
        h = self.gnn_model(g, h)
        g.ndata['h'] = h
        hg = dgl.mean_nodes(g, 'h')
        return self.classifier(hg)






# 您创建的自定义 Transformer 模型与 BERT 有几个主要区别：
#
# 输入处理：
#
# BERT：原始的 BERT 模型是为了处理基于词汇表索引的文本数据设计的。它使用一个嵌入层来将词汇索引转换为固定维度的向量，然后这些向量被用作模型的输入。
# 自定义 Transformer：您的模型直接处理浮点型数据。您使用了一个线性层（self.embedding）来将输入数据映射到一个新的空间，然后这些数据被用作自定义 Transformer 的输入。
# 预训练和词汇表：
#
# BERT：BERT 模型通常是预训练的，这意味着它已经在大规模文本数据上训练过，学习了词汇表中的每个词的丰富表示。这使得它非常适合于处理自然语言。
# 自定义 Transformer：在您的模型中，没有预训练的过程或词汇表的概念。您的模型是从头开始训练的，这意味着它需要在特定任务上进行训练以学习有效的特征表示。
# 模型架构：
#
# BERT：BERT 模型有一个特定的架构，包括多层 Transformer 编码器，每层包含自注意力和前馈网络。BERT 还包括了特殊的令牌（如 [CLS] 和 [SEP]），它们在处理文本时起着重要作用。
# 自定义 Transformer：虽然您的模型使用了标准的 Transformer 编码器层，但它没有 BERT 的一些特定结构和预训练机制。这使得它更为通用，但也可能缺乏处理特定文本任务时 BERT 的某些优势。
# 适用性：
#
# BERT：由于其预训练的特性和专门的文本处理能力，BERT 非常适合于各种自然语言处理任务。
# 自定义 Transformer：您的模型由于其通用性，更适合于处理非文本数据或者您自己的特定数据集，特别是当这些数据不是基于词汇表索引的时候。
# 总结来说，BERT 是针对自然语言处理优化和预训练的，而您的自定义 Transformer 模型是更为通用的，可以处理各种不同类型的数据，但它不包括 BERT 的预训练优势和某些针对文本处理的特定结构。
from torch.nn import TransformerEncoder, TransformerEncoderLayer



class NodeFeatureModel(nn.Module):
    def __init__(self, input_dim, embedding_dim):
        super(NodeFeatureModel, self).__init__()
        self.embedding = nn.Linear(input_dim, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, embedding_dim, batch_first=True)

        # 自定义的 Transformer 编码器层
        self.encoder_layer = TransformerEncoderLayer(
            d_model=embedding_dim,
            nhead=2,
            dim_feedforward=2 * embedding_dim,
            dropout=0.1
        )
        self.transformer_encoder = TransformerEncoder(self.encoder_layer, num_layers=2)

    def create_attention_mask(self, x, batch_lengths):
        mask = torch.zeros(x.size(0), x.size(1), dtype=torch.long)
        for i, length in enumerate(batch_lengths):
            mask[i, :length] = 1
        return mask
    def forward(self, x,batch_lengths,seq_model):
        # x is already a tensor with padded sequences

        x = self.embedding(x)
        if seq_model=="LSTM":
            # x = self.embedding(x)
            x_packed = pack_padded_sequence(x, batch_lengths, batch_first=True, enforce_sorted=False)

            _, (hn, _) = self.lstm(x_packed)
            return hn.squeeze(0)
        elif seq_model == "BERT":
            # 创建 attention_mask
            attention_mask = self.create_attention_mask(x, batch_lengths).to(device)

            # 调整 x 的形状以适应 Transformer 编码器
            x = x.permute(1, 0, 2)  # [seq_length, batch_size, embedding_dim]

            # 通过自定义的 Transformer 获取隐藏层状态
            transformer_output = self.transformer_encoder(x, src_key_padding_mask=attention_mask)

            # 取最后一个时间步的输出
            last_hidden_states = transformer_output[-1]
            return last_hidden_states


class NodeFeatureModel1(nn.Module):
    def __init__(self, input_dim, hidden_dim):
        super(NodeFeatureModel, self).__init__()
        self.embedding = nn.Linear(input_dim, hidden_dim)
        self.lstm = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)
        # self.lstm = nn.RNN(input_dim, hidden_dim, batch_first=True)
    def forward(self, x):
        # x is already a tensor with padded sequences
        x = self.embedding(x)
        _, (hn, _) = self.lstm(x )
        return hn.squeeze(0)

class GNNModel(nn.Module):
    def __init__(self, in_feats, out_feats, num_layers):
        super(GNNModel, self).__init__()
        self.layers = nn.ModuleList()
        # 设置allow_zero_in_degree为True
        self.layers.append(GraphConv(in_feats, out_feats, activation=nn.ReLU(), allow_zero_in_degree=True))
        for _ in range(num_layers - 1):
            # 设置allow_zero_in_degree为True
            self.layers.append(GraphConv(out_feats, out_feats, activation=nn.ReLU(), allow_zero_in_degree=True))

    def forward(self, g, h):
        for layer in self.layers:

            h = layer(g, h)
        return h

class GCNModel(nn.Module):
    def __init__(self, in_feats, out_feats, num_layers):
        super(GCNModel, self).__init__()
        self.layers = nn.ModuleList()
        self.layers.append(dglnn.GraphConv(in_feats, out_feats, activation=nn.ReLU(), allow_zero_in_degree=True))
        for _ in range(num_layers - 1):
            self.layers.append(dglnn.GraphConv(out_feats, out_feats, activation=nn.ReLU(), allow_zero_in_degree=True))

    def forward(self, g, h):
        for layer in self.layers:
            h = layer(g, h)
        return h


class GATModel(nn.Module):
    def __init__(self, in_feats, out_feats, num_layers, heads=4):
        super(GATModel, self).__init__()

        self.layers = nn.ModuleList()
        # Input layer
        self.layers.append(dglnn.GATConv(in_feats, out_feats // heads, num_heads=heads, allow_zero_in_degree=True))

        for _ in range(1, num_layers - 1):
            # Hidden layers with multi-heads
            self.layers.append(dglnn.GATConv(out_feats // heads * heads, out_feats // heads, num_heads=heads, allow_zero_in_degree=True))

        # Output layer
        self.layers.append(dglnn.GATConv(out_feats // heads * heads, out_feats, num_heads=1, allow_zero_in_degree=True))

    def forward(self, g, h):
        for layer in self.layers[:-1]:
            h = layer(g, h).flatten(1)
            h = F.elu(h)
        # Output layer without multi-head
        h = self.layers[-1](g, h).squeeze()
        return h


class SortPooling(nn.Module):
    def __init__(self, k):
        super(SortPooling, self).__init__()
        self.k = k

    def forward(self, h):
        # h: [num_nodes, num_features]
        # 排序池化，我们按照最后一个维度的特征值对节点进行排序
        _, idx = torch.sort(h, dim=0, descending=True)
        # 取前k个节点的特征
        k = min(self.k, h.size(0))
        h = h[idx[:k]]
        # 如果节点不足k个，用0填充
        if h.size(0) < self.k:
            h_padded = torch.zeros(self.k, h.size(1), device=h.device)
            h_padded[:h.size(0)] = h
            h = h_padded
        return h
from dgl.nn import  EdgeConv
from dgl import DGLGraph
class DGCNNModel(nn.Module):
    def __init__(self, in_feats, out_feats, num_layers, k=20):
        super(DGCNNModel, self).__init__()
        self.k = k  # k-NN图的k值
        # 第一个图卷积层
        self.graph_conv = GraphConv(in_feats, out_feats, activation=F.relu, allow_zero_in_degree=True)
        # 定义EdgeConv层的列表
        self.edge_convs = nn.ModuleList()
        # 增加边卷积层
        for _ in range(num_layers):
            self.edge_convs.append(EdgeConv(out_feats, out_feats, allow_zero_in_degree=True))
        # 接一个分类或者回归等全连接层，这里以分类为例
        self.fc = nn.Linear(out_feats, 2)  # 假设num_classes是你的类别数

    def forward(self, g, h):
        # k-NN图构造在此应该被实施，更新图g的边
        # 这里省略了k-NN图的构造代码，需要根据你的应用来具体实现
        # ...

        # 应用第一个图卷积
        h = self.graph_conv(g, h)

        # 对每个EdgeConv层应用边卷积操作
        for conv in self.edge_convs:
            # EdgeConv预期得到的是一批边的特征，所以这里需要根据更新后的图来获取边的特征
            # g = DGLGraph(g)
            h = conv(g, h)

        # 全局平均池化
        # hg = dgl.mean_nodes(g, h)

        # 应用分类层
        # out = self.fc(hg)
        return h
