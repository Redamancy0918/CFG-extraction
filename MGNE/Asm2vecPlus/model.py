from transformers import BertConfig, BertModel
import torch
import torch.nn as nn

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
class EmbeddingDecoder_old(torch.nn.Module):
    # 嵌入解码器类，包含嵌入层和预测层
    def __init__(self, input_size, embedding_size):
        super().__init__()
        self.embedding_layer = torch.nn.Linear(input_size, embedding_size)
        self.prediction_layer = torch.nn.Linear(embedding_size, input_size)

    def forward(self, x, masked_indices=None):
        embeddings = self.embedding_layer(x)
        predictions = self.prediction_layer(embeddings)
        if masked_indices is not None:
            masked_predictions = predictions[torch.arange(predictions.size(0)), masked_indices]
            return embeddings, masked_predictions
        return embeddings


class EmbeddingDecoder(nn.Module):
    def __init__(self, input_size, embedding_size, num_heads = 2 , dropout_rate=0.1):
        super().__init__()
        self.embedding_layer = nn.Linear(input_size, embedding_size)
        self.multihead_attention = nn.MultiheadAttention(embedding_size, num_heads)
        self.norm1 = nn.LayerNorm(embedding_size)
        self.dropout = nn.Dropout(dropout_rate)
        self.activation_fn = nn.ReLU()
        self.prediction_layer = nn.Linear(embedding_size, input_size)
        self.norm2 = nn.LayerNorm(embedding_size)

    def forward(self, x, masked_indices=None):
        # 嵌入层
        embeddings = self.embedding_layer(x)

        # 添加残差连接前的标准化
        embeddings = self.norm1(embeddings)

        # 多头注意力机制
        attn_output, _ = self.multihead_attention(embeddings, embeddings, embeddings)

        # 应用残差连接和Dropout
        embeddings = embeddings + self.dropout(attn_output)

        # 第二个残差连接前的标准化
        embeddings = self.norm2(embeddings)

        # 激活函数
        embeddings = self.activation_fn(embeddings)

        # 预测层
        predictions = self.prediction_layer(embeddings)

        # 如果提供了masked_indices，只返回被mask的预测
        if masked_indices is not None:
            masked_predictions = predictions[torch.arange(predictions.size(0)), masked_indices]
            return embeddings, masked_predictions

        return embeddings


class ImprovedEmbeddingDecoder(nn.Module):
    def __init__(self, input_size, embedding_size, dropout_rate=0.1):
        super(ImprovedEmbeddingDecoder, self).__init__()
        self.embedding_layer = nn.Linear(input_size, embedding_size)
        self.dropout = nn.Dropout(dropout_rate)
        self.activation_fn = nn.ReLU()
        self.prediction_layer = nn.Linear(embedding_size, input_size)

    def forward(self, x,masked_indices=None):
        # 嵌入层
        embeddings = self.embedding_layer(x)
        embeddings = self.activation_fn(embeddings)
        embeddings = self.dropout(embeddings)
        predictions = self.prediction_layer(embeddings)
        if masked_indices is not None:
            masked_predictions = predictions[torch.arange(predictions.size(0)), masked_indices]
            return embeddings, masked_predictions


        return embeddings


class EnhancedEmbeddingDecoder(nn.Module):
    def __init__(self, input_size, embedding_size, hidden_size):
        super().__init__()
        self.embedding_layer = nn.Linear(input_size, embedding_size)
        self.transform_layer_1 = nn.Linear(embedding_size, hidden_size)
        self.transform_layer_2 = nn.Linear(hidden_size, hidden_size)
        self.prediction_layer = nn.Linear(hidden_size, input_size)
        self.layer_norm1 = nn.LayerNorm(embedding_size)
        self.layer_norm2 = nn.LayerNorm(hidden_size)
        self.dropout = nn.Dropout(0.1)

    def forward(self, x, masked_indices=None):
        # 嵌入层
        embeddings = self.embedding_layer(x)
        embeddings = F.relu(embeddings)
        embeddings = self.layer_norm1(embeddings)

        # 隐藏层
        hidden = self.transform_layer_1(embeddings)
        hidden = F.relu(hidden)
        hidden = self.dropout(hidden)

        # 第二隐藏层
        hidden = self.transform_layer_2(hidden)
        hidden = F.relu(hidden)
        hidden = self.layer_norm2(hidden)

        # 预测层
        predictions = self.prediction_layer(hidden)

        # 如果提供了masked_indices，则只返回被掩码位置的预测
        if masked_indices is not None:
            masked_predictions = predictions[torch.arange(predictions.size(0)), masked_indices]
            return embeddings, masked_predictions

        return embeddings


class SimplifiedTransformerDecoder(nn.Module):
    def __init__(self, input_size, embedding_size, nhead, num_decoder_layers, dim_feedforward, dropout=0.1):
        super().__init__()
        self.input_projection = nn.Linear(input_size, embedding_size)  # 将输入向量映射到嵌入空间
        self.transformer_decoder_layer = nn.TransformerDecoderLayer(
            d_model=embedding_size,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout
        )
        self.transformer_decoder = nn.TransformerDecoder(
            self.transformer_decoder_layer,
            num_layers=num_decoder_layers
        )
        self.output_projection = nn.Linear(embedding_size, input_size)  # 将嵌入向量映射回原始维度
        self.embedding_size = embedding_size

    def forward(self, src, masked_indices=None):
        src = self.input_projection(src)  # 将输入映射到嵌入维度
        batch_size, seq_len, _ = src.size()
        # 初始化一个向下三角的掩码，用于防止位置注意未来的位置信息
        tgt_mask = torch.triu(torch.ones(seq_len, seq_len) * float('-inf'), diagonal=1).to(src.device)
        # 通过Transformer解码器层
        memory = src.permute(1, 0, 2)  # 调整为(seq_len, batch_size, embedding_size)
        output = self.transformer_decoder(tgt=memory, memory=memory, tgt_mask=tgt_mask)
        output = output.permute(1, 0, 2)  # 调整回(batch_size, seq_len, embedding_size)
        # 映射回原始维度
        predictions = self.output_projection(output)
        # 如果提供了masked_indices，则只选择这些索引的预测
        if masked_indices is not None:
            masked_predictions = predictions[torch.arange(batch_size), masked_indices]
            return output, masked_predictions  # 返回嵌入和掩码索引处的预测
        return output  # 否则返回整个序列的嵌入
def load_model(encoder_path="", decoder_path="", vector_size=4, embedding_size=4):
    # 加载编码器和解码器模型
    config = BertConfig(
        hidden_size=vector_size,
        num_hidden_layers=4,
        num_attention_heads=2,
        intermediate_size=4 * vector_size,
        hidden_dropout_prob=0.1,
        attention_probs_dropout_prob=0.1,
        max_position_embeddings=512
    )
    bert_encoder = BertModel(config)
    if encoder_path!="":
        bert_encoder.load_state_dict(torch.load(encoder_path))
    # 模型超参数
    input_size = vector_size  # 输入向量的大小
    nhead = 2  # 注意力头数
    num_decoder_layers = 1  # 解码器层数
    dim_feedforward = 64  # 前馈网络的维度
    dropout = 0.1  # Dropout率
    # decoder = SimplifiedTransformerDecoder(input_size, embedding_size, nhead, num_decoder_layers, dim_feedforward,dropout)
    decoder = EmbeddingDecoder_old(input_size, embedding_size)
    # decoder = SimplifiedTransformerDecoder(vector_size, embedding_size)
    if decoder_path != "":
        decoder.load_state_dict(torch.load(decoder_path))

    return bert_encoder.to(device), decoder.to(device)

