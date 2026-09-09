"""
PyTorch Neural Network Classifier for TSPU DPI Flow Classification.
Dual-branch architecture:
1. 1D-CNN branch for directional packet length sequence analysis.
2. MLP branch for statistical flow metrics (entropy, IAT jitter, byte asymmetry, etc.).
"""

import os
from typing import Tuple, Dict, Any, List
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

NUM_CLASSES = 4


class TSPUFlowClassifier(nn.Module):
    def __init__(self, seq_len: int = 30, num_stats: int = 16, num_classes: int = NUM_CLASSES):
        super().__init__()

        # 1. 1D-CNN Branch for Packet Length Sequence
        self.cnn_branch = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=3, padding=1),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Conv1d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(4),
            nn.Flatten()  # 64 * 4 = 256
        )

        # 2. MLP Branch for Statistical Features
        self.mlp_branch = nn.Sequential(
            nn.Linear(num_stats, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU()
        )

        # 3. Fusion & Classification Head
        self.classifier = nn.Sequential(
            nn.Linear(256 + 32, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )

    def forward(self, seq: torch.Tensor, stats: torch.Tensor) -> torch.Tensor:
        # seq shape: (batch, 1, seq_len)
        # stats shape: (batch, num_stats)
        feat_seq = self.cnn_branch(seq)
        feat_stats = self.mlp_branch(stats)
        combined = torch.cat([feat_seq, feat_stats], dim=1)
        return self.classifier(combined)


def train_classifier(
    model: TSPUFlowClassifier,
    X_seq: np.ndarray,
    X_stat: np.ndarray,
    y: np.ndarray,
    epochs: int = 15,
    batch_size: int = 32,
    lr: float = 0.002,
    device: str = "cpu"
) -> Dict[str, Any]:
    model.to(device)
    model.train()

    t_seq = torch.tensor(X_seq, dtype=torch.float32).unsqueeze(1)
    t_stat = torch.tensor(X_stat, dtype=torch.float32)
    t_y = torch.tensor(y, dtype=torch.long)

    dataset = TensorDataset(t_seq, t_stat, t_y)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    history = []
    for epoch in range(epochs):
        total_loss = 0.0
        correct = 0
        total = 0

        for batch_seq, batch_stat, batch_y in loader:
            batch_seq = batch_seq.to(device)
            batch_stat = batch_stat.to(device)
            batch_y = batch_y.to(device)

            optimizer.zero_grad()
            logits = model(batch_seq, batch_stat)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(batch_y)
            preds = torch.argmax(logits, dim=1)
            correct += (preds == batch_y).sum().item()
            total += len(batch_y)

        epoch_loss = total_loss / total
        epoch_acc = correct / total
        history.append({"epoch": epoch + 1, "loss": epoch_loss, "acc": epoch_acc})

    return {"history": history, "final_loss": epoch_loss, "final_acc": epoch_acc}


def evaluate_classifier(
    model: TSPUFlowClassifier,
    X_seq: np.ndarray,
    X_stat: np.ndarray,
    y: np.ndarray,
    device: str = "cpu"
) -> Dict[str, Any]:
    model.to(device)
    model.eval()

    t_seq = torch.tensor(X_seq, dtype=torch.float32).unsqueeze(1).to(device)
    t_stat = torch.tensor(X_stat, dtype=torch.float32).to(device)

    with torch.no_grad():
        logits = model(t_seq, t_stat)
        probs = torch.softmax(logits, dim=1).cpu().numpy()
        preds = np.argmax(probs, axis=1)

    correct = int(np.sum(preds == y))
    total = len(y)
    accuracy = correct / total if total > 0 else 0.0

    # Confusion matrix
    conf_matrix = np.zeros((NUM_CLASSES, NUM_CLASSES), dtype=int)
    for true_lbl, pred_lbl in zip(y, preds):
        conf_matrix[true_lbl, pred_lbl] += 1

    return {
        "accuracy": accuracy,
        "confusion_matrix": conf_matrix,
        "probs": probs,
        "preds": preds
    }


def save_model(model: TSPUFlowClassifier, path: str):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    torch.save(model.state_dict(), path)


def load_model(path: str, device: str = "cpu") -> TSPUFlowClassifier:
    model = TSPUFlowClassifier()
    if os.path.exists(path):
        model.load_state_dict(torch.load(path, map_location=device, weights_only=True))
    model.to(device)
    model.eval()
    return model
