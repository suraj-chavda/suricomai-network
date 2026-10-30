# Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
"""Trains suricomai-mini-chat from scratch and writes its GGUF weights and tokenizer.

usage: build.py <output-directory> [steps]

The network is a standard llama layout (RMSNorm, interleaved rotary positions, SwiGLU), small
enough to run on any processor. The prompt layout is the runtime's own ChatML layout with its
fixed system line, so what is trained is exactly what the runtime sends.
"""
import math
import random
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from tokenizers import Tokenizer, decoders, models, pre_tokenizers, trainers

from corpus import conversations

SYSTEM = "<|im_start|>system\nYou answer in plain sentences. You do not call tools.<|im_end|>\n"
SPECIAL = ["<|endoftext|>", "<|im_start|>", "<|im_end|>"]
VOCAB, DIM, LAYERS, HEADS, FFN, CTX = 1024, 192, 4, 6, 512, 512
EPS, BASE, SEQ = 1e-5, 10000.0, 256
DROPOUT = 0.1
PREFIXES = ["please ", "can you tell me ", "quick question, ", "i want to know ", "tell me, ", "hey, ", "just wondering, ", "so, "]


def render(turns, rng=None):
    """Return (text, spans) where spans mark the assistant text the model must learn."""
    text, spans = SYSTEM, []
    for user, assistant in turns:
        if rng is not None:
            user = decorate(user, rng)
        text += f"<|im_start|>user\n{user}<|im_end|>\n<|im_start|>assistant\n"
        start = len(text)
        text += assistant + "<|im_end|>"
        spans.append((start, len(text)))
        text += "\n"
    return text, spans


def decorate(q, rng):
    """People type capitals and punctuation. The model should not care."""
    if rng.random() < 0.25 and q.split()[0] in {"what", "who", "how", "which", "is", "are", "can", "do", "does", "where", "when", "why"}:
        q = rng.choice(PREFIXES) + q
    if rng.random() < 0.6:
        q = q[:1].upper() + q[1:]
    r = rng.random()
    if r < 0.45:
        q += "?" if q.split()[0].lower() in {"what", "who", "how", "why", "which", "is", "are", "can", "do", "does", "where", "when"} else "."
    elif r < 0.55:
        q += "!"
    return q


def make_tokenizer(convs):
    tok = Tokenizer(models.BPE())
    tok.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
    tok.decoder = decoders.ByteLevel()
    trainer = trainers.BpeTrainer(vocab_size=VOCAB, special_tokens=SPECIAL, initial_alphabet=pre_tokenizers.ByteLevel.alphabet(), show_progress=False)
    rng = random.Random(1)
    corpus = []
    for c in convs:
        for _ in range(3):
            corpus.append(render(c, rng)[0])
    tok.train_from_iterator(corpus, trainer)
    assert tok.get_vocab_size() == VOCAB, tok.get_vocab_size()
    return tok


def encode(tok, text, spans):
    enc = tok.encode(text, add_special_tokens=False)
    ids, offs = enc.ids, enc.offsets
    mask = [0] * len(ids)
    for i, (a, b) in enumerate(offs):
        for s, e in spans:
            if a >= s and b <= e and b > a:
                mask[i] = 1
    return ids, mask


class RMSNorm(nn.Module):
    def __init__(self):
        super().__init__()
        self.weight = nn.Parameter(torch.ones(DIM))

    def forward(self, x):
        return x * torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + EPS) * self.weight


def rope_tables(n, hd):
    inv = BASE ** (-torch.arange(0, hd, 2).float() / hd)
    ang = torch.arange(n).float()[:, None] * inv[None, :]
    return torch.cos(ang), torch.sin(ang)


def rope_interleaved(x, cos, sin):
    # x: (b, heads, t, hd). Rotate adjacent pairs, the layout the runtime's loader expects.
    x1, x2 = x[..., 0::2], x[..., 1::2]
    c, s = cos[: x.shape[2]], sin[: x.shape[2]]
    r1, r2 = x1 * c - x2 * s, x1 * s + x2 * c
    return torch.stack((r1, r2), dim=-1).flatten(-2)


class Block(nn.Module):
    def __init__(self):
        super().__init__()
        self.attn_norm, self.ffn_norm = RMSNorm(), RMSNorm()
        self.wq, self.wk, self.wv, self.wo = (nn.Linear(DIM, DIM, bias=False) for _ in range(4))
        self.gate, self.up = nn.Linear(DIM, FFN, bias=False), nn.Linear(DIM, FFN, bias=False)
        self.down = nn.Linear(FFN, DIM, bias=False)

    def forward(self, x, cos, sin):
        b, t, _ = x.shape
        hd = DIM // HEADS
        h = self.attn_norm(x)
        q, k, v = (w(h).view(b, t, HEADS, hd).transpose(1, 2) for w in (self.wq, self.wk, self.wv))
        q, k = rope_interleaved(q, cos, sin), rope_interleaved(k, cos, sin)
        a = F.scaled_dot_product_attention(q, k, v, is_causal=True, dropout_p=DROPOUT if self.training else 0.0)
        x = x + F.dropout(self.wo(a.transpose(1, 2).reshape(b, t, DIM)), DROPOUT, self.training)
        h = self.ffn_norm(x)
        return x + F.dropout(self.down(F.silu(self.gate(h)) * self.up(h)), DROPOUT, self.training)


class Mini(nn.Module):
    def __init__(self):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, DIM)
        self.blocks = nn.ModuleList(Block() for _ in range(LAYERS))
        self.norm = RMSNorm()
        self.out = nn.Linear(DIM, VOCAB, bias=False)
        cos, sin = rope_tables(CTX, DIM // HEADS)
        self.register_buffer("cos", cos, persistent=False)
        self.register_buffer("sin", sin, persistent=False)
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.normal_(p, std=0.02)

    def forward(self, ids):
        x = self.emb(ids)
        for blk in self.blocks:
            x = blk(x, self.cos, self.sin)
        return self.out(self.norm(x))


def batch(tok, convs, rng, size):
    rows = []
    for c in rng.sample(convs, size):
        ids, mask = encode(tok, *render(c, rng))
        rows.append((ids[:SEQ], mask[:SEQ]))
    n = max(len(r[0]) for r in rows)
    x = torch.zeros(len(rows), n, dtype=torch.long)
    m = torch.zeros(len(rows), n)
    for i, (ids, mask) in enumerate(rows):
        x[i, : len(ids)] = torch.tensor(ids)
        m[i, : len(mask)] = torch.tensor(mask, dtype=torch.float)
    return x, m


def loss_of(model, x, m):
    logits = model(x[:, :-1])
    nll = F.cross_entropy(logits.reshape(-1, VOCAB), x[:, 1:].reshape(-1), reduction="none").view(x.shape[0], -1)
    w = m[:, 1:]
    return (nll * w).sum() / w.sum().clamp(min=1)


@torch.no_grad()
def generate(model, tok, question, limit=80):
    ids = tok.encode(render([], None)[0] + f"<|im_start|>user\n{question}<|im_end|>\n<|im_start|>assistant\n", add_special_tokens=False).ids
    end = tok.token_to_id("<|im_end|>")
    out = []
    for _ in range(limit):
        logits = model(torch.tensor([ids + out]))[0, -1]
        nxt = int(logits.argmax())
        if nxt == end:
            break
        out.append(nxt)
    return tok.decode(out)


def export(model, tok, out_dir):
    import gguf

    sd = {k: v.detach().cpu().numpy() for k, v in model.state_dict().items()}
    path = out_dir / "suricomai-mini-chat.gguf"
    w = gguf.GGUFWriter(str(path), "llama")
    w.add_name("suricomai-mini-chat")
    w.add_context_length(CTX)
    w.add_embedding_length(DIM)
    w.add_block_count(LAYERS)
    w.add_feed_forward_length(FFN)
    w.add_head_count(HEADS)
    w.add_head_count_kv(HEADS)
    w.add_layer_norm_rms_eps(EPS)
    w.add_rope_dimension_count(DIM // HEADS)
    w.add_rope_freq_base(BASE)
    w.add_file_type(gguf.LlamaFileType.MOSTLY_F16)
    mats = lambda a: a.astype(np.float16)
    vec = lambda a: a.astype(np.float32)
    w.add_tensor("token_embd.weight", mats(sd["emb.weight"]))
    w.add_tensor("output_norm.weight", vec(sd["norm.weight"]))
    w.add_tensor("output.weight", mats(sd["out.weight"]))
    for i in range(LAYERS):
        p = f"blocks.{i}."
        for name, key, conv in [
            ("attn_norm", "attn_norm.weight", vec), ("ffn_norm", "ffn_norm.weight", vec),
            ("attn_q", "wq.weight", mats), ("attn_k", "wk.weight", mats), ("attn_v", "wv.weight", mats), ("attn_output", "wo.weight", mats),
            ("ffn_gate", "gate.weight", mats), ("ffn_up", "up.weight", mats), ("ffn_down", "down.weight", mats),
        ]:
            w.add_tensor(f"blk.{i}.{name}.weight", conv(sd[p + key]))
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file()
    w.close()
    tok.save(str(out_dir / "suricomai-mini-chat.tokenizer.json"))
    return path


def main():
    out_dir = Path(sys.argv[1])
    steps = int(sys.argv[2]) if len(sys.argv) > 2 else 2500
    out_dir.mkdir(parents=True, exist_ok=True)
    torch.manual_seed(0)
    rng = random.Random(0)
    train, valid = conversations()
    # The model is meant to know every listed fact in any spelling or punctuation, so it is
    # judged on seen facts in fresh wording, not on facts it was never given.
    train = train + valid
    valid = random.Random(3).sample(train, 120)
    tok = make_tokenizer(train)
    model = Mini()
    print("parameters:", sum(p.numel() for p in model.parameters()))
    opt = torch.optim.AdamW(model.parameters(), lr=3e-3, betas=(0.9, 0.95), weight_decay=0.05)
    best, best_state = 9.0, None
    for step in range(steps):
        lr = 3e-3 * min(1, (step + 1) / 100) * (0.1 + 0.9 * 0.5 * (1 + math.cos(math.pi * step / steps)))
        for g in opt.param_groups:
            g["lr"] = lr
        x, m = batch(tok, train, rng, 32)
        loss = loss_of(model, x, m)
        opt.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
        if step % 200 == 0 or step == steps - 1:
            model.eval()
            with torch.no_grad():
                vx, vm = batch(tok, valid, random.Random(5), len(valid))
                v = loss_of(model, vx, vm).item()
            model.train()
            print(f"step {step} train {loss.item():.3f} valid {v:.3f}", flush=True)
            if v < best:
                best, best_state = v, {k: t.clone() for k, t in model.state_dict().items()}
    model.load_state_dict(best_state)
    print(f"kept the checkpoint with validation loss {best:.3f}")
    model.eval()
    for q in ["What colour is a banana?", "What is the capital of Italy?", "Hello!", "What is the sun?", "What is 3 plus 4?", "Is SuriComAI private?", "What sound does a cow make?", "Tell me a joke", "What is the capital of Japan?", "who wins the world cup", "What is the price of silver?", "Write me a poem", "How tall is Mount Fuji?", "How fast are you?", "what colour is snow", "Who made suricomai?"]:
        print(">", q, "\n ", generate(model, tok, q))
    print("wrote", export(model, tok, out_dir))
    torch.save(model.state_dict(), out_dir / "mini.pt")


if __name__ == "__main__":
    main()
