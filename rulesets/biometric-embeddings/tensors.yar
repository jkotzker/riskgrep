// Binary tensor containers. YARA checks the container magic; the Rust
// post-processors parse the header and decide whether a float tensor is
// present. An embedding-shaped tensor (last dimension a common embedding
// width, at most two leading dimensions) scores high; any other float tensor
// with a large dimension (model weights, scientific data) scores low. Each
// format's pair shares a family, so an embedding-shaped tensor scores the
// higher weight.
//
// Parameter names never count: PyTorch (`weight`, `bias`, `running_mean`),
// JAX/Flax/TF (`kernel`, `scale`, `gamma`, `beta`, `moving_mean`), RWKV
// (`time_mix`, `time_decay`, `time_first`), Mamba (`mixer`, `A_log`,
// `dt_bias`, `conv1d`), ViT (`cls`), and model-embedding names. The unnamed
// and bank rules also ignore hierarchical names: a layer or block segment
// (`layers`, `blocks`, `h`, `encoder`, `encoderblock_0`, `transformer`,
// `backbone`, `model`) or an index segment between separators (`.0.`,
// `_1_`); identity keys are flat (`p225`, `person_000`, `spk_12`,
// `faces.0`, `speakers/p225`).

rule npy_embedding_tensor {
  meta:
    category = "biometric"
    weight = 70
    family = "npy"
    family_cap = 70
    post = "npy_header"
    min_dim = 64
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
  strings:
    $hdr = { 93 4E 55 4D 50 59 }
  condition:
    $hdr at 0
}

rule npy_float_tensor {
  meta:
    category = "biometric"
    weight = 30
    family = "npy"
    family_cap = 70
    post = "npy_header"
    min_dim = 64
  strings:
    $hdr = { 93 4E 55 4D 50 59 }
  condition:
    $hdr at 0
}

rule npz_embedding_tensor {
  meta:
    category = "biometric"
    weight = 70
    family = "npz"
    family_cap = 70
    post = "npz_members"
    min_dim = 64
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
    exclude_name_regex = "(?i)(weight|bias|running_(mean|var)|num_batches_tracked|in_proj|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe|(^|[._])proj(ection)?($|[._])|_proj$|text_projection|(^|[._/])(kernel|scale|gamma|beta|moving_(mean|variance)|time_(mix|decay|first)|mixer|a_log|dt_bias|conv1d|cls)($|[._/])|(^|[._/])(layers?|blocks?|h|encoder(block)?|decoder(block)?|transformer|backbone|model)($|[._/])|[._/][0-9]+[._/])"
  strings:
    $hdr = { 50 4B 03 04 }
  condition:
    $hdr at 0
}

// Several flat-named members of one identical embedding shape making up at
// least half of the archive's float members: one vector per person. Not in
// family `npz`, so it adds to the single-tensor rules.
rule npz_embedding_bank {
  meta:
    category = "biometric"
    weight = 80
    post = "npz_members"
    min_dim = 64
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
    exclude_name_regex = "(?i)(weight|bias|running_(mean|var)|num_batches_tracked|in_proj|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe|(^|[._])proj(ection)?($|[._])|_proj$|text_projection|(^|[._/])(kernel|scale|gamma|beta|moving_(mean|variance)|time_(mix|decay|first)|mixer|a_log|dt_bias|conv1d|cls)($|[._/])|(^|[._/])(layers?|blocks?|h|encoder(block)?|decoder(block)?|transformer|backbone|model)($|[._/])|[._/][0-9]+[._/])"
    min_bank = 3
    min_bank_share = 50
  strings:
    $hdr = { 50 4B 03 04 }
  condition:
    $hdr at 0
}

rule npz_float_tensor {
  meta:
    category = "biometric"
    weight = 30
    family = "npz"
    family_cap = 70
    post = "npz_members"
    min_dim = 64
  strings:
    $hdr = { 50 4B 03 04 }
  condition:
    $hdr at 0
}

// safetensors: u64 little-endian header length, then a JSON header ("{\"").
// Model checkpoints name parameters after embeddings (`word_embeddings`,
// `pos_embed`, `cls_token`, `time_embedding`, ...); those names do not count.
rule safetensors_named_embedding {
  meta:
    category = "biometric"
    weight = 85
    family = "safetensors"
    family_cap = 85
    post = "safetensors_header"
    min_dim = 1
    name_regex = "(?i)(^|[._/-])(embeddings?|speakers?|voices?|voiceprints?|faces?|xvectors?|dvectors?|ecapa|spk_emb)($|[._/-])"
    exclude_name_regex = "(?i)(weight|bias|running_(mean|var)|in_proj|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe|(^|[._/])(kernel|scale|gamma|beta|moving_(mean|variance)|time_(mix|decay|first)|mixer|a_log|dt_bias|conv1d|cls)($|[._/]))"
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}

// Embedding-shaped tensors without an embedding name. With
// `safetensors_float_tensor` one scores 70 (1 - 0.4 * 0.75), an ask rather
// than a deny. Model parameter, projection, and hierarchical names never
// count.
rule safetensors_embedding_tensor {
  meta:
    category = "biometric"
    weight = 60
    family = "safetensors"
    family_cap = 85
    post = "safetensors_header"
    min_dim = 64
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
    exclude_name_regex = "(?i)(weight|bias|running_(mean|var)|num_batches_tracked|in_proj|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe|(^|[._])proj(ection)?($|[._])|_proj$|text_projection|(^|[._/])(kernel|scale|gamma|beta|moving_(mean|variance)|time_(mix|decay|first)|mixer|a_log|dt_bias|conv1d|cls)($|[._/])|(^|[._/])(layers?|blocks?|h|encoder(block)?|decoder(block)?|transformer|backbone|model)($|[._/])|[._/][0-9]+[._/])"
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}

// An embedding bank: three or more such tensors of one identical shape,
// flat-named and at least half of the file's float tensors (a speaker or
// face store keyed by identity). Not in family `safetensors`, so it adds to
// the rules above.
rule safetensors_embedding_bank {
  meta:
    category = "biometric"
    weight = 80
    post = "safetensors_header"
    min_dim = 64
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
    exclude_name_regex = "(?i)(weight|bias|running_(mean|var)|num_batches_tracked|in_proj|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe|(^|[._])proj(ection)?($|[._])|_proj$|text_projection|(^|[._/])(kernel|scale|gamma|beta|moving_(mean|variance)|time_(mix|decay|first)|mixer|a_log|dt_bias|conv1d|cls)($|[._/])|(^|[._/])(layers?|blocks?|h|encoder(block)?|decoder(block)?|transformer|backbone|model)($|[._/])|[._/][0-9]+[._/])"
    min_bank = 3
    min_bank_share = 50
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}

rule safetensors_float_tensor {
  meta:
    category = "biometric"
    weight = 25
    family = "safetensors"
    family_cap = 85
    post = "safetensors_header"
    min_dim = 64
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}
