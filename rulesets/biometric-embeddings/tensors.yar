// Binary tensor containers. YARA checks the container magic; the Rust
// post-processors parse the header and decide whether a float tensor is
// present. An embedding-shaped tensor (last dimension a common embedding
// width, at most two leading dimensions) scores high; any other float tensor
// with a large dimension (model weights, scientific data) scores low. Each
// format's pair shares a family, so an embedding-shaped tensor scores the
// higher weight.

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
    name_regex = "(?i)(embedding|speaker|voice|face|xvector|dvector|ecapa|spk_emb)"
    exclude_name_regex = "(?i)((\\.weight|\\.bias)$|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe)"
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}

// Embedding-shaped tensors without an embedding name, in files with at most
// a few tensors: a model layout has many. With `safetensors_float_tensor` it
// scores 70 (1 - 0.4 * 0.75), an ask rather than a deny. Model parameter
// names never count.
rule safetensors_embedding_tensor {
  meta:
    category = "biometric"
    weight = 60
    family = "safetensors"
    family_cap = 85
    post = "safetensors_header"
    min_dim = 64
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
    max_tensors = 4
    exclude_name_regex = "(?i)(weight|bias|running_(mean|var)|num_batches_tracked|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe)"
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
