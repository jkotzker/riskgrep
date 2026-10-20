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
rule safetensors_named_embedding {
  meta:
    category = "biometric"
    weight = 85
    family = "safetensors"
    family_cap = 85
    post = "safetensors_header"
    min_dim = 1
    name_regex = "(?i)(embedding|speaker|voice|face|xvector|ecapa)"
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}

// Layer parameters (`*.weight`, `*.bias`, batch-norm statistics) are model
// weights, not embeddings, whatever their shape.
rule safetensors_embedding_tensor {
  meta:
    category = "biometric"
    weight = 70
    family = "safetensors"
    family_cap = 85
    post = "safetensors_header"
    min_dim = 64
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
    exclude_name_regex = "(?i)(weight|bias|running_(mean|var)|num_batches_tracked)"
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}

rule safetensors_float_tensor {
  meta:
    category = "biometric"
    weight = 30
    family = "safetensors"
    family_cap = 85
    post = "safetensors_header"
    min_dim = 64
  strings:
    $hdr = { 7B 22 }
  condition:
    $hdr at 8 and uint32(4) == 0 and uint32(0) > 1 and uint32(0) + 8 <= filesize
}
