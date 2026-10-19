// Binary tensor containers. YARA checks the container magic; the Rust
// post-processors parse the header and decide whether a float tensor with a
// large dimension is present.

rule npy_float_tensor {
  meta:
    category = "biometric"
    weight = 70
    post = "npy_header"
    min_dim = 64
  strings:
    $hdr = { 93 4E 55 4D 50 59 }
  condition:
    $hdr at 0
}

rule npz_float_tensor {
  meta:
    category = "biometric"
    weight = 70
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
