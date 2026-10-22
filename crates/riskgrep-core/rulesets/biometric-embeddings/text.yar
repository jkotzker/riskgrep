// Floats printed as text. Any run of 64 or more decimal floats separated by
// commas, whitespace, or brackets (python lists, numpy repr, JSON arrays, CSV
// rows) scores low: the `float_run` post-processor finds the maximal runs in
// one linear pass. A single bracketed array whose length is a common
// embedding width scores high (`float_array`). No YARA pattern is used: any
// pattern that fires on every float costs more than the pass itself
// (measured: 354 ms vs a few ms for 8 MiB). The condition only skips files
// too small to hold 64 floats (each is at least 4 bytes: "0.1,").

rule printed_float_run {
  meta:
    category = "biometric"
    weight = 40
    family = "printed_floats"
    family_cap = 60
    post = "float_run"
    min_floats = 64
  condition:
    filesize >= 256
}

rule printed_embedding_array {
  meta:
    category = "biometric"
    weight = 60
    family = "printed_floats"
    family_cap = 60
    post = "float_array"
    embedding_dims = "128,192,256,384,512,640,768,1024,1536,2048,3072,4096"
  condition:
    filesize >= 256
}
