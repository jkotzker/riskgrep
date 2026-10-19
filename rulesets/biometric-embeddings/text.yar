// Floats printed as text: a run of 64 or more decimal floats separated by
// commas, whitespace, or brackets (python lists, numpy repr, JSON arrays, CSV
// rows). The `float_run` post-processor finds the maximal runs and applies the
// count in one linear pass. No YARA pattern is used: any pattern that fires on
// every float costs more than the pass itself (measured: 354 ms vs a few ms
// for 8 MiB). The condition only skips files too small to hold 64 floats
// (each is at least 4 bytes: "0.1,").

rule printed_float_run {
  meta:
    category = "biometric"
    weight = 40
    post = "float_run"
    min_floats = 64
  condition:
    filesize >= 256
}
