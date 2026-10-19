// Floats printed as text: a run of 64 or more decimal floats separated by
// commas, whitespace, or brackets (python lists, numpy repr, JSON arrays, CSV
// rows). The tail is greedy so one run yields one match.

rule printed_float_run {
  meta:
    category = "biometric"
    weight = 40
  strings:
    $re = /-?[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?([ \t\r\n,\[\]]+-?[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?){63}([ \t\r\n,\[\]]+-?[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?)*/
  condition:
    $re
}
