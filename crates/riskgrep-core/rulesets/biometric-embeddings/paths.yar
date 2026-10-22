// Path heuristics use the engine's `path` external. No anchors: counts once.

rule path_biometric_name {
  meta:
    category = "biometric"
    weight = 30
  condition:
    path matches /(voiceprint|embedding|speaker|enroll|faceprint)/i
}
