rule ransom
{
  meta:
    author = "cyberlab"
    description = "Benign marker rule for lab samples (no live malware)"
    reference = "cyberlab-training-lab"
  strings:
    $marker = "LAB_BENIGN_MARKER_v1" ascii
    $url = "http://benign.lab.local/beacon" ascii
    $email = "analyst@lab.local" ascii
  condition:
    any of them
}
