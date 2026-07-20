; benign lab asm listing (source only)
section .text
global _start
_start:
  nop
  ; marker: LAB_BENIGN_MARKER_v1
  mov eax, 1
  int3   ; inert trap
