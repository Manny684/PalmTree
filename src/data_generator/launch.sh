rm ./debug.txt
ida64 -A -S"$PWD/control_flow_gen.py" /home/he1n/phd/BinHunter/binaries/CWE416_singles/good/CWE416_Use_After_Free__malloc_free_int_06-good -t
# -S"$PWD/control_flow_gen.py"
# /home/he1n/phd/BinHunter/binaries/CWE416_singles/good/CWE416_Use_After_Free__malloc_free_int_06-good
# /home/he1n/phd/BinHunter/binaries/CWE416_singles/good/CWE416_Use_After_Free__new_delete_array_struct_14-good
