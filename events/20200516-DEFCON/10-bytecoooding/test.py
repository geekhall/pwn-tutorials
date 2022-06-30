
THRESHOLD = int(os.environ.get('THRESHOLD', 1000))
PLATFORMS = ["jvm", "python3", "python2", "ruby", "lua", "nodejs", "ocaml", "elisp"]

print(f"Choose the platforms ({' '.join(PLATFORMS)}) you want to run your bytecode against")
print(THRESHOLD)

