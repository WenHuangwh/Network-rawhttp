def compare_bytes(a, b):
    print(f"len MB: {len(a)}, len OK: {len(b)}")

    min_length = min(len(a), len(b))
    
    for i in range(min_length):
        if a[i] != b[i]:
            print(f"diff at index {i}, MB = {a[i]}, OK = {b[i]}")
        if i == min_length - 1:
            print("end")
    
    return 



def main():
    with open('10MB(1).log', 'rb') as f:
        file_1_contents = f.read()

    with open('10OK.log', 'rb') as f:
        file_2_contents = f.read()

    differences = compare_bytes(file_1_contents, file_2_contents)


main()