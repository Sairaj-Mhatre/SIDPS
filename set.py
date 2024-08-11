with open('words.txt', 'r') as file:
    words = file.read().splitlines()

# Remove duplicates while preserving order
unique_words = list(dict.fromkeys(words))

print(unique_words)