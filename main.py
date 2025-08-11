import sys
from container import PartialReadVault


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python main.py create <vault_path> <password>")
        print("  python main.py open <vault_path> <password>")
        print("  python main.py add <vault_path> <password> <file_to_add>")
        print("  python main.py extract <vault_path> <password> <filename_in_vault> <output_path>")
        print("  python main.py list <vault_path> <password>")
        print("  python main.py remove <vault_path> <password> <filename_in_vault>")
        sys.exit(1)

    command = sys.argv[1].lower()
    vault = PartialReadVault()

    if command == "create":
        if len(sys.argv) < 4:
            print("Usage: python main.py create <vault_path> <password>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        vault.create_vault(vault_path, password)
        print(f"Vault created at {vault_path}")

    elif command == "open":
        if len(sys.argv) < 4:
            print("Usage: python main.py open <vault_path> <password>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        vault.unlock_vault(vault_path, password)
        print("Vault unlocked. Files in vault:")
        for fname in vault.list_files():
            print(f" - {fname}")

    elif command == "add":
        if len(sys.argv) < 5:
            print("Usage: python main.py add <vault_path> <password> <file_to_add>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        file_to_add = sys.argv[4]

        vault.unlock_vault(vault_path, password)
        vault.add_file(file_to_add)
        print(f"Added {file_to_add} to {vault_path}")

    elif command == "extract":
        if len(sys.argv) < 6:
            print("Usage: python main.py extract <vault_path> <password> <filename_in_vault> <output_path>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        filename_in_vault = sys.argv[4]
        output_path = sys.argv[5]

        vault.unlock_vault(vault_path, password)
        vault.extract_file(filename_in_vault, output_path)
        print(f"Extracted {filename_in_vault} to {output_path}")

    elif command == "list":
        if len(sys.argv) < 4:
            print("Usage: python main.py list <vault_path> <password>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]

        vault.unlock_vault(vault_path, password)
        files = vault.list_files()
        if files:
            print("Files in vault:")
            for fname, metadata in files.items():
                print(f" - {fname} (size: {metadata['plaintext_size']} bytes)")
        else:
            print("No files in the vault.")

    elif command == "remove":
        if len(sys.argv) < 5:
            print("Usage: python main.py remove <vault_path> <password> <filename_in_vault>")
            sys.exit(1)
        vault_path = sys.argv[2]
        password = sys.argv[3]
        filename_in_vault = sys.argv[4]

        vault.unlock_vault(vault_path, password)
        vault.remove_file(filename_in_vault)
        print(f"Removed {filename_in_vault} from vault")

    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
