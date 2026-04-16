from core.menu import print_banner, show_menu, get_user_choice, handle_choice


def main():
    print_banner()

    while True:
        show_menu()
        choice = get_user_choice()
        handle_choice(choice)


if __name__ == "__main__":
    main()