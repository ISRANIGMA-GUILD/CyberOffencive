import os


def main() -> None:
    root_folder = input('Enter folder name of your character: ')
    if not os.path.exists(root_folder):
        print("Invalid folder!")
        return
    
    extension = input('Enter files extension: ')
    extension_dots_amount = extension.count('.')
    if extension_dots_amount > 1:
        extension.replace('.', '')
    if not extension.startswith('.'):
        extension = "." + extension
        
    sub_folders = [os.path.join(root_folder, sub_folder) for sub_folder in os.listdir(root_folder) if os.path.isdir(os.path.join(root_folder, sub_folder))]

    for sub_folder in sub_folders:
        status = sub_folder.split('\\')[-1]
        frame_index = 0
        files = [os.path.join(sub_folder, file) for file in os.listdir(sub_folder) if os.path.isfile(os.path.join(sub_folder, file))]
        for file in files:
            try:
                new_file_name = status + "_" + str(frame_index) + extension
                frame_index += 1
                os.rename(file, os.path.join(sub_folder, new_file_name))
            except FileExistsError:
                pass
            

if __name__ == "__main__":
    main()