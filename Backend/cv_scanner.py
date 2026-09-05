import re
import os
import requests
import zipfile
import shutil
import datetime
import sys
import multiprocessing

def should_update():
    current_date = datetime.date.today()
    last_updated_date = None
    if not os.path.exists("db_temp"):
        return True
    if os.path.exists("last_updated_date.txt"):
        try:
            with open("last_updated_date.txt", "r") as file:
                last_updated_date = datetime.datetime.strptime(file.read().strip(), "%Y-%m-%d").date()
        except (ValueError, FileNotFoundError):
            last_updated_date = None
    if last_updated_date is None or current_date >= last_updated_date + datetime.timedelta(days=30):
        return True

    return False


def update():
    url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
    try:
        # Remove the existing update.zip if it exists
        if os.path.exists("update.zip"):
            os.remove("update.zip")
        print("Downloading database")
        # Download the zip file
        response = requests.get(url)
        response.raise_for_status()

        # Save the zip file
        with open("update.zip", "wb") as file:
            file.write(response.content)

        # Remove the old extracted folder if it exists
        folder_name = "db_temp"
        folder_path = os.path.join(os.getcwd(), folder_name)

        # Check if the folder exists
        if os.path.exists(folder_path):
            # Remove the folder
            shutil.rmtree(folder_path)

        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Extract the contents of update.zip into the db_temp folder
        with zipfile.ZipFile("update.zip", "r") as zip_ref:
            zip_ref.extractall(folder_name)

        os.remove("update.zip")
        print("CVE database updated")
        return True

    except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
        print(f"Error occurred while updating CVE database: {str(e)}")
        return False

def search_keywords_in_files(keywords, files_to_process, key_map, out_list):
    for keyword in keywords:
        key_map[keyword] = []

    for file in files_to_process:
        file_name = os.path.basename(file)
        if file_name != "metadata.json":
            with open(file, 'r') as f:
                file_content = f.read()
                for keyword in keywords:
                    if keyword in file_content:
                        result = f"{keyword} {file_name}\n"
                        print(result)
                        key_map[keyword].append(file_name)

    for keyword, files in key_map.items():
        out_list.append(f"Possible vulnerabilities of: {keyword}\n")
        for file in files:
            out_list.append(f"    {file}\n")
        out_list.append("\n")


def find_cve(text):
    try:
        # Update CVE database
        if should_update():
            updated = update()
            if updated:
                with open("last_updated_date.txt", "w") as file:
                    file.write(datetime.date.today().strftime("%Y-%m-%d"))
                print("CVE DB Update successful.")
            else:
                print("CVE DB Update failed. Retrying tomorrow.")

        with open("ignore.txt", "r") as file:
            ignore_dict = {}
            for line in file:
                words = line.strip().split()
                for word in words:
                    ignore_dict[word] = True

        content = text
        patterns = []

        with open("regular_expression.txt", "r") as file:
            for line in file:
                pattern = line.strip()
                patterns.append(pattern)

        matches = []
        keywords = []
        key_map = {}
        print("Using regular expression for finding software vulnerabilities:")
        for pattern in patterns:
            print(pattern)
            try:
                matches.extend(re.findall(pattern, content, re.IGNORECASE | re.DOTALL))
            except Exception as e:
                print("Error in regular expression:", e)

        for match in matches:
            if match[0] not in ignore_dict:
                line = f"{match[0]} {match[1]}"
                keywords.append(line)

        local_repo_path = "db_temp"
        print("Scanning for vulnerabilities......")

        for key in keywords:
            key_map[key] = []

        files_to_process = []
        for root, dirs, files in os.walk(local_repo_path):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    files_to_process.append(file_path)

        # Divide files into chunks for parallel processing
        chunk_size = (len(files_to_process) + 3) // 4
        file_chunks = [files_to_process[i:i + chunk_size] for i in range(0, len(files_to_process), chunk_size)]

        # Create a multiprocessing pool with 4 processes
        with multiprocessing.Pool(processes=4) as pool:
            manager = multiprocessing.Manager()
            out_list = manager.list()
            # Submit tasks to the pool
            results = []
            for chunk in file_chunks:
                results.append(pool.apply_async(search_keywords_in_files, args=(keywords, chunk, key_map, out_list)))

            # Wait for all processes to finish
            for result in results:
                result.get()

        out = "".join(out_list)
        # Write the result to output.txt in the desired format
        with open("testoutput.txt", "w") as output_file:
            output_file.write(out)

        print("Done")
        return out

    except Exception as e:
        print("An error occurred:", str(e))


if __name__ == '__main__':
    multiprocessing.freeze_support()  
    
    if len(sys.argv) < 2:
        print("Please provide the file name to be scanned.")
        sys.exit(1)

    input_file = sys.argv[1]

    temp = ""
    with open(input_file, "r") as file:
        temp = file.read()

    output = find_cve(temp)
    

    with open("output.txt", "w") as output_file:
        output_file.write(output)

    print(output)



























"""
import re
import os
import requests
import zipfile
import shutil
import datetime
import sys
import multiprocessing

def should_update():
    current_date = datetime.date.today()
    last_updated_date = None
    if not os.path.exists("db_temp"):
        return True
    if os.path.exists("last_updated_date.txt"):
        try:
            with open("last_updated_date.txt", "r") as file:
                last_updated_date = datetime.datetime.strptime(file.read().strip(), "%Y-%m-%d").date()
        except (ValueError, FileNotFoundError):
            last_updated_date = None
    if last_updated_date is None or current_date >= last_updated_date + datetime.timedelta(days=30):
        return True

    return False


def update():
    url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
    try:
        # Remove the existing update.zip if it exists
        if os.path.exists("update.zip"):
            os.remove("update.zip")
        print("Downloading database")
        # Download the zip file
        response = requests.get(url)
        response.raise_for_status()

        # Save the zip file
        with open("update.zip", "wb") as file:
            file.write(response.content)

        # Remove the old extracted folder if it exists
        folder_name = "db_temp"
        folder_path = os.path.join(os.getcwd(), folder_name)

        # Check if the folder exists
        if os.path.exists(folder_path):
            # Remove the folder
            shutil.rmtree(folder_path)

        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Extract the contents of update.zip into the db_temp folder
        with zipfile.ZipFile("update.zip", "r") as zip_ref:
            zip_ref.extractall(folder_name)

        os.remove("update.zip")
        print("CVE database updated")
        return True

    except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
        print(f"Error occurred while updating CVE database: {str(e)}")
        return False



def search_keywords_in_files(keywords, files_to_process, key_map):
    for file in files_to_process:
        file_name = os.path.basename(file)
        if file_name != "metadata.json":
            with open(file, 'r') as f:
                file_content = f.read()
                for keyword in keywords:
                    if keyword in file_content:
                        print(keyword + " " + file_name)
                        key_map[keyword].append(file_name)
                        # Test code , to be removed...
                        #for testvar in key_map[keyword]:
                            #print(testvar)
                    

def find_cve(text):
    try:
        # Update CVE database
        if should_update():
            updated = update()
            if updated:
                with open("last_updated_date.txt", "w") as file:
                    file.write(datetime.date.today().strftime("%Y-%m-%d"))
                print("CVE DB Update successful.")
            else:
                print("CVE DB Update failed. Retrying tomorrow.")

        with open("ignore.txt", "r") as file:
            ignore_dict = {}
            for line in file:
                words = line.strip().split()
                for word in words:
                    ignore_dict[word] = True

        content = text
        patterns = []

        with open("regular_expression.txt", "r") as file:
            for line in file:
                pattern = line.strip()
                patterns.append(pattern)

        matches = []
        keywords = []
        key_map = {}
        print("Using regular expression for finding software vulnerabilities:")
        for pattern in patterns:
            print(pattern)
            try:
                matches.extend(re.findall(pattern, content, re.IGNORECASE | re.DOTALL))
            except Exception as e:
                print("Error in regular expression:", e)

        for match in matches:
            if match[0] not in ignore_dict:
                line = f"{match[0]} {match[1]}"
                keywords.append(line)

        local_repo_path = "db_temp"
        print("Scanning for vulnerabilities......")

        for key in keywords:
            key_map[key] = []

        files_to_process = []
        for root, dirs, files in os.walk(local_repo_path):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    files_to_process.append(file_path)

        # Divide files into chunks for parallel processing
        chunk_size = (len(files_to_process) + 3) // 4
        file_chunks = [files_to_process[i:i + chunk_size] for i in range(0, len(files_to_process), chunk_size)]

        # Create a multiprocessing pool with 4 processes
        with multiprocessing.Pool(processes=4) as pool:
            # Submit tasks to the pool
            results = []
            for chunk in file_chunks:
                results.append(pool.apply_async(search_keywords_in_files, args=(keywords, chunk, key_map)))

            # Wait for all processes to finish
            for result in results:
                result.get()

        out = ""
        for keyword, file_paths in key_map.items():
            out += "Possible vulnerabilities of " + keyword + "\n"
            for file_path in file_paths:
                out += "  " + file_path + "??\n"
        print(file_path)
        print("Done")
        print(out)
        return out

    except Exception as e:
        return f"An error occurred: {str(e)}"

if __name__ == '__main__':
    multiprocessing.freeze_support()  
    
    if len(sys.argv) < 2:
        print("Please provide the file name to be scanned.")
        sys.exit(1)

    input_file = sys.argv[1]

    temp = ""
    with open(input_file, "r") as file:
        temp = file.read()

    output = find_cve(temp)
    

    with open("output.txt", "w") as output_file:
        output_file.write(output)

    print(output)
"""
