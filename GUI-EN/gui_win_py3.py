import os
import getpass
import shutil
import tkinter as tk
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from ctypes import windll
import tkinter.messagebox as msgbox
from threading import Thread, Semaphore
from tkinter import ttk
from tkinter import messagebox
from tkinter import Text


try:
    import requests
except:
    os.system("pip install requests")
    try:
        import requests
    except:
        messagebox.askyesno("Installation Error", "The installation of the requests library has failed. Please install it manually and then run the program again.")

def get_technique_abbr(technique_full):
    techniques_dict = {
        "ALL": "BESUTQ",
        "Blind SQL Injection": "B",
        "Error-based SQL Injection": "E",
        "Stacked SQL Injection": "S",
        "Union-based SQL Injection": "U",
        "Time-based SQL Injection": "T",
        "Inline Query SQL Injection": "Q"
    }
    return techniques_dict.get(technique_full, '')


def copy_folders_with_log_files(source_path, dest_path):
    for root, dirs, files in os.walk(source_path):
        if "log" in files:
            log_file_path = os.path.join(root, "log")
            if os.path.getsize(log_file_path) > 0:
                folder_name = os.path.basename(root)
                dest_folder_path = os.path.join(dest_path, folder_name)
                shutil.copytree(root, dest_folder_path)
                
max_concurrent_cmds = 5
sem = Semaphore(max_concurrent_cmds)

def run_command():
    command_output.delete("1.0", "end")
    cmd = ["start", "cmd", "/k", "python3", "-Xfrozen_modules=off", "sqlmap.py"]
    cmd2 = ["start", "cmd", "/c", "python3", "-Xfrozen_modules=off", "sqlmap.py"]

    if "http" in top_textbox.get("1.0", "1.5"):
        if batch_url_var.get():
            textbox_content = top_textbox.get('1.0', 'end-1c')
            lines = textbox_content.splitlines()
        else:
            cmd.append("-u")
            cmd.append(top_textbox.get('1.0', 'end-1c'))
    else:
        if top_textbox.get("1.0", "end-1c").strip() != "":
            with open("url.txt", "w", encoding="utf-8") as file:
                file.write(top_textbox.get('1.0', 'end-1c'))
            cmd.append("-r url.txt")
    
    options1 = {
        'level': level_var.get(),
        'risk': risk_var.get(),
        'threads': threads_var.get(),
        'current-db': current_db_var.get(),
        'current-user': current_user_var.get(),
        'is-dba': is_dba_var.get(),
        'dbs': dbs_var.get(),
        'tables': tables_var.get(),
        'columns': columns_var.get(),
        'dump': dump_var.get(),
        'dump-all': dump_all_var.get(),
        'os-shell': os_shell_var.get(),
        'sql-shell': sql_shell_var.get(),
        'proxy': proxy_var.get(),
        'proxy-cred': proxy_cred_var.get(),
        'batch': batch_var.get(),
        'purge': purge_var.get(),
        'force-ssl' : ssl_var.get()
    }

    options2 = {
        'D': custom_db_var.get(),
        'T': custom_table_var.get(),
        'C': custom_column_var.get(),
        'o': optimizations_var.get()
    }



    if batch_data_var.get():
        txt_files = [f for f in os.listdir('batch') if f.endswith('.txt')]
        for txt_file in txt_files:
            new_cmd = cmd2.copy()
            new_cmd.append("-r")
            new_cmd.append("batch/" + txt_file)
            new_cmd.append("--batch")
            
            for option, value in options1.items():
                if value:
                    new_cmd.append(f"--{option.replace('_', '-')}")
                    if str(value).lower() != 'true':
                        new_cmd.append(str(value))

            for option, value in options2.items():
                if value:
                    new_cmd.append(f"-{option.replace('_', '-')}")
                    if str(value).lower() != 'true':
                        new_cmd.append(str(value))

            if random_agent_var.get():
                new_cmd.extend(["--random-agent", "--tamper=between", "--flush-session", "--randomize=1"])

            if custom_param_var.get():
                new_cmd.append(str(custom_param_var.get()))

            if dbms_type_var.get():
                new_cmd.append("--dbms=" + str(dbms_type_var.get()))

            def execute_command(command):
                os.system(" ".join(command))
                sem.release()

            sem.acquire()
            t = Thread(target=execute_command, args=(new_cmd,))
            t.start()
            
        source_path = f"C:\\Users\\{getpass.getuser()}\\AppData\\Local\\sqlmap\\output"
        dest_path = f"C:\\Users\\{getpass.getuser()}\\AppData\\Local\\sqlmap\\ldopt"
        copy_folders_with_log_files(source_path, dest_path)
        os.system(f'explorer C:\\Users\\{getpass.getuser()}\\AppData\\Local\\sqlmap\\ldopt')

    if technique_var.get():
        technique_abbr = get_technique_abbr(technique_var.get())
        cmd.extend(["--technique=" + technique_abbr])

    for option, value in options1.items():
        if value:
            cmd.append(f"--{option.replace('_', '-')}")
            if str(value).lower() != 'true':
                cmd.append(str(value))

    for option, value in options2.items():
        if value:
            cmd.append(f"-{option.replace('_', '-')}")
            if str(value).lower() != 'true':
                cmd.append(str(value))

    if random_agent_var.get():
        cmd.extend(["--random-agent", "--tamper=between", "--flush-session", "--randomize=1"])

    if custom_param_var.get():
        cmd.append(str(custom_param_var.get()))

    if dbms_type_var.get():
        cmd.append("--dbms=" + str(dbms_type_var.get()))
    
    if not batch_url_var.get():
        os.system(" ".join(cmd))
        print("the command executed:", " ".join(cmd))
        display_cmd = [part for part in cmd if part not in ["start", "cmd", "/k", "-Xfrozen_modules=off"]]
        output = " ".join(display_cmd)
        command_output.insert("end", output)
    else:
        cmd = ["start" if item == "start" else ("/c" if item == "/k" else item) for item in cmd]
        cmd_pl = cmd[:]
        def run_command(cmd_pl):
            cmd_pl = " ".join(cmd_pl)
            print(cmd_pl)
            process = subprocess.Popen(cmd_pl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            return stdout, stderr   
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(run_command, cmd_pl) for line in lines for cmd_pl in (cmd[:] + ["-u", line],)]
            for future in futures:
                stdout, stderr = future.result()
                print(f"STDOUT: {stdout.decode()}")
                print(f"STDERR: {stderr.decode()}")
def sqlmap_help():
    cmd = ["start", "cmd", "/k", "python3", "-Xfrozen_modules=off", "sqlmap.py", "-hh"]
    os.system(" ".join(cmd))


def help():
    custom_help_text = """
    Test level: 1-5 levels can be selected, with higher levels having more test content.
    Risk level: Selectable from 1 to 3 levels. Level 1 uses relatively safe syntax, while level 3 uses highly risky syntax.
    Thread Count: Choose from 1 to 20. SQLmap typically limits the maximum number of threads to 20.
    Current Database: Execute the --current-db command.
    Current User: Execute the --current-user command.
    Check DBA Privileges: Execute the --is-dba command.
    Enumerate Databases: Execute the --dbs command.
    Enumerate Tables: Execute the --tables command, specifying the database name. (Without a specific database name, it will enumerate all tables.)
    Enumerate Columns: Execute the --columns command, specifying the database and table names. (Without specific names, it will enumerate all columns.)
    Dump Data: Execute the --dump command, specifying the database, table, and column names. (Without specific names, it will dump all data.)
    Dump All Data: Execute the --dump-all command.
    OS Interactive Shell: Execute the --os-shell command.
    SQL Interactive Shell: Execute the --sql-shell command.
    Specify Database Name: Use the -D option.
    Specify Table Name: Use the -T option.
    Specify Column Name: Use the -C option.
    Command Text Box: Displays the SQLmap command being run.
    Set Proxy: Format is (http://|https://|socks5://IP:PORT).
    Proxy Authentication: Format is (username:password).
    Strip Identifying Features: Execute the --random-agent --tamper=between --flush-session --randomize=1 command.
    Enable All Optimization Options: Execute the -o command.
    Default Response: Execute the --batch command.
    Clear Cache: Execute the --purge command.
    Force SSL Communication: Execute the --force-ssl command.
    Batch Scan URLs: Execute the -u command with one URL per line and run multiple commands concurrently.
    Batch Scan Requests: Loop the -r command with default responses enabled and use multiple commands; after completion, automatically open the SQLmap results directory. (Leave the text box empty.)
    Injection Technique: Choose a specific injection technique or select all techniques.
    Specify Database Type: Choose a specific database type.
    Custom Parameters: Enter any additional parameters directly; they will be appended to the end of the command.
    View SQLMAP Help: View the content of sqlmap -hh.
    Start Execution: Save the text and execute the SQLmap command.
    Text Box in the Middle: Enter a URL starting with http to use the -u command, or enter request data to use the -r command.

    """
    help = tk.Toplevel()
    help.title("Help")
    label = tk.Label(help, text=custom_help_text)
    label.pack()
    help.update_idletasks()
    help.geometry(f"+{x}+{y}")
    
root = tk.Tk()
root.title("SQLmap汉化GUI版-V1.7   by本间白猫")

paned_window = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
paned_window.pack(fill=tk.BOTH, expand=True)

left_frame = ttk.Frame(paned_window, width=200, height=root.winfo_screenheight())
paned_window.add(left_frame, weight=1)

middle_frame = ttk.Frame(paned_window, width=400, height=root.winfo_screenheight())
paned_window.add(middle_frame, weight=3)

right_frame = ttk.Frame(paned_window, width=200, height=root.winfo_screenheight())
paned_window.add(right_frame, weight=1)

ttk.Label(left_frame, text="Test Level").pack(fill='x')
level_var = tk.StringVar(value='1')
level_combo = ttk.Combobox(left_frame, values=[str(i) for i in range(1, 6)], textvariable=level_var)
level_combo.pack(fill='x')

ttk.Label(left_frame, text="Risk Level").pack(fill='x')
risk_var = tk.StringVar(value='1')
risk_combo = ttk.Combobox(left_frame, values=[str(i) for i in range(1, 4)], textvariable=risk_var)
risk_combo.pack(fill='x')

ttk.Label(left_frame, text="Threads").pack(fill='x')
threads_var = tk.StringVar()
threads_entry = ttk.Entry(left_frame, textvariable=threads_var)
threads_entry.pack(fill='x')

current_db_var = tk.BooleanVar()
current_db_checkbutton = ttk.Checkbutton(left_frame, text="Current Database", variable=current_db_var)
current_db_checkbutton.pack(fill='x')

current_user_var = tk.BooleanVar()
current_user_checkbutton = ttk.Checkbutton(left_frame, text="Current User", variable=current_user_var)
current_user_checkbutton.pack(fill='x')

is_dba_var = tk.BooleanVar()
is_dba_checkbutton = ttk.Checkbutton(left_frame, text="Current User DBA Authority", variable=is_dba_var)
is_dba_checkbutton.pack(fill='x')

dbs_var = tk.BooleanVar()
dbs_checkbutton = ttk.Checkbutton(left_frame, text="Enumerate Database Names", variable=dbs_var)
dbs_checkbutton.pack(fill='x')

tables_var = tk.BooleanVar()
tables_checkbutton = ttk.Checkbutton(left_frame, text="Enumeration Table Name", variable=tables_var)
tables_checkbutton.pack(fill='x')

columns_var = tk.BooleanVar()
columns_checkbutton = ttk.Checkbutton(left_frame, text="Enumeration Column Name", variable=columns_var)
columns_checkbutton.pack(fill='x')

dump_var = tk.BooleanVar()
dump_checkbutton = ttk.Checkbutton(left_frame, text="Enumeration Field", variable=dump_var)
dump_checkbutton.pack(fill='x')

dump_all_var = tk.BooleanVar()
dump_all_checkbutton = ttk.Checkbutton(left_frame, text="Dump All", variable=dump_all_var)
dump_all_checkbutton.pack(fill='x')

os_shell_var = tk.BooleanVar()
os_shell_checkbutton = ttk.Checkbutton(left_frame, text="OS Interactive Shell", variable=os_shell_var)
os_shell_checkbutton.pack(fill='x')

sql_shell_var = tk.BooleanVar()
sql_shell_checkbutton = ttk.Checkbutton(left_frame, text="SQL Interactive Shell", variable=sql_shell_var)
sql_shell_checkbutton.pack(fill='x')

ttk.Label(left_frame, text="Specify The Database Name").pack(fill='x')
custom_db_var = tk.StringVar()
custom_db_entry = ttk.Entry(left_frame, textvariable=custom_db_var)
custom_db_entry.pack(fill='x')

ttk.Label(left_frame, text="Specify Table Name").pack(fill='x')
custom_table_var = tk.StringVar()
custom_table_entry = ttk.Entry(left_frame, textvariable=custom_table_var)
custom_table_entry.pack(fill='x')

ttk.Label(left_frame, text="Specify Column Names").pack(fill='x')
custom_column_var = tk.StringVar()
custom_column_entry = ttk.Entry(left_frame, textvariable=custom_column_var)
custom_column_entry.pack(fill='x')

command_output = Text(left_frame, height=3, wrap='word', width=20)
command_output.insert("1.0","When you run SQLmap, the SQLmap command that will be executed is shown here")  
command_output.pack(fill='both', expand=True, pady=10)

ttk.Label(right_frame, text="Set The Proxy").pack(fill='x')
proxy_var = tk.StringVar()
proxy_entry = ttk.Entry(right_frame, textvariable=proxy_var)
proxy_entry.pack(fill='x')

ttk.Label(right_frame, text="Proxy Authentication").pack(fill='x')
proxy_cred_var = tk.StringVar()
proxy_cred_entry = ttk.Entry(right_frame, textvariable=proxy_cred_var)
proxy_cred_entry.pack(fill='x')

random_agent_var = tk.BooleanVar()
random_agent_checkbutton = ttk.Checkbutton(right_frame, text="Removal Feature", variable=random_agent_var)
random_agent_checkbutton.pack(fill='x')

optimizations_var = tk.BooleanVar()
optimizations_checkbutton = ttk.Checkbutton(right_frame, text="Turn On All Optimization Switches", variable=optimizations_var)
optimizations_checkbutton.pack(fill='x')

batch_var = tk.BooleanVar()
batch_checkbutton = ttk.Checkbutton(right_frame, text="Default Response", variable=batch_var)
batch_checkbutton.pack(fill='x')

purge_var = tk.BooleanVar()
purge_checkbutton = ttk.Checkbutton(right_frame, text="Clear Cache", variable=purge_var)
purge_checkbutton.pack(fill='x')

ssl_var = tk.BooleanVar()
ssl_checkbutton = ttk.Checkbutton(right_frame, text="Mandatory SSL Protocol", variable=ssl_var)
ssl_checkbutton.pack(fill='x')

batch_url_var = tk.BooleanVar()
batch_url_checkbutton = ttk.Checkbutton(right_frame, text="Batch Scan URLs", variable=batch_url_var)
batch_url_checkbutton.pack(fill='x')

batch_data_var = tk.BooleanVar()
batch_data_checkbutton = ttk.Checkbutton(right_frame, text="Batch Scanning Of Packets", variable=batch_data_var)
batch_data_checkbutton.pack(fill='x')

techniques = ["", "ALL","Blind SQL Injection", "Error-based SQL Injection", "Stacked SQL Injection", "Union-based SQL Injection", "Time-based SQL Injection", "Inline Query SQL Injection"]
technique_var = tk.StringVar(value=techniques[0])
ttk.Label(right_frame, text="Injection Mode").pack(fill='x')
technique_combo = ttk.Combobox(right_frame, values=techniques, textvariable=technique_var)
technique_combo.pack(fill='x')

dbmss = ["", " Altibase"," Amazon Redshift"," Apache Derby"," Apache Ignite"," Aurora"," ClickHouse"," CockroachDB"," CrateDB"," Cubrid"," Drizzle"," EnterpriseDB"," eXtremeDB"," Firebird"," FrontBase"," Greenplum"," H2"," HSQLDB"," IBM DB2"," Informix"," InterSystems Cache"," Iris"," MariaDB"," Mckoi"," MemSQL"," Microsoft Access"," Microsoft SQL Server"," MimerSQL"," MonetDB"," MySQL"," OpenGauss"," Oracle"," Percona"," PostgreSQL"," Presto"," Raima Database Manager"," SAP MaxDB"," SQLite"," Sybase"," TiDB"," Vertica"," Virtuoso"," Yellowbrick"," YugabyteDB"]
dbms_type_var = tk.StringVar(value=techniques[0])
ttk.Label(right_frame, text="Specify Database Type").pack(fill='x')
dbms_type_entry = ttk.Combobox(right_frame, values=dbmss, textvariable=dbms_type_var)
dbms_type_entry.pack(fill='x')

ttk.Label(right_frame, text="Custom Parameters").pack(fill='x')
custom_param_var = tk.StringVar()
custom_param_entry = ttk.Entry(right_frame, textvariable=custom_param_var)
custom_param_entry.pack(fill='x')

make_batch_button = ttk.Button(right_frame, text="Create Batch Data Packages", command=lambda: make_batch())
make_batch_button.pack(fill='x',pady=(10, 0))

sqlmap_help_button = ttk.Button(right_frame, text="SQLMAP Help", command=lambda: sqlmap_help())
sqlmap_help_button.pack(fill='x',pady=(10, 0))

help_button = ttk.Button(right_frame, text="Help", command=lambda: help())
help_button.pack(fill='x',pady=(10, 0))

check_button = ttk.Button(right_frame, text="Check The Version", command=lambda: update_module())
check_button.pack(fill='x',pady=(10, 0))

run_button = ttk.Button(right_frame, text="RUN", command=lambda: run_command())
run_button.pack(fill='x',side='bottom',pady=(10, 10))

def clear_default_text(event):
    if top_textbox.get("1.0", "end-1c") == default_text:
        top_textbox.delete("1.0", "end")

default_text = """

1. When entering a URL that starts with http here, the-u command, which allows you to scan the URL directly. For example: 10.10.10.10/id=1?

2. When entering data packets grabbed by tools such as burp here, the-r command, which allows you to directly scan the request packet. For example:
-----------------------------------------
POST /vul/sqli/sqli_id.php HTTP/1.1
Host: host
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml

id=1&submit=%E6%9F%A5%E8%AF%A2
-----------------------------------------

3. If you want to implement the "Batch Scan URL" function, check this function, and in the text box, place the targets you want to batch scan according to the rule of one URL per line. For example:
-------------------------
http://10.10.10.10/id=1?
http://20.20.20.20/id=1?
http://30.30.30.30/id=1?
-------------------------

4. If you want to perform the "Batch Scan Data Packet" function, you must clear everything here, then find a "batch" folder in the tool's directory, and place it in the form of a txt file for each data packet.
Tip: Only check "Batch Scan Data Packages", and then start running the folder where you can directly start saving sqlmap results.

5. You can click the button on the right to create a data package for batch scanning. Click Generate Data Package in the toolbox and return to the main interface. Check the "Batch Scan Data Package" function to start batch scanning.

6. If you have any doubts about the use of this tool, you can click "Help" on the right side for more information.
"""
top_textbox = tk.Text(middle_frame, height=15, width=50)
top_textbox.insert("1.0", default_text)
top_textbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

top_textbox.bind("<FocusIn>", clear_default_text)

def make_batch():
    def generate_and_save_data():
        left_contents = [text_entry_left.get("1.0", "end-1c") for text_entry_left in text_entries_left]
        right_contents = [text_entry_right.get("1.0", "end-1c") for text_entry_right in text_entries_right]
        
        middle_text_content1 = text_entry_middle1.get("1.0", "end-1c")
        max_chars_to_compare = max(len(left_content) for left_content in left_contents)
        middle_lines = middle_text_content1.split('\n')
        split_index = 0
        for i, line in enumerate(middle_lines):
            if not line.strip():
                split_index = i
                break

        right_lines = [right_content.split("\n") for right_content in right_contents]

        for line_number in range(max(len(line) for line in right_lines)):
            updated_middle_lines = []

            for idx, line in enumerate(middle_lines):
                if any(left[:max_chars_to_compare] == line[:max_chars_to_compare] for left in left_contents if len(left) >= max_chars_to_compare):
                    new_line = '\n'.join([f"{left}:{right_line[line_number]}" for left, right_line in zip(left_contents, right_lines) if len(right_line) > line_number and right_line[line_number].strip()])
                    updated_middle_lines.append(new_line)
                else:
                    updated_middle_lines.append(line)

            filename = f"batch/{line_number + 1}.txt"
            with open(filename, "w") as file:
                file.write('\n'.join(updated_middle_lines))
            print('\n'.join(updated_middle_lines))
        messagebox.showinfo("Data Packet Generated Successfully", f"Generated And Saved To Multiple Files")


    second_root = tk.Tk()
    second_root.title("Batch Generation Data Package Toolbox")

    paned_window_second = ttk.PanedWindow(second_root, orient=tk.HORIZONTAL)
    paned_window_second.pack(fill=tk.BOTH, expand=True)

    left_frame_second = ttk.Frame(paned_window_second, width=150, height=1)
    paned_window_second.add(left_frame_second, weight=1)

    middle_frame_second = ttk.Frame(paned_window_second, width=400, height=second_root.winfo_screenheight())
    paned_window_second.add(middle_frame_second, weight=3)

    right_frame_second = ttk.Frame(paned_window_second, width=150, height=1)
    paned_window_second.add(right_frame_second, weight=1)

    text_entries_left = []
    text_entries_right = []

    for i in range(1, 9):
        ttk.Label(left_frame_second, text=f"Request Header Input Box-{i}").pack(fill='x')
        text_entry_left = tk.Text(left_frame_second, height=2, width=20)
        text_entry_left.pack(fill='x', pady=(0, 0))
        text_entries_left.append(text_entry_left)

    text1 = """
    Only One Line Can Be Entered In This Input Field
    Request Header Input Box-1
    Host
    Request Header Input Box-2
    Cookie
    """
    sample_desc_left = ttk.Label(left_frame_second, text=text1)
    sample_desc_left.pack(fill='both', expand=True)

    make_packet_button = ttk.Button(left_frame_second, text="Generate A Data Packet", command=generate_and_save_data)
    make_packet_button.pack(fill='x', pady=(0, 10))

    def clear_default_text1(event):
        if text_entry_middle1.get("1.0", "end-1c") == text2:
            text_entry_middle1.delete("1.0", "end")
    
    text2 = """
    Place the request package here, and the following is an example

    POST /login.php HTTP/1.1
    Host: 127.0.0.1
    Cookie: shironeko

    user=shironeko&pass=123456
    """

    ttk.Label(middle_frame_second, text="Request Packet Input Box").pack(fill='x')
    text_entry_middle1 = tk.Text(middle_frame_second, height=24, width=60)
    text_entry_middle1.insert("1.0", text2)
    text_entry_middle1.pack(fill="both", expand=True, pady=(0, 10))
    text_entry_middle1.bind("<FocusIn>", clear_default_text1)
    
    for i in range(1, 9):
        ttk.Label(right_frame_second, text=f"Request Header Content-{i}").pack(fill='x')
        text_entry_right = tk.Text(right_frame_second, height=2, width=20)
        text_entry_right.pack(fill='x', pady=(0, 0))
        text_entries_right.append(text_entry_right)

    text3 = """
    This input field supports multiple lines.
    Request Header Content-1
    192.168.0.1
    192.168.0.2
    Request Header Content-2
    admin1
    admin2
    """

    sample_desc_right = ttk.Label(right_frame_second, text=text3)
    sample_desc_right.pack(fill='both', expand=True)

    make_packet_button = ttk.Button(right_frame_second, text="Generate A Data Packet", command=generate_and_save_data)
    make_packet_button.pack(fill='x', pady=(0, 10))
    second_root.geometry("+%d+%d" % (x, y))

    second_root.mainloop()

def show_custom_dialog(text1,x,y):
    root = tk.Tk()
    root.withdraw()
    dialog = tk.Toplevel(root)
    dialog.title("Update Reminder")
    text_widget = tk.Text(dialog, height=5, wrap='word')
    text_widget.insert(tk.END, text1)
    text_widget.config(state='disabled')
    text_widget.pack(expand=True, fill='both', padx=20, pady=20)
    dialog.geometry(f"+{x}+{y}")
    dialog.update_idletasks()
    ok_button = tk.Button(dialog, text="Yes", command=dialog.destroy)
    ok_button.pack(pady=(0, 20))

    dialog.mainloop()
def update_module(x,y):
    try:
        sqlmap_time = "2024-07-22"
        url = "https://y.shironekosan.cn/1.html"
        response = requests.get(url)
        pattern = r'<div\s+class="nc-light-gallery"\s+id="image_container">(.*?)</div>'
        matches = re.search(pattern, response.text, re.DOTALL)
        content_array = []
        
        if matches:
            inner_content = matches.group(1)
            p_matches = re.findall(r'<p>(.*?)</p>', inner_content)
            content_array.extend(p_matches)
        if sqlmap_time == content_array[1]:
            pass
        else:
            text1 = """
            SQLmap-GUI The latest updates exist. Please go to any of the following addresses to obtain updates:
            https://pan.quark.cn/s/39b4b5674570#/list/share
            https://github.com/honmashironeko/sqlmap-gui/
            https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5/
            """
            show_custom_dialog(text1,x,y)
    except Exception as e:
        messagebox.askyesno("Update Reminder", "Your network is abnormal. Please check the network environment！")
        print(e)


root.withdraw()
msgbox.showinfo("Usage Terms", """
This tool is only a graphical interface that mainly provides simplicity for operation. You can place files under any sqlmap version for your learning and use only.
This tool allows you to conduct secondary development or forward it to others, but I hope you can keep the original author information. Long live open source ~
Welcome to pay attention to the Weixin Official Accounts：樱花庄的本间白猫
Author's Blog：https://y.shironekosan.cn
Author's：本间白猫
""")
root.deiconify()
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
root.update_idletasks()
root_width = root.winfo_width()
root_height = root.winfo_height()
x = (screen_width - root_width) // 2
y = (screen_height - root_height) // 2
root.geometry("+%d+%d" % (x, y))
root.mainloop()
update_module(x, y)