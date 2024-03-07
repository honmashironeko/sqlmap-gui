import tkinter as tk
import tkinter.messagebox as msgbox
import os
import getpass
from threading import Thread, Semaphore
from tkinter import ttk
from tkinter import messagebox
from tkinter import Text

def get_technique_abbr(technique_full):
    techniques_dict = {
        "全选": "BESUTQ",
        "盲注": "B",
        "报错注入": "E",
        "堆叠注入": "S",
        "联合查询注入": "U",
        "时间注入": "T",
        "内联查询注入": "Q"
    }
    return techniques_dict.get(technique_full, '')

max_concurrent_cmds = 5
sem = Semaphore(max_concurrent_cmds)

def run_command():
    command_output.delete("1.0", "end")
    cmd = ["start", "cmd", "/k", "python", "-Xfrozen_modules=off", "sqlmap.py"]
    cmd2 = ["start", "cmd", "/c", "python", "-Xfrozen_modules=off", "sqlmap.py"]

    if "http" in top_textbox.get("1.0", "1.5"):
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
        '--force-ssl' : ssl_var.get()
    }

    options2 = {
        'D': custom_db_var.get(),
        'T': custom_table_var.get(),
        'C': custom_column_var.get(),
        'o': optimizations_var.get()
    }

    if batch_url_var.get():
        cmd.append("-m batch_url.txt")

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
                new_cmd.extend(["--random-agent", "--tamper=between", "--flush-session", "--randomize=1", "--skip=XSS"])

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
        os.system(f'explorer C:\\Users\\{getpass.getuser()}\\AppData\\Local\\sqlmap\\output')
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
        cmd.extend(["--random-agent", "--tamper=between", "--flush-session", "--randomize=1", "--skip=XSS"])

    if custom_param_var.get():
        cmd.append(str(custom_param_var.get()))

    if dbms_type_var.get():
        cmd.append("--dbms=" + str(dbms_type_var.get()))

    if not batch_data_var.get():
        os.system(" ".join(cmd))
        print("执行的命令:", " ".join(cmd))
        display_cmd = [part for part in cmd if part not in ["start", "cmd", "/k", "-Xfrozen_modules=off"]]
        output = " ".join(display_cmd)
        command_output.insert("end", output)

def sqlmap_help():
    cmd = ["start", "cmd", "/k", "python", "-Xfrozen_modules=off", "sqlmap.py", "-hh"]
    os.system(" ".join(cmd))

def check_create_files():
    if not os.path.exists("url.txt"):
        with open("url.txt", "w", encoding="utf-8"):
            pass

    if not os.path.exists("batch"):
        os.makedirs("batch")

    if not os.path.exists("batch_url.txt"):
        with open("batch_url.txt", "w", encoding="utf-8"):
            pass

def help():
    custom_help_text = """
    测试级别：可选择1-5级，等级越高测试内容越多。
    风险级别：可选择1-3级，1级采用相对安全的语法，3级采用非常危险的语法。
    线程数：可选择1-20，通常SQLmap限制最高20线程。
    当前数据库：执行--current-db命令。
    当前用户：执行--current-user命令。
    当前用户DBA权限：执行--is-dba命令。
    枚举库名：执行--dbs命令。
    枚举表名：执行--tables命令，需要填入 指定库名 。（不填写指定内容会枚举所有）
    枚举列名：执行--columns命令，需要填入 指定库名、指定表名 。（不填写指定内容会枚举所有）
    枚举字段：执行--dump命令，需要填入 指定库名、指定表名、指定列名 。（不填写指定内容会枚举所有）
    一键脱库：执行--dump-all命令。
    OS交互式Shell：执行--os-shell命令。
    SQL交互式Shell：执行--sql-shell命令。
    指定库名：执行-D命令。
    指定表名：执行-T命令。
    指定列名：执行-C命令。
    设置代理：格式为(http://|https://|socks5://IP:PORT)
    代理身份验证：格式为(用户名:密码)
    一键去特征：执行--random-agent --tamper=between --flush-session --randomize=1 --skip=XSS命令。
    打开所有优化开关：执行-o命令。
    默认应答：执行--batch命令。
    清除缓存：执行--purge命令。
    强制SSL通信：执行--force-ssl命令。
    批量扫描URL：执行-m命令，一行一条的形式填写URL。(中间文本框留空)
    批量扫描数据包：循环执行-r命令，开启默认应答，启用大量cmd来运行，结束后自动打开sqlmap结果目录。(中间文本框留空)
    注入方式：可选择指定注入方式或全部注入方式。
    指定数据库类型：可选择指定数据库类型。
    自定义参数：直接填写需要的额外参数，会自动添加在命令最后。
    查看SQLMAP帮助：查看sqlmap -hh内容。
    开始运行：保存中间内容并执行SQLmap命令。
    文本框：回显运行的SQLmap命令。
    中部文本框：填写http开头执行-u命令，填写数据包执行-r命令。

    """
    help = tk.Toplevel()
    help.title("帮助")
    label = tk.Label(help, text=custom_help_text)
    label.pack()
    help.update_idletasks()
    help.geometry(f"+{x}+{y}")
    
root = tk.Tk()
root.title("SQLMap汉化GUI版   by本间白猫")

paned_window = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
paned_window.pack(fill=tk.BOTH, expand=True)

left_frame = ttk.Frame(paned_window, width=200, height=root.winfo_screenheight())
paned_window.add(left_frame, weight=1)

middle_frame = ttk.Frame(paned_window, width=400, height=root.winfo_screenheight())
paned_window.add(middle_frame, weight=3)

right_frame = ttk.Frame(paned_window, width=200, height=root.winfo_screenheight())
paned_window.add(right_frame, weight=1)

ttk.Label(left_frame, text="测试级别").pack(fill='x')
level_var = tk.StringVar(value='1')
level_combo = ttk.Combobox(left_frame, values=[str(i) for i in range(1, 6)], textvariable=level_var)
level_combo.pack(fill='x')

ttk.Label(left_frame, text="风险级别").pack(fill='x')
risk_var = tk.StringVar(value='1')
risk_combo = ttk.Combobox(left_frame, values=[str(i) for i in range(1, 4)], textvariable=risk_var)
risk_combo.pack(fill='x')

ttk.Label(left_frame, text="线程数").pack(fill='x')
threads_var = tk.StringVar()
threads_entry = ttk.Entry(left_frame, textvariable=threads_var)
threads_entry.pack(fill='x')

current_db_var = tk.BooleanVar()
current_db_checkbutton = ttk.Checkbutton(left_frame, text="当前数据库", variable=current_db_var)
current_db_checkbutton.pack(fill='x')

current_user_var = tk.BooleanVar()
current_user_checkbutton = ttk.Checkbutton(left_frame, text="当前用户", variable=current_user_var)
current_user_checkbutton.pack(fill='x')

is_dba_var = tk.BooleanVar()
is_dba_checkbutton = ttk.Checkbutton(left_frame, text="当前用户DBA权限", variable=is_dba_var)
is_dba_checkbutton.pack(fill='x')

dbs_var = tk.BooleanVar()
dbs_checkbutton = ttk.Checkbutton(left_frame, text="枚举库名", variable=dbs_var)
dbs_checkbutton.pack(fill='x')

tables_var = tk.BooleanVar()
tables_checkbutton = ttk.Checkbutton(left_frame, text="枚举表名", variable=tables_var)
tables_checkbutton.pack(fill='x')

columns_var = tk.BooleanVar()
columns_checkbutton = ttk.Checkbutton(left_frame, text="枚举列名", variable=columns_var)
columns_checkbutton.pack(fill='x')

dump_var = tk.BooleanVar()
dump_checkbutton = ttk.Checkbutton(left_frame, text="枚举字段", variable=dump_var)
dump_checkbutton.pack(fill='x')

dump_all_var = tk.BooleanVar()
dump_all_checkbutton = ttk.Checkbutton(left_frame, text="一键脱库", variable=dump_all_var)
dump_all_checkbutton.pack(fill='x')

os_shell_var = tk.BooleanVar()
os_shell_checkbutton = ttk.Checkbutton(left_frame, text="OS交互式Shell", variable=os_shell_var)
os_shell_checkbutton.pack(fill='x')

sql_shell_var = tk.BooleanVar()
sql_shell_checkbutton = ttk.Checkbutton(left_frame, text="SQL交互式Shell", variable=sql_shell_var)
sql_shell_checkbutton.pack(fill='x')

ttk.Label(left_frame, text="指定库名").pack(fill='x')
custom_db_var = tk.StringVar()
custom_db_entry = ttk.Entry(left_frame, textvariable=custom_db_var)
custom_db_entry.pack(fill='x')

ttk.Label(left_frame, text="指定表名").pack(fill='x')
custom_table_var = tk.StringVar()
custom_table_entry = ttk.Entry(left_frame, textvariable=custom_table_var)
custom_table_entry.pack(fill='x')

ttk.Label(left_frame, text="指定列名").pack(fill='x')
custom_column_var = tk.StringVar()
custom_column_entry = ttk.Entry(left_frame, textvariable=custom_column_var)
custom_column_entry.pack(fill='x')

ttk.Label(right_frame, text="设置代理").pack(fill='x')
proxy_var = tk.StringVar()
proxy_entry = ttk.Entry(right_frame, textvariable=proxy_var)
proxy_entry.pack(fill='x')

ttk.Label(right_frame, text="代理身份验证").pack(fill='x')
proxy_cred_var = tk.StringVar()
proxy_cred_entry = ttk.Entry(right_frame, textvariable=proxy_cred_var)
proxy_cred_entry.pack(fill='x')

random_agent_var = tk.BooleanVar()
random_agent_checkbutton = ttk.Checkbutton(right_frame, text="一键去特征", variable=random_agent_var)
random_agent_checkbutton.pack(fill='x')

optimizations_var = tk.BooleanVar()
optimizations_checkbutton = ttk.Checkbutton(right_frame, text="打开所有优化开关", variable=optimizations_var)
optimizations_checkbutton.pack(fill='x')

batch_var = tk.BooleanVar()
batch_checkbutton = ttk.Checkbutton(right_frame, text="默认应答", variable=batch_var)
batch_checkbutton.pack(fill='x')

purge_var = tk.BooleanVar()
purge_checkbutton = ttk.Checkbutton(right_frame, text="清除缓存", variable=purge_var)
purge_checkbutton.pack(fill='x')

ssl_var = tk.BooleanVar()
ssl_checkbutton = ttk.Checkbutton(right_frame, text="强制SSL协议", variable=ssl_var)
ssl_checkbutton.pack(fill='x')

batch_url_var = tk.BooleanVar()
batch_url_checkbutton = ttk.Checkbutton(right_frame, text="批量扫描URL", variable=batch_url_var)
batch_url_checkbutton.pack(fill='x')

batch_data_var = tk.BooleanVar()
batch_data_checkbutton = ttk.Checkbutton(right_frame, text="批量扫描数据包", variable=batch_data_var)
batch_data_checkbutton.pack(fill='x')

techniques = ["", "全选","盲注", "报错注入", "堆叠注入", "联合查询注入", "时间注入", "内联查询注入"]
technique_var = tk.StringVar(value=techniques[0])
ttk.Label(right_frame, text="注入方式").pack(fill='x')
technique_combo = ttk.Combobox(right_frame, values=techniques, textvariable=technique_var)
technique_combo.pack(fill='x')

dbmss = ["", " Altibase"," Amazon Redshift"," Apache Derby"," Apache Ignite"," Aurora"," ClickHouse"," CockroachDB"," CrateDB"," Cubrid"," Drizzle"," EnterpriseDB"," eXtremeDB"," Firebird"," FrontBase"," Greenplum"," H2"," HSQLDB"," IBM DB2"," Informix"," InterSystems Cache"," Iris"," MariaDB"," Mckoi"," MemSQL"," Microsoft Access"," Microsoft SQL Server"," MimerSQL"," MonetDB"," MySQL"," OpenGauss"," Oracle"," Percona"," PostgreSQL"," Presto"," Raima Database Manager"," SAP MaxDB"," SQLite"," Sybase"," TiDB"," Vertica"," Virtuoso"," Yellowbrick"," YugabyteDB"]
dbms_type_var = tk.StringVar(value=techniques[0])
ttk.Label(right_frame, text="指定数据库类型").pack(fill='x')
dbms_type_entry = ttk.Combobox(right_frame, values=dbmss, textvariable=dbms_type_var)
dbms_type_entry.pack(fill='x')

ttk.Label(right_frame, text="自定义参数").pack(fill='x')
custom_param_var = tk.StringVar()
custom_param_entry = ttk.Entry(right_frame, textvariable=custom_param_var)
custom_param_entry.pack(fill='x')

sqlmap_help_button = ttk.Button(right_frame, text="查看SQLMAP帮助", command=lambda: sqlmap_help())
sqlmap_help_button.pack(fill='x',pady=(10, 0))

help_button = ttk.Button(right_frame, text="查看工具帮助", command=lambda: help())
help_button.pack(fill='x',pady=(10, 0))

command_output = Text(right_frame, height=3, wrap='word', width=20)
command_output.insert("1.0","运行sqlmap时，将执行的sqlmap语句显示在这里")  
command_output.pack(fill='both', expand=True, pady=10)

run_button = ttk.Button(right_frame, text="开始运行", command=lambda: run_command())
run_button.pack(fill='x',side='bottom',pady=(0, 10))

def clear_default_text(event):
    if top_textbox.get("1.0", "end-1c") == default_text:
        top_textbox.delete("1.0", "end")

default_text = """

1、在此处输入 http 开头的URL时，执行-u命令，这可以让您直接扫描URL。例如：http://10.10.10.10/id=1?

2、在此处输入 burp 等工具抓取的数据包时，执行-r命令，这可以让您直接扫描请求包。例如：
-----------------------------------------
POST /vul/sqli/sqli_id.php HTTP/1.1
Host: host
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml

id=1&submit=%E6%9F%A5%E8%AF%A2
-----------------------------------------

3、如果您要执行 “批量扫描URL” 功能，必须清除此处所有内容，然后在工具的目录下，找到一个 “batch_url.txt” 文件，按照一行一条URL的规则放置您要批量扫描的目标。例如：
-------------------------
http://10.10.10.10/id=1?
http://20.20.20.20/id=1?
http://30.30.30.30/id=1?
-------------------------

4、如果您要执行 “批量扫描数据包” 功能，必须清除此处所有内容，然后在工具的目录下，找到一个 “batch” 文件夹，按照一个数据包一个txt文件的形式放入txt文件。

5、如果您对本工具使用有疑惑，可以点击右侧 “查看工具帮助” 获取更多信息。
"""
top_textbox = tk.Text(middle_frame, height=15, width=50)
top_textbox.insert("1.0", default_text)
top_textbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

top_textbox.bind("<FocusIn>", clear_default_text)

root.withdraw()
msgbox.showinfo("使用须知", """
本工具仅是一个图形化界面，主要为操作提供简单化，您可以将文件放置在任何sqlmap版本下,仅供您学习使用。
本工具允许您进行二次开发、或转发他人，但希望您能保留原作者信息，开源万岁~
欢迎关注微信公众号：樱花庄的本间白猫
作者博客：https://y.shironekosan.shop
作者：本间白猫
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

check_create_files()
root.mainloop()
