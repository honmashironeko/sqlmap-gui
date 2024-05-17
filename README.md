# 碎碎念

​ SQLmap作为测试SQL注入的强有力工具深受广大用户的青睐，但由于非国人制作，绝大多数均为英文版，对于使用体验会有较大影响。同时仅仅只有命令行模式，需要记下大量命令和重复输入命令，因此本工具应运而生。

# **工具介绍**

​ 通过人工汉化，并针对中文与英文的语法区别，进行了特殊的代码修改，从而实现汉化后语句通顺，减小误会的产生。编写好的GUI文件直接进入图形化模式，通过鼠标勾选参数就可以快速执行命令，同时通过脚本开发，目前支持批量并发扫描URL、批量扫描Burp等请求包，为大批量检测sql注入漏洞提供了便利。同时支持了Windows、Linux、Mac三大操作系统。

# 快速上手

​夸克网盘：https://pan.quark.cn/s/39b4b5674570#/list/share

Github：https://github.com/honmashironeko/sqlmap-gui/

百度网盘：https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5/

前往以上三个下载地址中任意一个地址获得本工具，并解压压缩包，您会获得 SQLMAP 本体及本工具主体。

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/28a74eae-6f93-46b0-8803-da96a8197dd7)


由于本工具涉及第三方库，所以请您在cmd中运行命令来安装第三方库：`pip install requests`

**Windows使用方法**

根据您的python环境决定用哪个程序，平时运行py文件是用 python XX.py，您双击 Windows双击启动图形化.bat 即可启动，python3 XX.py的话请您使用 Windows双击启动图形化-py3.bat。

**Mac、Linux使用方法**

双击 gui_mac.py 文件即可启动，或在命令行中运行 gui_mac.py。

**基本使用方法**

​ 左侧选择命令，中间填入burp抓取的数据包，点击开始运行即可！ 

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/9125f8ef-3a02-41a2-bdf9-ff1a7fa1884f)


本工具还提供了批量制作请求包的功能，在主界面点击 “制作批量数据包”，进入制作工作台后按照提示填写对应内容后生成数据包即可。返回主界面勾选 “批量扫描数据包”开始运行，检测到存在漏洞的站点会提取到ldopt文件夹中。

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/780bb409-c31d-4514-a69b-8a5ecb57ecd2)


# 使用帮助

​ 图形化界面分为三个部分，左侧部分为数据库相关操作模块，中间为数据包、URL填写模块，右侧为杂项模块。

**左侧模块内容介绍**

- 测试级别：可选择1-5级，等级越高，SQL语句测试内容越多。
- 风险级别：可选择1-3级，1级采用相对安全的语法，3级采用非常危险的语法。
- 线程数：可选择1-20线程，通常SQLmap限制最高20线程。
- 当前数据库：执行--current-db命令，查看当前正在使用哪一个库。
- 当前用户：执行--current-user命令，查看正在使用的用户是哪一个。
- 当前用户DBA权限：执行--is-dba命令，查看当前用户是否是DBA权限。
- 枚举库名：执行--dbs命令，枚举所有库名。
- 枚举表名：执行--tables命令，需要填入指定库名，枚举指定库名下的所有表名。（不填写指定内容会枚举所有）
- 枚举列名：执行--columns命令，需要填入指定库名、指定表名，枚举指定库名、指定表名下的所有列名。（不填写指定内容会枚举所有）
- 枚举字段：执行--dump命令，需要填入指定库名、指定表名、指定列名，枚举指定库名、指定表名、指定列名下的所有字段。（不填写指定内容会枚举所有）
- 一键脱库：执行--dump-all命令，获取所有库名、表名、列名、字段并保存到文件中。
- OS交互式Shell：执行--os-shell命令。
- SQL交互式Shell：执行--sql-shell命令。
- 指定库名：执行-D命令。
- 指定表名：执行-T命令。
- 指定列名：执行-C命令。
- 文本框：回显运行的SQLmap命令。

**右侧模块内容介绍**

- 设置代理：格式为([http://|https](http://%7Chttps)://|socks5://IP:PORT)
- 代理身份验证：格式为(用户名:密码)
- 一键去特征：执行--random-agent--tamper=between--flush-session--randomize=1 --skip-heuristics命令。
- 打开所有优化开关：执行-o命令。
- 默认应答：执行--batch命令，使用默认的选项。
- 清除缓存：执行--purge命令，删除之前的记录缓存。
- 强制SSL通信：执行--force-ssl命令，强制sqlmap使用https进行请求。
- 批量扫描URL：执行-m命令，一行一条的形式填写URL。
- 批量扫描数据包：使用前要在batch文件夹中放入txt文件，每一个txt文件对应一次扫描，循环执行-r命令，开启默认应答，启用大量cmd来运行，结束后自动打开sqlmap结果目录。(中间文本框留空)
- 注入方式：可选择指定注入方式或全部注入方式。
- 指定数据库类型：可选择指定数据库类型。
- 自定义参数：直接填写需要的额外参数，会自动添加在命令最后。
- 制作批量数据包：启动批量生成数据包工作台。
- 查看SQLMAP帮助：查看sqlmap -hh内容。
- 查看工具帮助：查看工具基础功能介绍。
- 检查版本：检测是否存在最新版。
- 开始运行：保存中间内容并执行SQLmap命令。

**中间模块内容介绍**

- 中部文本框：填写http开头执行-u命令，填写数据包执行-r命令，填写每行一个URL并勾选批量扫描URL执行-u命令并进行并发请求，默认同时5个sqlmap运行。

# 工具截图

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/402db063-9156-4a9a-a6ab-555c67c69164)

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/22451c07-30b7-4570-9943-2c05e12fc37d)

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/7a4f99ab-3588-4e09-9022-ca093fff4072)


# 最后一说

​ 如果您方便的话，辛苦您为作者主页的个人项目点个star~ 并关注一下公众号：**樱花庄的本间白猫**

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/08f33be3-8d2e-4859-9ddd-3b8623a1753f)


​ 如果出现bug或有建议，可以添加作者联系方式进行反馈！同时邀请进入交流群一起交流一下~

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/019fe14e-2a71-4a98-a7fa-c69688a17b35)


# 特别鸣谢

感谢以下师傅们为本项目的大力支持！（排名不分先后）

Re1axCyber（Mac系统优化）

幻影龙王

start

小黑

E0tk1

overflow0verture

Mine

陆沉

Union

# 更新日志

**2024年5月16日**

1、更改 批量扫描URL 功能逻辑，从 -m 按顺序扫描URL，修改为 -u 扫描，并同时进行并发执行，可实现5个sqlmap同时扫描，并在扫描完成后开启新的扫描进程，保证持续5个进程扫描。



2、更改工具更新思路，不再强制更换文件，采用检测更新并提醒存在新的更新的方式。



3、区分开python、python3、Windows和Mac、Linux的固定文件，不再统一到一个py文件中。

**2024年3月11日**

1、sqlmap汉化版本体修正一处描述。

  
2、gui.py文件修复多处错误。

**2024年3月11日**

1、添加自动更新功能。

  
2、修改批量制作数据包UI及操作逻辑。

  
3、修正几次帮助文本内容。

**2024年3月8日**

1、新添批量制作数据包功能。

  
2、修改批量扫描URL逻辑。

  
3、修改主界面UI设计。

  
4、修正帮助介绍。

**2024年3月7日**

1、修复一处BUG。

2、新增支持Linux系统（但存在部分功能无法调用）

  
3、新增支持Mac系统（该优化为 Re1axCyber 制作）

**2024年3月7日**

1、修复一处报错BUG。

  
2、新增文本框预先帮助，点击文本框自动清除。

  
3、启用版本命名，当前为V1.0版本。

**2024年3月7日**

1、修改工具帮助，在其弹窗后允许继续其他操作而无需强制关闭。

**2024年3月6日**

1、基于本项目汉化版制作成图形化界面，发布sqlmap-cn-gui版本。

**2024年1月29日**

1、首个汉化版发布，对大部分英文进行人工汉化。

# 简单打赏

本项目及其他项目并不要求大家付费，但是应部分师傅好意，因此留下打赏码，如果您觉得工具好用，欢迎大家打赏一下~（**此外接工具开发、众测渗透等项目混口饭吃**~）

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/50ffc1be-6c2a-45cc-8e19-4e8606e96f60)

![image](https://github.com/honmashironeko/sqlmap-gui/assets/139044047/ffa9661d-caaf-4840-b95d-3309d636fce9)
