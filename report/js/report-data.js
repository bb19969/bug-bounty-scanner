window.reportData = {
  domain: "example.com",
  toolVersions: `amass: v3.15.1
subfinder: v2.5.0
assetfinder: v0.1.1
findomain: v8.2.1
dnsx: v1.1.3
httpx: v1.2.7
waybackurls: v0.1.0
gau: v2.2.5
nuclei: v3.1.1
dalfox: v2.7.0
kxss: v1.0.5`,
  stats: {
    subdomains: 42,
    alive: 19,
    aliveWeb: 12,
    urls: 247,
    newSubs: 2
  },
  newSubdomains: `blog.example.com
api-2.example.com`,
  endpoints: `https://api.example.com/v1/user?id=123
https://shop.example.com/product?item=456
https://blog.example.com/wp-login.php
https://cdn.example.com/assets/main.js
https://store.example.com/cart?item=789
...`,
  parameters: `id
item
utm_source
utm_medium
ref
token
search
filter`,
  vulnerabilities: {
    nuclei: `[critical] CVE-2024-XXXX detected on https://shop.example.com
[medium] X-Frame-Options header missing on https://blog.example.com
[low] Server banner exposed on https://cdn.example.com
...`,
    dalfox: `[POC] Reflected XSS detected at https://api.example.com/v1/user?id=foo%3Cscript%3Ealert(1)%3C/script%3E
[INFO] No stored XSS found on https://shop.example.com/product
...`,
    kxss: `https://blog.example.com/search?q="onmouseover=alert(1)" reflected in response
...`
  },
  screenshots: [
    {file: "aquatone/screenshots/api.example.com.png", label: "api.example.com.png"},
    {file: "aquatone/screenshots/blog.example.com.png", label: "blog.example.com.png"},
    {file: "aquatone/screenshots/cdn.example.com.png", label: "cdn.example.com.png"}
  ]
};
