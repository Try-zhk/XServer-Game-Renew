#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
将常见代理分享链接（vless / vmess / trojan / ss / hysteria2 / tuic）
转换为 sing-box 配置文件，在本地 127.0.0.1:8080 提供 mixed(http+socks) 入口。
用法: python3 gen_singbox_config.py "<代理链接>" > singbox.json
"""

import sys
import json
import base64
import urllib.parse as up


def b64_decode(s: str) -> str:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")


def parse_query(qs: str) -> dict:
    return {k: v[0] for k, v in up.parse_qs(qs).items()}


def build_tls(q: dict, sni_default: str = "", force_tls: bool = False):
    security = q.get("security", "tls" if force_tls else "")
    if security not in ("tls", "reality"):
        return None
    tls = {
        "enabled": True,
        "server_name": q.get("sni") or q.get("host") or sni_default,
        "insecure": q.get("allowInsecure", "0") in ("1", "true"),
    }
    alpn = q.get("alpn")
    if alpn:
        tls["alpn"] = alpn.split(",")
    fp = q.get("fp")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": q.get("pbk", ""),
            "short_id": q.get("sid", ""),
        }
    return tls


def build_transport(q: dict):
    net = q.get("type", "tcp")
    if net == "ws":
        headers = {"Host": q["host"]} if q.get("host") else {}
        return {"type": "ws", "path": q.get("path", "/"), "headers": headers}
    if net == "grpc":
        return {"type": "grpc", "service_name": q.get("serviceName", q.get("path", ""))}
    if net in ("http", "h2"):
        host = [q["host"]] if q.get("host") else []
        return {"type": "http", "host": host, "path": q.get("path", "/")}
    return None


def parse_vless(link: str) -> dict:
    body = link[len("vless://"):]
    uuid_, rest = body.split("@", 1)
    hostport_query, _, _frag = rest.partition("#")
    hostport, _, query = hostport_query.partition("?")
    host, port = hostport.rsplit(":", 1)
    q = parse_query(query)
    out = {
        "type": "vless",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "uuid": uuid_,
        "flow": q.get("flow", ""),
        "packet_encoding": "xudp",
    }
    tls = build_tls(q, sni_default=host)
    if tls:
        out["tls"] = tls
    transport = build_transport(q)
    if transport:
        out["transport"] = transport
    return out


def parse_trojan(link: str) -> dict:
    body = link[len("trojan://"):]
    password, rest = body.split("@", 1)
    hostport_query, _, _frag = rest.partition("#")
    hostport, _, query = hostport_query.partition("?")
    host, port = hostport.rsplit(":", 1)
    q = parse_query(query)
    out = {
        "type": "trojan",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "password": up.unquote(password),
    }
    tls = build_tls(q, sni_default=host, force_tls=True)
    out["tls"] = tls if tls else {"enabled": True, "server_name": host}
    transport = build_transport(q)
    if transport:
        out["transport"] = transport
    return out


def parse_vmess(link: str) -> dict:
    data = json.loads(b64_decode(link[len("vmess://"):]))
    out = {
        "type": "vmess",
        "tag": "proxy",
        "server": data.get("add"),
        "server_port": int(data.get("port")),
        "uuid": data.get("id"),
        "security": data.get("scy", "auto"),
        "alter_id": int(data.get("aid", 0) or 0),
    }
    net = data.get("net", "tcp")
    if net == "ws":
        headers = {"Host": data["host"]} if data.get("host") else {}
        out["transport"] = {"type": "ws", "path": data.get("path", "/"), "headers": headers}
    elif net == "grpc":
        out["transport"] = {"type": "grpc", "service_name": data.get("path", "")}
    if data.get("tls", "") in ("tls", "reality"):
        out["tls"] = {
            "enabled": True,
            "server_name": data.get("sni") or data.get("host") or data.get("add"),
            "insecure": False,
        }
    return out


def parse_ss(link: str) -> dict:
    body = link[len("ss://"):]
    hostpart, _, _frag = body.partition("#")
    if "@" in hostpart:
        userinfo, hostport = hostpart.split("@", 1)
        userinfo = up.unquote(userinfo)
        try:
            userinfo = b64_decode(userinfo) if ":" not in userinfo else userinfo
        except Exception:
            pass
        method, password = userinfo.split(":", 1)
    else:
        decoded = b64_decode(hostpart)
        method_password, hostport = decoded.split("@", 1)
        method, password = method_password.split(":", 1)
    hostport = hostport.split("/")[0].split("?")[0]
    host, port = hostport.rsplit(":", 1)
    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "method": method,
        "password": password,
    }


def parse_hysteria2(link: str) -> dict:
    body = link.split("://", 1)[1]
    password, rest = body.split("@", 1)
    hostport_query, _, _frag = rest.partition("#")
    hostport, _, query = hostport_query.partition("?")
    host, port = hostport.rsplit(":", 1)
    q = parse_query(query)
    return {
        "type": "hysteria2",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "password": up.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", host),
            "insecure": q.get("insecure", "0") in ("1", "true"),
        },
    }


def parse_tuic(link: str) -> dict:
    body = link[len("tuic://"):]
    userinfo, rest = body.split("@", 1)
    hostport_query, _, _frag = rest.partition("#")
    hostport, _, query = hostport_query.partition("?")
    host, port = hostport.rsplit(":", 1)
    q = parse_query(query)
    if ":" in userinfo:
        uuid_, password = userinfo.split(":", 1)
    else:
        uuid_, password = userinfo, ""
    return {
        "type": "tuic",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "uuid": uuid_,
        "password": up.unquote(password),
        "congestion_control": q.get("congestion_control", "bbr"),
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", host),
            "insecure": q.get("allow_insecure", "0") in ("1", "true"),
            "alpn": q.get("alpn", "h3").split(","),
        },
    }


def parse_socks(link: str) -> dict:
    # 支持两种常见写法：
    #   socks5://user:pass@host:port#name
    #   socks5://base64(user:pass)@host:port#name（无用户名密码时可省略 base64 部分）
    body = link.split("://", 1)[1]
    hostpart, _, _frag = body.partition("#")
    hostpart, _, query = hostpart.partition("?")

    username, password = "", ""
    if "@" in hostpart:
        userinfo, hostport = hostpart.rsplit("@", 1)
        userinfo = up.unquote(userinfo)
        if ":" not in userinfo:
            try:
                userinfo = b64_decode(userinfo)
            except Exception:
                pass
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo
    else:
        hostport = hostpart

    hostport = hostport.split("/")[0]
    host, port = hostport.rsplit(":", 1)
    out = {
        "type": "socks",
        "tag": "proxy",
        "server": host,
        "server_port": int(port),
        "version": "5",
    }
    if username:
        out["username"] = username
    if password:
        out["password"] = password
    return out


PARSERS = {
    "vless://": parse_vless,
    "trojan://": parse_trojan,
    "vmess://": parse_vmess,
    "ss://": parse_ss,
    "hysteria2://": parse_hysteria2,
    "hy2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "socks5://": parse_socks,
    "socks://": parse_socks,
}


def main():
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print("用法: gen_singbox_config.py <代理链接>", file=sys.stderr)
        sys.exit(1)

    link = sys.argv[1].strip()
    outbound = None
    for prefix, fn in PARSERS.items():
        if link.startswith(prefix):
            outbound = fn(link)
            break

    if outbound is None:
        print(f"❌ 不支持的协议前缀: {link.split('://')[0]}://", file=sys.stderr)
        sys.exit(1)

    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 8080,
            }
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy"},
    }
    print(json.dumps(config, ensure_ascii=False))


if __name__ == "__main__":
    main()
