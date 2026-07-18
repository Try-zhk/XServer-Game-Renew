#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import json
import sys
from urllib.parse import parse_qs, unquote, urlsplit


def b64decode(value):
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value).decode("utf-8", errors="replace")


def query_value(query, key, default=""):
    return query.get(key, [default])[0] or default


def bool_value(value):
    return str(value).lower() in ("1", "true", "yes", "on")


def split_host_port(value):
    value = value.strip().rstrip("/")

    if value.startswith("["):
        host, port = value.rsplit("]:", 1)
        return host[1:], int(port)

    host, port = value.rsplit(":", 1)
    return host, int(port)


def tag_from_url(parts, default):
    name = unquote(parts.fragment).strip()
    return name or default


def make_tls(query, server):
    security = query_value(query, "security").lower()

    if security not in ("tls", "reality"):
        return None

    insecure_param = query_value(query, "allowInsecure") or query_value(query, "insecure")
    tls = {
        "enabled": True,
        "server_name": query_value(query, "sni") or query_value(query, "host") or server,
        "insecure": bool_value(insecure_param) if insecure_param else True,
    }

    fingerprint = query_value(query, "fp")

    if fingerprint:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint,
        }

    alpn = query_value(query, "alpn")
    if alpn:
        tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]

    if security == "reality":
        public_key = query_value(query, "pbk")
        short_id = query_value(query, "sid")

        if not public_key:
            raise ValueError("Reality 节点缺少 pbk 参数")

        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": short_id,
        }

    return tls


def split_early_data(path, query=None):
    max_early_data = None

    if query is not None:
        ed_param = query_value(query, "ed")
        if ed_param:
            try:
                max_early_data = int(ed_param)
            except ValueError:
                max_early_data = None

    if "?ed=" in path:
        path, _, ed_value = path.partition("?ed=")
        if max_early_data is None:
            try:
                max_early_data = int(ed_value)
            except ValueError:
                pass

    return path or "/", max_early_data


def make_transport(network, query):
    network = (network or "tcp").lower()

    if network in ("", "tcp", "none"):
        return None

    path = unquote(query_value(query, "path", "/")) or "/"
    host = query_value(query, "host")

    if network == "ws":
        clean_path, max_early_data = split_early_data(path, query)
        transport = {
            "type": "ws",
            "path": clean_path,
        }
        if host:
            transport["headers"] = {"Host": host}
        if max_early_data:
            transport["max_early_data"] = max_early_data
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return transport

    if network == "grpc":
        service_name = (
            query_value(query, "serviceName")
            or query_value(query, "service_name")
            or query_value(query, "path").strip("/")
        )
        return {
            "type": "grpc",
            "service_name": service_name,
        }

    if network == "httpupgrade":
        transport = {
            "type": "httpupgrade",
            "path": path,
        }
        if host:
            transport["host"] = host
        return transport

    if network == "tcp" and query_value(query, "headerType") == "http":
        return {
            "type": "http",
            "path": path,
            "host": [host] if host else [],
        }

    return None


def parse_vless(link):
    parts = urlsplit(link)
    query = parse_qs(parts.query)

    if not parts.username or not parts.hostname or not parts.port:
        raise ValueError("VLESS 链接缺少 UUID、服务器或端口")

    outbound = {
        "type": "vless",
        "tag": tag_from_url(parts, "vless"),
        "server": parts.hostname,
        "server_port": parts.port,
        "uuid": unquote(parts.username),
        "flow": query_value(query, "flow"),
    }

    tls = make_tls(query, parts.hostname)
    if tls:
        outbound["tls"] = tls

    transport = make_transport(query_value(query, "type"), query)
    if transport:
        outbound["transport"] = transport

    return outbound


def parse_trojan(link):
    parts = urlsplit(link)
    query = parse_qs(parts.query)

    if not parts.username or not parts.hostname or not parts.port:
        raise ValueError("Trojan 链接缺少密码、服务器或端口")

    outbound = {
        "type": "trojan",
        "tag": tag_from_url(parts, "trojan"),
        "server": parts.hostname,
        "server_port": parts.port,
        "password": unquote(parts.username),
    }

    tls = make_tls(query, parts.hostname)
    if not tls:
        insecure_param = query_value(query, "allowInsecure") or query_value(query, "insecure")
        tls = {
            "enabled": True,
            "server_name": query_value(query, "sni") or parts.hostname,
            "insecure": bool_value(insecure_param) if insecure_param else True,
        }

    outbound["tls"] = tls

    transport = make_transport(query_value(query, "type"), query)
    if transport:
        outbound["transport"] = transport

    return outbound


def parse_anytls(link):
    parts = urlsplit(link)
    query = parse_qs(parts.query)

    if not parts.hostname or not parts.port:
        raise ValueError("AnyTLS 链接缺少服务器或端口")

    outbound = {
        "type": "anytls",
        "tag": tag_from_url(parts, "anytls"),
        "server": parts.hostname,
        "server_port": parts.port,
        "password": unquote(parts.username or ""),
    }

    tls = make_tls(query, parts.hostname)
    if not tls:
        insecure_param = query_value(query, "allowInsecure") or query_value(query, "insecure")
        tls = {
            "enabled": True,
            "server_name": query_value(query, "sni") or parts.hostname,
            "insecure": bool_value(insecure_param) if insecure_param else True,
        }

    outbound["tls"] = tls

    return outbound


def parse_ss(link):
    raw = link[len("ss://"):]
    raw, _, fragment = raw.partition("#")
    tag = unquote(fragment) or "shadowsocks"

    if "?" in raw:
        raw = raw.split("?", 1)[0]

    if "@" not in raw:
        raw = b64decode(raw)

    if "@" not in raw:
        raise ValueError("Shadowsocks 链接格式无效")

    userinfo, address = raw.rsplit("@", 1)

    try:
        decoded = b64decode(userinfo)
        if ":" in decoded:
            userinfo = decoded
    except Exception:
        pass

    if ":" not in userinfo:
        raise ValueError("Shadowsocks 链接缺少加密方式或密码")

    method, password = userinfo.split(":", 1)
    server, port = split_host_port(address)

    return {
        "type": "shadowsocks",
        "tag": tag,
        "server": server,
        "server_port": port,
        "method": unquote(method),
        "password": unquote(password),
    }


def parse_vmess(link):
    raw = link[len("vmess://"):]
    data = json.loads(b64decode(raw))

    host = data.get("add")
    uuid = data.get("id")

    if not host or not uuid:
        raise ValueError("VMess 链接缺少服务器或 UUID")

    try:
        port = int(data.get("port", 443))
    except (TypeError, ValueError):
        raise ValueError("VMess 端口无效")

    outbound = {
        "type": "vmess",
        "tag": data.get("ps") or "vmess",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": data.get("scy") or "auto",
        "alter_id": int(data.get("aid") or 0),
    }

    tls_mode = str(data.get("tls") or "").lower()
    if tls_mode in ("tls", "reality"):
        tls = {
            "enabled": True,
            "server_name": data.get("sni") or data.get("host") or host,
            "insecure": True,
        }

        if data.get("fp"):
            tls["utls"] = {
                "enabled": True,
                "fingerprint": data["fp"],
            }

        if tls_mode == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": data.get("pbk", ""),
                "short_id": data.get("sid", ""),
            }

        outbound["tls"] = tls

    network = data.get("net") or "tcp"
    path = data.get("path") or "/"
    host_header = data.get("host") or ""

    if network == "ws":
        clean_path, max_early_data = split_early_data(path)
        transport = {
            "type": "ws",
            "path": clean_path,
        }
        if host_header:
            transport["headers"] = {"Host": host_header}
        if max_early_data:
            transport["max_early_data"] = max_early_data
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        outbound["transport"] = transport

    if network == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": path,
        }

    return outbound


def parse_hysteria2(link):
    parts = urlsplit(link)
    query = parse_qs(parts.query)

    if not parts.hostname or not parts.port:
        raise ValueError("Hysteria2 链接缺少服务器或端口")

    if parts.password:
        password = unquote(parts.username or "") + ":" + unquote(parts.password)
    else:
        password = unquote(parts.username or "")

    insecure_param = query_value(query, "insecure") or query_value(query, "allowInsecure")
    outbound = {
        "type": "hysteria2",
        "tag": tag_from_url(parts, "hysteria2"),
        "server": parts.hostname,
        "server_port": parts.port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": query_value(query, "sni") or parts.hostname,
            "insecure": bool_value(insecure_param) if insecure_param else True,
        },
    }

    obfs = query_value(query, "obfs")
    obfs_password = query_value(query, "obfs-password") or query_value(query, "obfs_password")

    if obfs == "salamander" and obfs_password:
        outbound["obfs"] = {
            "type": "salamander",
            "password": obfs_password,
        }

    return outbound


def parse_tuic(link):
    parts = urlsplit(link)
    query = parse_qs(parts.query)

    if not parts.username or not parts.hostname or not parts.port:
        raise ValueError("TUIC 链接缺少 UUID、服务器或端口")

    outbound = {
        "type": "tuic",
        "tag": tag_from_url(parts, "tuic"),
        "server": parts.hostname,
        "server_port": parts.port,
        "uuid": unquote(parts.username),
        "password": unquote(parts.password or ""),
        "congestion_control": query_value(query, "congestion_control", "bbr"),
        "tls": {
            "enabled": True,
            "server_name": query_value(query, "sni") or parts.hostname,
            "insecure": bool_value(query_value(query, "allowInsecure"))
            if query_value(query, "allowInsecure")
            else True,
        },
    }

    alpn = query_value(query, "alpn")
    if alpn:
        outbound["tls"]["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]

    return outbound


def parse_socks_or_http(link):
    parts = urlsplit(link)

    if not parts.hostname or not parts.port:
        raise ValueError("代理链接缺少服务器或端口")

    scheme = parts.scheme.lower()
    is_socks = scheme in ("socks", "socks4", "socks4a", "socks5")

    outbound = {
        "type": "socks" if is_socks else "http",
        "tag": tag_from_url(parts, scheme),
        "server": parts.hostname,
        "server_port": parts.port,
    }

    if parts.username:
        outbound["username"] = unquote(parts.username)

    if parts.password:
        outbound["password"] = unquote(parts.password)

    if scheme == "socks4":
        outbound["version"] = "4"

    if scheme == "socks4a":
        outbound["version"] = "4a"

    if scheme == "https":
        outbound["tls"] = {
            "enabled": True,
            "server_name": parts.hostname,
            "insecure": False,
        }

    return outbound


def parse_link(link):
    link = link.strip()

    if link.startswith("vless://"):
        return parse_vless(link)

    if link.startswith("vmess://"):
        return parse_vmess(link)

    if link.startswith("trojan://"):
        return parse_trojan(link)

    if link.startswith("anytls://"):
        return parse_anytls(link)

    if link.startswith("ss://"):
        return parse_ss(link)

    if link.startswith("hysteria2://") or link.startswith("hy2://"):
        return parse_hysteria2(link)

    if link.startswith("tuic://"):
        return parse_tuic(link)

    if link.startswith(("socks://", "socks4://", "socks4a://", "socks5://", "http://", "https://")):
        return parse_socks_or_http(link)

    raise ValueError("不支持的链接类型")


def generate_config(link, output_path, port):
    outbound = parse_link(link)

    config = {
        "log": {
            "level": "warn",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        ],
        "outbounds": [
            outbound,
            {
                "type": "direct",
                "tag": "direct",
            },
            {
                "type": "block",
                "tag": "block",
            },
        ],
        "route": {
            "final": outbound["tag"],
        },
    }

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(config, file, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="将单条代理链接转换为 sing-box 检测配置"
    )
    parser.add_argument("link", help="一条代理分享链接")
    parser.add_argument("-o", "--output", default="config.json", help="输出配置文件")
    parser.add_argument(
        "--port",
        "--mixed-port",
        dest="port",
        type=int,
        default=2080,
        help="本地 SOCKS/HTTP 代理端口",
    )
    args = parser.parse_args()

    try:
        generate_config(args.link, args.output, args.port)
        print("配置已生成：" + args.output)
    except Exception as error:
        print("配置生成失败：" + str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
