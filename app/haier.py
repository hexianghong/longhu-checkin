"""海尔智家 API 客户端与凭据解析。

支持两种接入方式：
1. 手机号 + 密码登录（App 网关签名，直拿 accountToken + refreshToken，支持自动续期）
2. 抓包导入（支持上传 HAR、粘贴 cURL、直接填 accountToken / refreshToken）

核心接口（Host: https://zj.haier.net）：
- 密码登录：POST /api-gw/oauthserver/account/v1/login
- 刷新令牌：POST /api-gw/oauthserver/account/v1/refreshToken
- 每日签到：POST /api-gw/zjBaseServer/daily/sign
- 小程序资料：POST /api-gw/oauthserver/applet/v1/userinfo/query
- 账号资料：GET  https://account-api.haier.net/v2/haier/userinfo
"""

import hashlib
import json
import random
import re
import string
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

BASE = "https://zj.haier.net"
USER_INFO_API = "https://account-api.haier.net/v2/haier/userinfo"

APP_SOURCE_WXAPP = "wxapp"
APP_SOURCE_APP = "app"

APP_SOURCES = {
    # 海尔智家微信小程序（wxe24b2f1f4e378891）
    APP_SOURCE_WXAPP: ("MB-SHEZJAPPWXXCX-0000", "79ce99cc7f9804663939676031b8a427"),
    # 海尔智家 App
    APP_SOURCE_APP: ("MB-UZHSH-0001", "5dfca8714eb26e3a776e58a8273c8752"),
}

MINI_APP_ID = "wxe24b2f1f4e378891"
PAGE_VERSION = "475"

EP_LOGIN = "/api-gw/oauthserver/account/v1/login"
EP_REFRESH = "/api-gw/oauthserver/account/v1/refreshToken"
EP_SIGN = "/api-gw/zjBaseServer/daily/sign"
EP_APPLET_USERINFO = "/api-gw/oauthserver/applet/v1/userinfo/query"

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 "
    "MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Mac "
    "MacWechat/WMPF"
)

DEFAULT_EXPIRE_SECONDS = 30 * 86400


class HaierError(Exception):
    """海尔智家业务可读异常"""


def random_client_id() -> str:
    """生成形如 13位毫秒时间戳 + 12位随机字母数字 的 clientId。"""
    ts = str(int(time.time() * 1000))
    alphabet = string.ascii_letters + string.digits
    suffix = "".join(random.choice(alphabet) for _ in range(12))
    return f"{ts}{suffix}"


def sign_sha256(path: str, body_text: str, app_id: str, app_key: str, timestamp: str) -> str:
    """海尔网关通用签名：sha256(path + 紧凑body + appId + appKey + timestamp)"""
    compact = (
        (body_text or "")
        .replace("\t", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace(" ", "")
    )
    raw = f"{path}{compact}{app_id}{app_key}{timestamp}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_headers(
    path: str,
    body_text: str,
    token: str = "",
    client_id: str = "",
    app_source: str = APP_SOURCE_WXAPP,
    user_agent: str = "",
) -> dict:
    app_id, app_key = APP_SOURCES.get(app_source, APP_SOURCES[APP_SOURCE_WXAPP])
    ts = str(int(time.time() * 1000))
    seq_id = time.strftime("%Y%m%d%H%M%S") + str(random.randint(100000, 999999))
    cid = (client_id or "").strip() or random_client_id()
    sig = sign_sha256(path, body_text, app_id, app_key, ts)

    headers = {
        "Host": "zj.haier.net",
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "*/*",
        "appId": app_id,
        "appKey": app_key,
        "timestamp": ts,
        "sequenceId": seq_id,
        "sign": sig,
        "clientId": cid,
        "platForm": "sc-mp-wx-zjapp" if app_source == APP_SOURCE_WXAPP else "app",
        "ENV": "",
        "timezone": "+8",
        "language": "zh-CN",
        "User-Agent": (user_agent or "").strip() or DEFAULT_UA,
        "Referer": f"https://servicewechat.com/{MINI_APP_ID}/{PAGE_VERSION}/page-frame.html",
    }
    if token:
        headers["accessToken"] = token
        headers["accountToken"] = token
        headers["ak"] = token
    return headers


def _request(
    method: str,
    url: str,
    headers: dict,
    body: dict | None = None,
    timeout: int = 20,
) -> dict:
    session = requests.Session()
    session.trust_env = False  # 忽略系统代理，避免被本机抓包代理拦截
    body_text = json.dumps(body, separators=(",", ":"), ensure_ascii=False) if body is not None else ""
    try:
        if method.upper() == "GET":
            resp = session.get(url, headers=headers, timeout=timeout)
        else:
            resp = session.post(url, headers=headers, data=body_text.encode("utf-8"), timeout=timeout)
    except requests.RequestException as exc:
        raise HaierError(f"网络请求失败: {exc}") from exc
    finally:
        session.close()

    text = resp.text or ""
    try:
        return json.loads(text)
    except Exception:
        return {"retCode": f"HTTP_{resp.status_code}", "retInfo": text[:200]}


def expire_at(seconds: int | None = None) -> str:
    sec = int(seconds) if seconds and int(seconds) > 0 else DEFAULT_EXPIRE_SECONDS
    return (datetime.now(timezone.utc) + timedelta(seconds=sec)).isoformat()


def mask_phone(phone: str) -> str:
    clean = re.sub(r"\D", "", str(phone or ""))
    if len(clean) == 11:
        return f"{clean[:3]}****{clean[-4:]}"
    return phone or ""


# --------------------------------------------------------------------------
# 登录 / 续期 / 资料 / 签到
# --------------------------------------------------------------------------

def phone_login(phone: str, password: str) -> dict:
    """用手机号 + 密码登录海尔智家，返回 token / refresh_token / expires_in / client_id。"""
    number = re.sub(r"\D", "", phone or "")
    if len(number) != 11 or not number.startswith("1"):
        raise HaierError("请输入 11 位手机号")
    pwd = (password or "").strip()
    if not pwd:
        raise HaierError("请输入登录密码")

    payload = {"username": number, "password": pwd}
    body_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    headers = _build_headers(
        EP_LOGIN,
        body_text,
        token="",
        client_id=number,
        app_source=APP_SOURCE_APP,
    )
    res = _request("POST", f"{BASE}{EP_LOGIN}", headers, payload)
    ret_code = str(res.get("retCode") or "")
    if ret_code != "00000":
        msg = res.get("retInfo") or res.get("message") or f"登录失败 (retCode={ret_code})"
        raise HaierError(msg)

    data = res.get("data") if isinstance(res.get("data"), dict) else {}
    token_info = data.get("tokenInfo") if isinstance(data.get("tokenInfo"), dict) else data
    account_token = str(token_info.get("accountToken") or "").strip()
    refresh_tok = str(token_info.get("refreshToken") or "").strip()
    try:
        expires_in = int(token_info.get("expiresIn") or DEFAULT_EXPIRE_SECONDS)
    except (TypeError, ValueError):
        expires_in = DEFAULT_EXPIRE_SECONDS
    if not account_token:
        raise HaierError("登录未返回 accountToken，请检查账号是否已注册海尔智家")

    return {
        "token": account_token,
        "refresh_token": refresh_tok,
        "expires_in": expires_in,
        "client_id": number,
        "app_source": APP_SOURCE_APP,
    }


def _refresh_once(refresh_tok: str, client_id: str, app_source: str, user_agent: str = "") -> dict:
    payload = {"refreshToken": refresh_tok}
    body_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    headers = _build_headers(
        EP_REFRESH,
        body_text,
        token="",
        client_id=client_id,
        app_source=app_source,
        user_agent=user_agent,
    )
    return _request("POST", f"{BASE}{EP_REFRESH}", headers, payload)


def refresh_token(account: dict) -> tuple[bool, dict | str]:
    """刷新海尔智家 token。

    - 若配置了 refresh_token：调 refreshToken 接口换取最新 accountToken + refreshToken。
      如果当前 app_source 返回 43005（来源不匹配），自动尝试另一种 app_source。
    - 若未配置 refresh_token（如仅抓包粘贴了小程序 accountToken）：
      通过资料接口校验当前 token 是否仍然有效，有效则视为正常，不报错。
    """
    refresh_tok = (account.get("refresh_token") or "").strip()
    token = (account.get("token") or "").strip()
    client_id = (account.get("client_id") or "").strip() or random_client_id()
    primary_source = (account.get("app_source") or APP_SOURCE_WXAPP).strip()
    if primary_source not in APP_SOURCES:
        primary_source = APP_SOURCE_WXAPP
    ua = account.get("user_agent") or DEFAULT_UA

    if refresh_tok:
        sources = [primary_source, APP_SOURCE_APP if primary_source == APP_SOURCE_WXAPP else APP_SOURCE_WXAPP]
        last_err = ""
        for src in sources:
            try:
                res = _refresh_once(refresh_tok, client_id, src, ua)
            except HaierError as exc:
                last_err = str(exc)
                continue
            ret_code = str(res.get("retCode") or "")
            if ret_code == "00000":
                data = res.get("data") if isinstance(res.get("data"), dict) else {}
                tinfo = data.get("tokenInfo") if isinstance(data.get("tokenInfo"), dict) else data
                new_token = str(tinfo.get("accountToken") or "").strip()
                new_refresh = str(tinfo.get("refreshToken") or refresh_tok).strip()
                try:
                    expires_in = int(tinfo.get("expiresIn") or DEFAULT_EXPIRE_SECONDS)
                except (TypeError, ValueError):
                    expires_in = DEFAULT_EXPIRE_SECONDS
                if new_token:
                    return True, {
                        "token": new_token,
                        "refresh_token": new_refresh,
                        "expires_in": expires_in,
                        "app_source": src,
                        "client_id": client_id,
                        "message": "token 已通过 refreshToken 自动续期",
                    }
            last_err = res.get("retInfo") or res.get("message") or f"retCode={ret_code}"
            # 非 43005（客户端来源不匹配）无需切 source 重试
            if ret_code != "43005":
                break
        return False, f"refreshToken 续期失败：{last_err or '未知原因'}"

    if not token:
        return False, "缺少 token"

    # 没有 refresh_token 时，验证现有 accountToken 是否可用
    try:
        profile = fetch_profile(account)
        return True, {
            "token": token,
            "refresh_token": "",
            "expires_in": None,
            "app_source": primary_source,
            "client_id": client_id,
            "profile": profile,
            "message": "accountToken 校验有效（未配置 refreshToken）",
        }
    except HaierError as exc:
        return False, str(exc)


def fetch_profile(account: dict) -> dict:
    """查询海尔智家账号资料（手机号、用户名/昵称、userId）。"""
    token = (account.get("token") or "").strip()
    if not token:
        raise HaierError("缺少 accountToken")

    # 1. 优先查官方 OAuth userinfo 接口
    session = requests.Session()
    session.trust_env = False
    try:
        resp = session.get(
            USER_INFO_API,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": account.get("user_agent") or DEFAULT_UA,
            },
            timeout=15,
        )
        data = resp.json() if resp.text else {}
    except Exception:
        data = {}
    finally:
        session.close()

    if isinstance(data, dict) and (data.get("userId") or data.get("mobile")):
        mobile = str(data.get("mobile") or "")
        username = str(data.get("username") or data.get("nickName") or "")
        return {
            "user_id": str(data.get("userId") or ""),
            "phone": mask_phone(mobile) or mobile,
            "nickname": username or mask_phone(mobile),
        }

    # 2. 兜底查小程序 userinfo/query 接口
    client_id = (account.get("client_id") or "").strip() or random_client_id()
    body_text = "{}"
    headers = _build_headers(
        EP_APPLET_USERINFO,
        body_text,
        token=token,
        client_id=client_id,
        app_source=APP_SOURCE_WXAPP,
        user_agent=account.get("user_agent") or DEFAULT_UA,
    )
    res = _request("POST", f"{BASE}{EP_APPLET_USERINFO}", headers, {})
    if str(res.get("retCode") or "") == "00000":
        udata = res.get("data") if isinstance(res.get("data"), dict) else {}
        mobile = str(udata.get("mobile") or udata.get("phone") or "")
        nick = str(udata.get("nickName") or udata.get("userName") or udata.get("username") or "")
        return {
            "user_id": str(udata.get("userId") or udata.get("id") or ""),
            "phone": mask_phone(mobile) or mobile,
            "nickname": nick or mask_phone(mobile),
        }

    err = (
        (data.get("error_description") if isinstance(data, dict) else "")
        or res.get("retInfo")
        or "accountToken 无效或已过期"
    )
    raise HaierError(str(err))


def checkin(account: dict) -> tuple[str, str, int | None]:
    """执行海尔智家小程序每日签到。

    返回 (status, message, total_sign_days)
    status: ok / already / fail
    """
    token = (account.get("token") or "").strip()
    if not token:
        return "fail", "【海尔】缺少 accountToken", None

    client_id = (account.get("client_id") or "").strip() or random_client_id()
    body_text = "{}"
    headers = _build_headers(
        EP_SIGN,
        body_text,
        token=token,
        client_id=client_id,
        app_source=APP_SOURCE_WXAPP,
        user_agent=account.get("user_agent") or DEFAULT_UA,
    )
    try:
        res = _request("POST", f"{BASE}{EP_SIGN}", headers, {})
    except HaierError as exc:
        return "fail", f"【海尔】签到请求失败：{exc}", None

    ret_code = str(res.get("retCode") or "")
    data = res.get("data") if isinstance(res.get("data"), dict) else {}
    msg = str(res.get("retInfo") or res.get("message") or res.get("msg") or "").strip()

    total_days = data.get("totalSignDay")
    if total_days is None:
        total_days = data.get("continueSignDay") or data.get("signDay")
    try:
        total_days = int(total_days) if total_days is not None else None
    except (TypeError, ValueError):
        total_days = None

    reward_point = data.get("point") or data.get("signPoint") or data.get("rewardPoint") or data.get("score")

    if ret_code == "00000" or res.get("code") == 200 or res.get("success") is True:
        parts = ["【海尔】签到成功"]
        if total_days is not None:
            parts.append(f"已连续签到 {total_days} 天")
        if reward_point:
            parts.append(f"+{reward_point} 积分")
        return "ok", "，".join(parts), total_days

    if re.search(r"已签|签到过|重复|已完成", msg):
        suffix = f"，已连续签到 {total_days} 天" if total_days is not None else f"（{msg}）"
        return "already", f"【海尔】今日已签到{suffix}", total_days

    if re.search(r"用户信息获取失败|token|登录|未授权|失效|过期|未登录|鉴权", msg, re.I):
        return "fail", f"【海尔】鉴权失效：{msg or 'accountToken 已过期，请更新凭据或配置 refreshToken'}", None

    return "fail", f"【海尔】签到失败：{msg or '未知错误'}（retCode={ret_code or '无'}）", None


# --------------------------------------------------------------------------
# 抓包解析：支持 HAR / cURL / 直接填 token 或 refreshToken
# --------------------------------------------------------------------------

def _extract_token_from_headers(headers: dict) -> str:
    for key in ("accounttoken", "accesstoken", "ak", "authorization"):
        val = (headers.get(key) or "").strip()
        if not val or val.lower() in ("undefined", "null"):
            continue
        if val.lower().startswith("bearer "):
            val = val[7:].strip()
        if len(val) >= 12:
            return val
    return ""


def _detect_app_source(headers: dict) -> str:
    app_id = (headers.get("appid") or "").strip()
    if app_id == APP_SOURCES[APP_SOURCE_APP][0]:
        return APP_SOURCE_APP
    return APP_SOURCE_WXAPP


def parse_curl(text: str) -> dict:
    if "curl" not in (text or "").lower():
        raise HaierError("粘贴的内容中没有找到 curl 命令")

    flat = text.replace("\\\n", " ").replace("\\\r\n", " ").replace("^\n", " ")
    headers = {}
    pattern = re.compile(r"(?:-H|--header)[\s=]+(['\"])(.*?)\1", re.S)
    for match in pattern.finditer(flat):
        raw = match.group(2)
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    body_str = ""
    body_match = re.search(r"(?:--data-raw|--data|-d)[\s=]+(['\"])(.*?)\1", flat, re.S)
    if body_match:
        body_str = body_match.group(2)

    refresh_tok = ""
    if body_str:
        try:
            bjson = json.loads(body_str)
            if isinstance(bjson, dict):
                refresh_tok = str(bjson.get("refreshToken") or "").strip()
        except Exception:
            pass

    token = _extract_token_from_headers(headers)
    if not token and not refresh_tok:
        raise HaierError("cURL 中未找到 accountToken / accessToken 或 refreshToken")

    return {
        "token": token,
        "refresh_token": refresh_tok,
        "client_id": (headers.get("clientid") or "").strip() or random_client_id(),
        "app_source": _detect_app_source(headers),
        "user_agent": headers.get("user-agent") or DEFAULT_UA,
        "note": "从 cURL 解析海尔智家凭据",
    }


def parse_har(raw: str | bytes) -> dict:
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        data = json.loads(raw)
    except Exception as exc:
        raise HaierError(f"HAR 文件不是合法的 JSON：{exc}") from exc

    entries = (data.get("log") or {}).get("entries") or []
    if not entries:
        raise HaierError("HAR 文件中没有任何请求记录")

    best_token = ""
    best_refresh = ""
    best_client_id = ""
    best_source = APP_SOURCE_WXAPP
    best_ua = ""
    best_score = -1
    saw_connect_haier = False

    for entry in entries:
        req = entry.get("request") or {}
        res = entry.get("response") or {}
        method = (req.get("method") or "").upper()
        url = req.get("url") or ""

        if "haier.net" not in url and "ehaier.com" not in url:
            continue

        if method == "CONNECT" or entry.get("_isIntercepted") is False:
            saw_connect_haier = True
            continue

        headers = {}
        for h in (req.get("headers") or []):
            name = (h.get("name") or "").lower()
            if name:
                headers[name] = h.get("value") or ""

        token = _extract_token_from_headers(headers)
        refresh_tok = ""

        # 检查请求体和响应体是否带 tokenInfo / refreshToken
        post_text = ((req.get("postData") or {}).get("text")) or ""
        if post_text:
            try:
                pjson = json.loads(post_text)
                if isinstance(pjson, dict):
                    refresh_tok = str(pjson.get("refreshToken") or "").strip()
            except Exception:
                pass

        res_text = ((res.get("content") or {}).get("text")) or ""
        if res_text:
            try:
                rjson = json.loads(res_text)
                if isinstance(rjson, dict):
                    tinfo = (rjson.get("data") or {}).get("tokenInfo") or rjson.get("data") or {}
                    if isinstance(tinfo, dict):
                        token = str(tinfo.get("accountToken") or token).strip()
                        refresh_tok = str(tinfo.get("refreshToken") or refresh_tok).strip()
            except Exception:
                pass

        if not token and not refresh_tok:
            continue

        path = urlparse(url).path
        score = 10
        if "daily/sign" in path:
            score = 100
        elif "jscode2session" in path or "refreshToken" in path or "login" in path:
            score = 95
        elif "userinfo" in path:
            score = 85
        elif "zj.haier.net" in url:
            score = 60

        if refresh_tok and not best_refresh:
            best_refresh = refresh_tok
        if score > best_score:
            best_score = score
            if token:
                best_token = token
            if refresh_tok:
                best_refresh = refresh_tok
            best_client_id = (headers.get("clientid") or "").strip() or best_client_id
            best_source = _detect_app_source(headers)
            best_ua = headers.get("user-agent") or best_ua

    if not best_token and not best_refresh:
        if saw_connect_haier:
            raise HaierError(
                "检测到 HAR 中有 zj.haier.net 请求，但全部是未解密的 CONNECT 隧道（未开启 HTTPS 解密）。"
                "请在抓包工具（Proxyman / Charles）中对 *.haier.net 开启 SSL Proxying 后重新抓取，"
                "或直接使用「手机号 + 密码」免抓包登录。"
            )
        raise HaierError("HAR 中未找到带 token 的海尔智家（zj.haier.net）请求")

    return {
        "token": best_token,
        "refresh_token": best_refresh,
        "client_id": best_client_id or random_client_id(),
        "app_source": best_source,
        "user_agent": best_ua or DEFAULT_UA,
        "note": f"从 HAR 解析海尔智家凭据（匹配度 {best_score}）",
    }


def parse_token_input(raw: str, refresh_token: str = "", client_id: str = "", app_source: str = "") -> dict:
    text = (raw or "").strip()
    ref = (refresh_token or "").strip()
    cid = (client_id or "").strip()
    src = (app_source or "").strip() or APP_SOURCE_WXAPP

    # 支持直接粘贴 JSON（如抓包里的 tokenInfo 或请求头 JSON）
    if text.startswith("{") and text.endswith("}"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                tinfo = (obj.get("data") or {}).get("tokenInfo") if isinstance(obj.get("data"), dict) else None
                target = tinfo if isinstance(tinfo, dict) else obj
                tok = (
                    target.get("accountToken")
                    or target.get("accessToken")
                    or target.get("ak")
                    or target.get("token")
                    or ""
                )
                ref = str(target.get("refreshToken") or ref or "").strip()
                cid = str(target.get("clientId") or cid or "").strip()
                if tok or ref:
                    return {
                        "token": str(tok).strip(),
                        "refresh_token": ref,
                        "client_id": cid or random_client_id(),
                        "app_source": src if src in APP_SOURCES else APP_SOURCE_WXAPP,
                        "user_agent": DEFAULT_UA,
                        "note": "从 JSON 凭据解析",
                    }
        except Exception:
            pass

    if text.lower().startswith("bearer "):
        text = text[7:].strip()

    if not text and not ref:
        raise HaierError("请填写 accountToken 或 refreshToken")

    return {
        "token": text,
        "refresh_token": ref,
        "client_id": cid or random_client_id(),
        "app_source": src if src in APP_SOURCES else APP_SOURCE_WXAPP,
        "user_agent": DEFAULT_UA,
        "note": "手动填写海尔智家凭据",
    }


def parse(mode: str, payload: str | bytes, refresh_token: str = "", client_id: str = "", app_source: str = "") -> dict:
    if mode == "curl":
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
        return parse_curl(text)
    if mode == "har":
        return parse_har(payload)
    if mode == "token":
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
        return parse_token_input(text, refresh_token=refresh_token, client_id=client_id, app_source=app_source)
    raise HaierError(f"不支持的导入方式：{mode}")

