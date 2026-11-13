"""龙湖签到服务：Web 前端 + REST API + 内置定时任务。"""

import hashlib
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import db, dxrisk, haier, longhu, parser, runner, scheduler
from . import login as app_login

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    scheduler.start()
    logger.info("服务已启动，签到窗口：小程序 %s，APP %s",
                scheduler.window_text("mini"), scheduler.window_text("app"))
    yield


app = FastAPI(title="龙湖签到", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --------------------------------------------------------------------------
# 页面
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


# --------------------------------------------------------------------------
# 账号
# --------------------------------------------------------------------------

def _decorate(account: dict, usage: dict[str, list[dict]] | None = None,
              settings: dict | None = None,
              next_runs: dict[str, str] | None = None) -> dict:
    settings = settings if settings is not None else db.get_settings()
    next_runs = next_runs or {}
    item = dict(account)
    for key in ("token", "user_agent", "api_key", "dx_token", "refresh_token"):  # 敏感字段不外发
        item.pop(key, None)
    token = account.get("token") or ""
    item["token_mask"] = f"{token[:6]}...{token[-4:]}" if len(token) > 12 else "****"
    item["platform"] = (account.get("platform") or "longhu").strip() or "longhu"
    item["has_refresh"] = bool((account.get("refresh_token") or "").strip())
    item["app_source"] = (account.get("app_source") or "wxapp").strip()
    item["sign_days"] = int(account.get("sign_days") or 0)

    # 设备指纹状态。同一指纹用于多个账号会触发风控（2026-11-03 实测），
    # 指纹归 id 最小的账号所有，其余账号会被标记为冲突并暂停签到。
    dx = (account.get("dx_token") or "").strip()
    item["has_dx"] = bool(dx)
    # 只看启用中的账号，与运行时 _dx_conflict 的口径保持一致
    shared = [
        a for a in (usage or {}).get(dx, [])
        if a["id"] != account["id"] and a.get("enabled")
    ] if dx else []
    item["dx_shared"] = bool(shared)
    item["dx_shared_with"] = [a["name"] for a in shared]
    item["dx_conflict"] = any(a["id"] < account["id"] for a in shared)
    item["days_left"] = runner.days_left(account.get("expire_at"))
    # 各入口各自的窗口：账号自定义优先，否则跟随全局
    item["mini_time"] = (account.get("mini_time") or "").strip()
    item["app_time"] = (account.get("app_time") or "").strip()
    all_entries = (*db.SLOT_ENTRIES, "haier")
    item["windows"] = {
        entry: scheduler.account_window(account, entry, settings)
        for entry in all_entries
    }
    item["next_runs"] = {
        entry: next_runs.get(f"{account['id']}:{entry}", "")
        for entry in all_entries
    }
    return item


@app.get("/api/accounts")
def api_accounts():
    usage = db.dx_usage()
    settings = db.get_settings()
    next_runs = scheduler.next_run_map()
    return [_decorate(acc, usage, settings, next_runs) for acc in db.list_accounts()]


# 旧版 cURL / HAR / token 导入接口。网页已只提供手机号登录，这里仅为兼容
# 可能存在的外部脚本而保留，不再有前端入口。
@app.post("/api/accounts/bind")
async def api_bind(
    mode: str = Form(...),
    name: str = Form(""),
    payload: str = Form(""),
    dx_token: str = Form(""),
    file: UploadFile | None = File(None),
):
    if mode == "har":
        if file is None:
            raise HTTPException(400, "HAR 模式需要上传文件")
        raw = await file.read()
    else:
        raw = payload

    try:
        parsed = parser.parse(mode, raw)
    except parser.ParseError as exc:
        raise HTTPException(400, str(exc)) from exc

    account = {
        "token": parsed["token"],
        "user_agent": parsed.get("user_agent") or longhu.DEFAULT_UA,
        "api_key": parsed.get("api_key"),
        "bu_code": parsed.get("bu_code", "C20400"),
        "channel": parsed.get("channel", "C2"),
    }

    # 一账号一指纹：共用指纹会触发风控，提前拦掉，别等跑起来才暴露。
    dx_value = dx_token.strip()
    if dx_value:
        others = db.accounts_with_dx(dx_value)
        if others:
            names = "、".join(a["name"] for a in others)
            raise HTTPException(
                400,
                f"这个指纹已被「{names}」占用。同一指纹用于多个账号会触发风控，"
                "请换一份未被占用的独立指纹；新版手机号登录会自动签发，不用重装 App。",
            )

    # 校验 token：先直接查资料，失败则尝试续期后重试
    profile = None
    verify_error = ""
    try:
        profile = longhu.probe_token(
            account["token"], account["user_agent"], account["bu_code"], account["channel"]
        )
    except longhu.LonghuError as exc:
        verify_error = str(exc)
        ok, new_token = longhu.refresh_token(account)
        if ok:
            account["token"] = new_token
            try:
                profile = longhu.probe_token(
                    account["token"], account["user_agent"],
                    account["bu_code"], account["channel"],
                )
                verify_error = ""
            except longhu.LonghuError as exc2:
                verify_error = str(exc2)

    if profile is None:
        raise HTTPException(400, f"凭据校验失败：{verify_error or '未知原因'}，请重新抓取")

    # 默认名用脱敏手机号：昵称一律是「珑珠用户」，多账号根本分不出来。
    final_name = (
        (name or "").strip()
        or profile.get("phone")
        or profile.get("nickname")
        or f"龙湖账号 {len(db.list_accounts()) + 1}"
    )

    account_id = db.create_account({
        "name": final_name,
        "token": account["token"],
        "user_agent": account["user_agent"],
        "api_key": account["api_key"],
        "dx_token": dx_value or None,
        "bu_code": account["bu_code"],
        "channel": account["channel"],
        "growth_value": profile.get("growth_value", 0),
        "level_name": profile.get("level_name", ""),
        "balance": profile.get("balance", 0),
        "nickname": profile.get("nickname", ""),
        "expire_at": longhu.expire_at(),
    })
    db.add_log(account_id, final_name, "bind", "ok", f"{parsed['note']}，凭据校验通过")

    return {"ok": True, "id": account_id, "name": final_name, "profile": profile}


# --------------------------------------------------------------------------
# 手机号 + 验证码登录：添加新账号不再需要抓包
#
# 链路（2026-11-07 实测）：
#   prepare  → 服务端按手机号签一份独立顶象指纹（dxrisk，纯标准库）
#   send-code→ App 端签名头（app 密钥）调 sendSmsCodeSecret
#              首次会返 909001「请操作图形验证」，此时前端跑一次顶象滑块，
#              把 "<滑块token>:<指纹>" 作为 riskToken 重发即可
#   verify   → smsCodeSecret 拿到 token/lmid，直接落库
# 登录拿到的 token 与现有签到链路完全通用（probe_token 两种网关都验过）。
# --------------------------------------------------------------------------

_sms_cooldown: dict[str, float] = {}


def _valid_mobile(raw: str) -> str:
    value = re.sub(r"\D", "", raw or "")
    if len(value) != 11 or not value.startswith("1"):
        raise HTTPException(400, "请输入 11 位手机号")
    return value


def _pick_profile(mobile: str, requested: str | None) -> str:
    """选一套机型预设：手动指定优先，自动模式尽量把新账号分散到不同机型。"""
    key = (requested or "").strip().lower()
    keys = dxrisk.PROFILE_KEYS
    if key and key != "auto":
        if key not in dxrisk.DEVICE_PROFILES:
            raise HTTPException(400, "未知机型预设，请从列表里选")
        return key
    # 自动：已有账号数轮转 + 手机号稳定哈希，避免所有账号都落在同一套
    digest = hashlib.sha256(("dx-profile:" + mobile).encode()).digest()
    return keys[(len(db.list_accounts(only_enabled=True)) + digest[0]) % len(keys)]


def _new_fingerprint(mobile: str, profile: str) -> str:
    """给新账号签一份独立指纹；共用指纹会被上游判成同设备多账号。"""
    last = ""
    for _ in range(4):
        try:
            res = dxrisk.issue(f"{mobile}:{uuid.uuid4().hex}",
                               timeout=15, profile=profile)
        except Exception as exc:  # 指纹服务偶发超时，重试即可
            last = str(exc)[:120]
            continue
        value = (res.get("token") or "").strip()
        if value and not db.accounts_with_dx(value):
            return value
        last = f"code={res.get('code')}（指纹为空或已被占用）"
    raise HTTPException(502, f"设备指纹生成失败：{last or '未知原因'}")


def _login_error(exc: app_login.LoginError) -> JSONResponse:
    """透传上游业务码；909001 让前端弹出滑块。"""
    return JSONResponse(
        status_code=400,
        content={
            "need_captcha": exc.extra_code == "909001",
            "code": exc.extra_code or exc.code,
            "message": exc.message,
        },
    )


@app.get("/api/device/profiles")
def api_device_profiles():
    """机型预设列表；只给成套预设，不开放字段自由填写。"""
    return {"ok": True, "profiles": dxrisk.profiles(),
            "default_profile": dxrisk.DEFAULT_PROFILE}


@app.post("/api/login/prepare")
def api_login_prepare(mobile: str = Form(...), profile: str = Form("")):
    """登录前置：按所选机型签一份新的设备指纹，后续两步都要原样带回。"""
    number = _valid_mobile(mobile)
    key = _pick_profile(number, profile)
    return {
        "ok": True,
        "mobile": number,
        "fingerprint": _new_fingerprint(number, key),
        "profile": key,
        "profile_name": dxrisk.DEVICE_PROFILES[key]["name"],
    }


@app.post("/api/login/send-code")
def api_login_send_code(
    mobile: str = Form(...),
    fingerprint: str = Form(...),
    risk_token: str = Form(""),
):
    number = _valid_mobile(mobile)
    fp = fingerprint.strip()
    if not fp:
        raise HTTPException(400, "缺少设备指纹，请重新打开添加账号面板")
    now = time.time()
    if now - _sms_cooldown.get(number, 0) < 55:
        raise HTTPException(400, "发送太频繁，请等 1 分钟再试")
    try:
        app_login.send_sms_code(number, fp, risk_token.strip())
    except app_login.LoginError as exc:
        return _login_error(exc)
    _sms_cooldown[number] = now
    return {"ok": True, "message": f"验证码已发到 {number[:3]}****{number[-4:]}"}


@app.post("/api/login/verify")
def api_login_verify(
    mobile: str = Form(...),
    code: str = Form(...),
    fingerprint: str = Form(...),
    name: str = Form(""),
    profile: str = Form(""),
):
    """用短信验证码换 token，校验后直接写进账号表。"""
    number = _valid_mobile(mobile)
    fp = fingerprint.strip()
    sms = (code or "").strip()
    pkey = (profile or "").strip().lower()
    if not re.fullmatch(r"\d{4,8}", sms):
        raise HTTPException(400, "验证码应为 4–8 位数字")
    if not fp:
        raise HTTPException(400, "缺少设备指纹，请重新打开添加账号面板")
    if db.accounts_with_dx(fp):
        raise HTTPException(400, "这个指纹已被其他账号占用，请换一份未被占用的独立指纹")

    try:
        result = app_login.login_by_code(number, sms, fp)
    except app_login.LoginError as exc:
        return _login_error(exc)

    token = (result.get("token") or "").strip()
    if not token:
        raise HTTPException(400, "登录成功但没返回 token，请重试")

    existing = next((a for a in db.list_accounts() if a.get("token") == token), None)
    if existing:
        raise HTTPException(400, f"这个账号已经添加过了：{existing['name']}")

    # 登录态和现有签到链路通用；查资料只是为了填默认名/成长值，失败不阻断入库。
    user_profile: dict = {}
    try:
        user_profile = longhu.probe_token(token)
    except longhu.LonghuError as exc:
        logger.warning("新登录账号资料查询失败（不影响入库）：%s", exc)

    final_name = (
        (name or "").strip()
        or user_profile.get("phone")
        or f"龙湖账号 {len(db.list_accounts()) + 1}"
    )
    account_id = db.create_account({
        "name": final_name,
        "token": token,
        "user_agent": longhu.DEFAULT_UA,
        "api_key": None,
        "dx_token": fp,
        "bu_code": "C20400",
        "channel": "C2",
        "growth_value": user_profile.get("growth_value", 0),
        "level_name": user_profile.get("level_name", ""),
        "balance": user_profile.get("balance", 0),
        "nickname": user_profile.get("nickname", ""),
        "expire_at": longhu.expire_at(),
    })
    pname = dxrisk.DEVICE_PROFILES.get(pkey, {}).get("name", "自动分配")
    scheduler.reschedule()
    db.add_log(account_id, final_name, "login", "ok",
               f"手机号验证码登录成功，设备指纹已同步（机型 {pname}，lmid "
               f"{result.get('lmid') or '-'}）")
    return {"ok": True, "id": account_id, "name": final_name, "profile": user_profile}


# --------------------------------------------------------------------------
# 海尔智家：密码登录 + 抓包凭据导入 + 凭据更新
# --------------------------------------------------------------------------

@app.post("/api/haier/login")
def api_haier_login(
    mobile: str = Form(...),
    password: str = Form(...),
    name: str = Form(""),
):
    """海尔智家手机号 + 密码登录，直拿 accountToken 与 refreshToken。"""
    try:
        login_res = haier.phone_login(mobile, password)
    except haier.HaierError as exc:
        raise HTTPException(400, str(exc)) from exc

    token = login_res["token"]
    refresh_tok = login_res.get("refresh_token") or ""
    client_id = login_res.get("client_id") or haier.random_client_id()
    app_source = login_res.get("app_source") or haier.APP_SOURCE_APP

    profile = {}
    try:
        profile = haier.fetch_profile({
            "token": token,
            "client_id": client_id,
            "app_source": app_source,
        })
    except haier.HaierError as exc:
        logger.warning("海尔登录成功但拉取资料失败：%s", exc)

    haier_count = sum(1 for a in db.list_accounts() if (a.get("platform") or "longhu") == "haier")
    final_name = (
        (name or "").strip()
        or profile.get("phone")
        or profile.get("nickname")
        or haier.mask_phone(mobile)
        or f"海尔账号 {haier_count + 1}"
    )

    account_id = db.create_account({
        "name": final_name,
        "token": token,
        "refresh_token": refresh_tok,
        "client_id": client_id,
        "app_source": app_source,
        "platform": "haier",
        "user_agent": haier.DEFAULT_UA,
        "growth_value": profile.get("growth_value", 0),
        "level_name": profile.get("level_name", ""),
        "balance": profile.get("balance", 0),
        "sign_days": profile.get("sign_days", 0),
        "nickname": profile.get("nickname", ""),
        "expire_at": haier.expire_at(login_res.get("expires_in")),
    })
    scheduler.reschedule()
    db.add_log(account_id, final_name, "login", "ok", "海尔智家密码登录成功，已启用自动续期")
    return {"ok": True, "id": account_id, "name": final_name, "profile": profile}


@app.post("/api/haier/bind")
async def api_haier_bind(
    mode: str = Form("token"),
    name: str = Form(""),
    payload: str = Form(""),
    refresh_token: str = Form(""),
    client_id: str = Form(""),
    app_source: str = Form("wxapp"),
    file: UploadFile | None = File(None),
):
    """海尔智家抓包导入：支持 HAR 上传、cURL 粘贴、手动填写 accountToken / refreshToken。"""
    if mode == "har":
        if file is None:
            raise HTTPException(400, "请先选择要上传的 HAR 文件")
        raw = await file.read()
    else:
        raw = payload

    try:
        parsed = haier.parse(
            mode,
            raw,
            refresh_token=refresh_token,
            client_id=client_id,
            app_source=app_source,
        )
    except haier.HaierError as exc:
        raise HTTPException(400, str(exc)) from exc

    account = {
        "token": parsed.get("token") or "",
        "refresh_token": parsed.get("refresh_token") or "",
        "client_id": parsed.get("client_id") or haier.random_client_id(),
        "app_source": parsed.get("app_source") or haier.APP_SOURCE_WXAPP,
        "user_agent": parsed.get("user_agent") or haier.DEFAULT_UA,
    }

    # 如果只填了 refreshToken 或 token 已过期，先尝试用 refreshToken 换新 token
    expires_in = None
    if account["refresh_token"] and not account["token"]:
        ok, ref_res = haier.refresh_token(account)
        if not ok or not isinstance(ref_res, dict):
            raise HTTPException(400, f"refreshToken 换取 token 失败：{ref_res}")
        account["token"] = ref_res["token"]
        account["refresh_token"] = ref_res.get("refresh_token") or account["refresh_token"]
        account["app_source"] = ref_res.get("app_source") or account["app_source"]
        expires_in = ref_res.get("expires_in")

    profile = {}
    try:
        profile = haier.fetch_profile(account)
    except haier.HaierError as exc:
        # 若 token 失效但带有 refreshToken，自动刷新一次再试
        if account["refresh_token"]:
            ok, ref_res = haier.refresh_token(account)
            if ok and isinstance(ref_res, dict):
                account["token"] = ref_res["token"]
                account["refresh_token"] = ref_res.get("refresh_token") or account["refresh_token"]
                account["app_source"] = ref_res.get("app_source") or account["app_source"]
                expires_in = ref_res.get("expires_in")
                try:
                    profile = haier.fetch_profile(account)
                except haier.HaierError:
                    pass
            else:
                raise HTTPException(400, f"凭据校验与刷新均失败：{ref_res}") from exc
        else:
            raise HTTPException(400, f"海尔凭据校验失败：{exc}") from exc

    haier_count = sum(1 for a in db.list_accounts() if (a.get("platform") or "longhu") == "haier")
    final_name = (
        (name or "").strip()
        or profile.get("phone")
        or profile.get("nickname")
        or f"海尔账号 {haier_count + 1}"
    )

    account_id = db.create_account({
        "name": final_name,
        "token": account["token"],
        "refresh_token": account["refresh_token"] or None,
        "client_id": account["client_id"],
        "app_source": account["app_source"],
        "platform": "haier",
        "user_agent": account["user_agent"],
        "growth_value": profile.get("growth_value", 0),
        "level_name": profile.get("level_name", ""),
        "balance": profile.get("balance", 0),
        "sign_days": profile.get("sign_days", 0),
        "nickname": profile.get("nickname", ""),
        "expire_at": haier.expire_at(expires_in),
    })
    scheduler.reschedule()
    db.add_log(account_id, final_name, "bind", "ok", f"{parsed['note']}，校验通过")
    return {"ok": True, "id": account_id, "name": final_name, "profile": profile}


@app.post("/api/accounts/{account_id}/haier-cred")
def api_set_haier_cred(
    account_id: int,
    token: str = Form(""),
    refresh_token: str = Form(""),
    app_source: str = Form(""),
):
    """更新海尔智家账号的 accountToken / refreshToken。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")
    if (account.get("platform") or "longhu") != "haier":
        raise HTTPException(400, "该账号不是海尔智家账号")

    tok = token.strip()
    ref = refresh_token.strip()
    if not tok and not ref:
        raise HTTPException(400, "请至少填写 accountToken 或 refreshToken")

    updates = {}
    if tok:
        updates["token"] = tok
    if ref:
        updates["refresh_token"] = ref
    if app_source.strip() in haier.APP_SOURCES:
        updates["app_source"] = app_source.strip()
    updates["expire_at"] = haier.expire_at()

    db.update_account(account_id, **updates)
    db.add_log(account_id, account["name"], "bind", "ok", "已更新海尔智家凭据")
    return {"ok": True}


@app.post("/api/accounts/{account_id}/dx")
def api_set_dx(account_id: int, dx_token: str = Form("")):
    """补填/更换顶象设备指纹；新版手机号登录会自动签发，此项主要用于旧版或迁移账号。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")
    value = dx_token.strip()
    if value and (len(value) < 20 or " " in value):
        raise HTTPException(400, "指纹格式不对，应形如 6ae93a6cUDMfhHgK6eYXWjqtu1qMG9bAJdij8Er1")

    # 一账号一指纹：共用指纹会被上游判成同一设备多账号，直接触发风控。
    if value:
        others = db.accounts_with_dx(value, exclude_id=account_id)
        if others:
            names = "、".join(a["name"] for a in others)
            raise HTTPException(
                400,
                f"这个指纹已被「{names}」占用。同一指纹用于多个账号会触发风控，"
                "请换一份未被占用的独立指纹；新版手机号登录会自动签发，不用重装 App。",
            )

    db.update_account(account_id, dx_token=value or None)
    db.add_log(account_id, account["name"], "dx",
               "ok" if value else "fail", "已保存设备指纹" if value else "已清除设备指纹")
    return {"ok": True, "has_dx": bool(value)}


@app.delete("/api/accounts/{account_id}")
def api_delete(account_id: int):
    if not db.get_account(account_id):
        raise HTTPException(404, "账号不存在")
    db.delete_account(account_id)
    return {"ok": True}


@app.post("/api/accounts/{account_id}/run")
def api_run(account_id: int, app: str | None = None):
    """立即跑一轮。app=auto 强制尝试 APP 入口，app=off 跳过，默认按设置。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")
    mode = (app or "").strip().lower() or None
    if mode and mode not in runner.APP_MODES:
        raise HTTPException(400, "app 只能是 auto / manual / off")
    result = runner.run_account(account, do_checkin=True, app_mode=mode)
    return result


@app.get("/api/accounts/{account_id}/logs")
def api_account_logs(account_id: int, limit: int = 20):
    return db.list_logs(account_id, limit)


# --------------------------------------------------------------------------
# 概览 / 设置 / 日志
# --------------------------------------------------------------------------

@app.get("/api/overview")
def api_overview():
    accounts = db.list_accounts()
    today = date.today().isoformat()
    stats = {"ok": 0, "already": 0, "fail": 0, "pending": 0, "conflict": 0, "risk": 0}
    min_days = None

    for acc in accounts:
        days = runner.days_left(acc.get("expire_at"))
        if days is not None:
            min_days = days if min_days is None else min(min_days, days)
        ran_today = (acc.get("last_run_at") or "")[:10] == today
        if not acc.get("enabled"):
            stats["pending"] += 1
        elif not ran_today:
            stats["pending"] += 1
        else:
            status = acc.get("last_status") or ""
            stats[status if status in stats else "fail"] += 1

    settings = db.get_settings()
    longhu_count = sum(1 for a in accounts if (a.get("platform") or "longhu") == "longhu")
    haier_count = sum(1 for a in accounts if (a.get("platform") or "longhu") == "haier")
    return {
        "total": len(accounts),
        "longhu_count": longhu_count,
        "haier_count": haier_count,
        "stats": stats,
        "min_days": min_days,
        "next_run": scheduler.next_run_text(),
        "checkin_time": settings.get("checkin_time", "08:00"),
        "app_checkin_time": settings.get("app_checkin_time", "09:30"),
        "haier_checkin_time": settings.get("haier_checkin_time", "08:15"),
        "window": scheduler.window_text("mini"),
        "app_window": scheduler.window_text("app"),
        "haier_window": scheduler.window_text("haier"),
    }


@app.get("/api/logs")
def api_logs(limit: int = 50):
    return db.list_logs(None, limit)


@app.get("/api/settings")
def api_get_settings():
    data = db.get_settings()
    return {
        "checkin_time": data.get("checkin_time", "08:00"),
        "checkin_jitter": data.get("checkin_jitter", "60"),
        "app_checkin_time": data.get("app_checkin_time", "09:30"),
        "app_checkin_jitter": data.get("app_checkin_jitter", "60"),
        "haier_checkin_time": data.get("haier_checkin_time", "08:15"),
        "haier_checkin_jitter": data.get("haier_checkin_jitter", "60"),
        "window": scheduler.window_text("mini"),
        "app_window": scheduler.window_text("app"),
        "haier_window": scheduler.window_text("haier"),
        "webhook_url": data.get("webhook_url", ""),
        "app_checkin_mode": data.get("app_checkin_mode", "manual"),
        "next_run": scheduler.next_run_text(),
    }


def _parse_time_field(value: str, label: str) -> str:
    try:
        hour, minute = value.strip().split(":")
        assert 0 <= int(hour) <= 23 and 0 <= int(minute) <= 59
    except Exception:
        raise HTTPException(400, f"{label}格式应为 HH:MM") from None
    return f"{int(hour):02d}:{int(minute):02d}"


def _check_gap(mini_time: str, app_time: str):
    """两个入口不要设成同一时刻——分时签到就是为了不连着打。"""
    def minutes(text: str) -> int:
        hour, minute = text.split(":")
        return int(hour) * 60 + int(minute)

    diff = abs(minutes(mini_time) - minutes(app_time))
    if min(diff, 1440 - diff) < 5:
        raise HTTPException(
            400,
            "小程序和 APP 的时间至少错开 5 分钟——两个入口同一时刻连着打，"
            "等于没有分开排期。",
        )


@app.post("/api/settings")
def api_save_settings(
    checkin_time: str = Form(...),
    webhook_url: str = Form(""),
    checkin_jitter: str | None = Form(None),
    app_checkin_time: str | None = Form(None),
    app_checkin_jitter: str | None = Form(None),
    haier_checkin_time: str | None = Form(None),
    haier_checkin_jitter: str | None = Form(None),
    app_checkin_mode: str | None = Form(None),
):
    mini_time = _parse_time_field(checkin_time, "小程序时间")
    app_time = _parse_time_field(app_checkin_time or db.get_settings().get("app_checkin_time", "09:30"),
                                 "APP 时间")
    haier_time = _parse_time_field(haier_checkin_time or db.get_settings().get("haier_checkin_time", "08:15"),
                                   "海尔签到时间")
    _check_gap(mini_time, app_time)

    values = {
        "checkin_time": mini_time,
        "webhook_url": webhook_url.strip(),
        "app_checkin_time": app_time,
        "haier_checkin_time": haier_time,
    }
    for field, key, label in (
        (checkin_jitter, "checkin_jitter", "随机浮动"),
        (app_checkin_jitter, "app_checkin_jitter", "APP 随机浮动"),
        (haier_checkin_jitter, "haier_checkin_jitter", "海尔随机浮动"),
    ):
        if field is None or field.strip() == "":
            continue
        try:
            jitter = int(float(field))
            assert 0 <= jitter <= 1439
        except Exception:
            raise HTTPException(400, f"{label}应为 0–1439 之间的分钟数") from None
        values[key] = str(jitter)

    if app_checkin_mode is not None and app_checkin_mode.strip() != "":
        mode = app_checkin_mode.strip().lower()
        if mode not in runner.APP_MODES:
            raise HTTPException(400, "APP 入口方式只能是 auto / manual / off")
        values["app_checkin_mode"] = mode

    db.save_settings(values)
    scheduler.reschedule()
    return {
        "ok": True,
        "window": scheduler.window_text("mini"),
        "app_window": scheduler.window_text("app"),
        "haier_window": scheduler.window_text("haier"),
        "next_run": scheduler.next_run_text(),
    }


@app.post("/api/accounts/{account_id}/schedule")
def api_set_schedule(account_id: int, mini_time: str = Form(""),
                     app_time: str = Form("")):
    """单账号自定义两个入口的时间。留空表示跟随全局设置。"""
    account = db.get_account(account_id)
    if not account:
        raise HTTPException(404, "账号不存在")

    is_haier = (account.get("platform") or "longhu") == "haier"
    mini_value = _parse_time_field(mini_time, "签到时间" if is_haier else "小程序时间") if mini_time.strip() else ""
    app_value = _parse_time_field(app_time, "APP 时间") if (not is_haier and app_time.strip()) else ""

    if not is_haier:
        settings = db.get_settings()
        effective = dict(account, mini_time=mini_value, app_time=app_value)
        _check_gap(
            scheduler.effective_start(effective, "mini", settings),
            scheduler.effective_start(effective, "app", settings),
        )

    db.update_account(account_id, mini_time=mini_value or None, app_time=app_value or None)
    for entry in (("haier",) if is_haier else db.SLOT_ENTRIES):
        db.clear_slot_plan(account_id, entry)
    scheduler.reschedule()
    if is_haier:
        db.add_log(account_id, account["name"], "schedule", "ok",
                   f"签到时间已更新：{mini_value or '跟随全局'}")
    else:
        db.add_log(account_id, account["name"], "schedule", "ok",
                   f"签到时间已更新：小程序 {mini_value or '跟随全局'}，"
                   f"APP {app_value or '跟随全局'}")
    return {"ok": True}


@app.get("/api/health")
def api_health():
    return {"ok": True, "data_dir": os.environ.get("DATA_DIR", "./data")}
