#!/usr/bin/env python3
# bot.py - WiFiDog Auto MAC Scanner (Railway Compatible - No nmap)

import asyncio
import subprocess
import re
import logging
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

TOKEN = "YOUR_BOT_TOKEN_HERE"

found_macs:   dict[str, dict] = {}
scan_running: bool = False


# ─────────────────────────────────────────
#  URL Parser
# ─────────────────────────────────────────

def parse_portal_url(url: str) -> dict | None:
    try:
        parsed = urlparse(url.strip())
        params = parse_qs(parsed.query)

        def get(key):
            vals = params.get(key)
            return vals[-1] if vals else None

        mac = get("mac")
        if not mac:
            return None

        return {
            "mac":        mac,
            "ip":         get("ip")         or "N/A",
            "ssid":       get("ssid")       or "N/A",
            "gw_id":      get("gw_id")      or "N/A",
            "gw_sn":      get("gw_sn")      or "N/A",
            "gw_address": get("gw_address") or "N/A",
            "gw_port":    get("gw_port")    or "N/A",
            "nasip":      get("nasip")      or "N/A",
            "ustate":     get("ustate")     or "0",
            "slot_num":   get("slot_num")   or "N/A",
        }
    except Exception as e:
        logging.error(f"Parse error: {e}")
        return None


# ─────────────────────────────────────────
#  Network Helpers (Pure Python + System Tools, NO nmap)
# ─────────────────────────────────────────

def get_subnet_from_gw(gw_address: str) -> str:
    match = re.match(r"(\d+\.\d+\.\d+)\.\d+", gw_address)
    return f"{match.group(1)}.0/24" if match else "192.168.10.0/24"


def get_mac_from_ip(ip: str) -> str:
    """Get MAC address from ARP table using system commands (no root needed)."""
    mac = "N/A"
    try:
        # Method 1: Using 'ip neigh' (most reliable)
        result = subprocess.check_output(
            f"ip neigh show {ip} 2>/dev/null",
            shell=True,
            timeout=2
        ).decode()
        # Example: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        parts = result.split()
        for idx, part in enumerate(parts):
            if part == "lladdr" and idx + 1 < len(parts):
                mac = parts[idx + 1]
                return mac
    except:
        pass

    try:
        # Method 2: Reading /proc/net/arp (Linux standard)
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:  # skip header
                fields = line.split()
                if len(fields) >= 4 and fields[0] == ip:
                    mac = fields[3]
                    return mac
    except:
        pass

    return mac


def ping_ip(ip: str) -> bool:
    """Ping an IP and return True if alive."""
    try:
        subprocess.check_output(
            f"ping -c 1 -W 1 {ip} 2>/dev/null",
            shell=True,
            timeout=2
        )
        return True
    except:
        return False


def get_hostname(ip: str) -> str:
    try:
        result = subprocess.check_output(
            f"host {ip} 2>/dev/null",
            shell=True,
            timeout=2
        ).decode()
        m = re.search(r"domain name pointer (.+)\.", result)
        return m.group(1) if m else "Unknown"
    except:
        return "Unknown"


def arp_scan(subnet: str) -> list[dict]:
    """Scan subnet using ping sweep + ARP lookup (no nmap)."""
    devices = []
    prefix = ".".join(subnet.split(".")[:3])  # e.g., 192.168.1

    for i in range(1, 255):
        ip = f"{prefix}.{i}"

        # Ping check
        if not ping_ip(ip):
            continue

        # Get MAC
        mac = get_mac_from_ip(ip)
        if mac == "N/A":
            continue

        # Get hostname (optional)
        hostname = get_hostname(ip)

        devices.append({
            "ip":       ip,
            "mac":      mac,
            "hostname": hostname,
            "vendor":   "N/A",  # Vendor lookup needs online API, skip to avoid slowness
            "time":     datetime.now().strftime("%H:%M:%S"),
        })

    return devices


def ping_check(ip: str) -> float:
    try:
        result = subprocess.check_output(
            f"ping -c 1 -W 1 {ip} 2>/dev/null",
            shell=True,
            timeout=2
        ).decode()
        m = re.search(r"time=(\d+\.?\d*)\s*ms", result)
        return float(m.group(1)) if m else -1
    except:
        return -1


# ─────────────────────────────────────────
#  Core Auto Scan
# ─────────────────────────────────────────

async def auto_scan_from_url(portal_info: dict, update: Update):
    global scan_running, found_macs
    scan_running = True
    found_macs.clear()

    gw_address = portal_info.get("gw_address", "192.168.10.1")
    subnet     = get_subnet_from_gw(gw_address)
    portal_mac = portal_info.get("mac",    "N/A")
    portal_ip  = portal_info.get("ip",     "N/A")
    ssid       = portal_info.get("ssid",   "N/A")
    ustate     = portal_info.get("ustate", "0")

    net_status = (
        "🔒 Sign into Network"
        if ustate == "0"
        else "✅ Authenticated"
    )

    # ── Step 1: Portal info ──
    msg = await update.message.reply_text(
        f"📋 *Portal Info*\n"
        f"{'─'*28}\n"
        f"📌 MAC:    `{portal_mac}`\n"
        f"🌐 IP:     `{portal_ip}`\n"
        f"📶 SSID:   `{ssid}`\n"
        f"🔧 GW:     `{gw_address}`\n"
        f"📡 Subnet: `{subnet}`\n"
        f"🔒 Status: {net_status}\n"
        f"{'─'*28}\n"
        f"⏳ Auto scan စတင်နေသည်... (စက္ကန့် ၃၀-၆၀ ကြာနိုင်သည်)",
        parse_mode="Markdown"
    )

    await asyncio.sleep(1)

    # ── Step 2: ARP Scan (Ping Sweep) ──
    await msg.edit_text(
        f"🔍 *Scanning...*\n"
        f"📡 `{subnet}`\n\n"
        f"`██░░░░░░░░` 20%\n"
        f"📡 Ping ထိုးပြီး ARP ရှာနေသည်...",
        parse_mode="Markdown"
    )

    loop    = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, arp_scan, subnet)

    await msg.edit_text(
        f"🔍 *Scanning...*\n"
        f"📡 `{subnet}`\n\n"
        f"`████░░░░░░` 50%\n"
        f"🖥 Device `{len(devices)}` ခု တွေ့ရှိသည်\n"
        f"⚡ Internet စစ်ဆေးနေသည်...",
        parse_mode="Markdown"
    )

    # ── Step 3: Ping check for internet ──
    online_devices = []
    total          = len(devices)

    for i, dev in enumerate(devices):
        pct = 50 + int(((i + 1) / max(total, 1)) * 45)
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)

        await msg.edit_text(
            f"🔍 *Scanning...*\n"
            f"📡 `{subnet}`\n\n"
            f"`{bar}` {pct}%\n"
            f"🔎 စစ်ဆေးနေသည်: `{dev['ip']}`\n"
            f"✅ Internet MAC: `{len(online_devices)}` ခု",
            parse_mode="Markdown"
        )

        latency          = await loop.run_in_executor(None, ping_check, dev["ip"])
        dev["latency"]   = latency
        dev["internet"]  = latency > 0

        if latency > 0:
            online_devices.append(dev)
            found_macs[dev["mac"]] = dev

        await asyncio.sleep(0.05)

    scan_running = False

    # ── Step 4: Scan complete message ──
    await msg.edit_text(
        f"✅ *Scan ပြီးပါပြီ!*\n"
        f"{'─'*28}\n"
        f"`██████████` 100%\n\n"
        f"🖥 Device စုစုပေါင်း:       `{total}` ခု\n"
        f"🌐 Internet ရနေသော MAC: `{len(online_devices)}` ခု\n\n"
        f"⬇️ *ရလဒ်များ အောက်တွင် ပြသမည်...*",
        parse_mode="Markdown"
    )

    await asyncio.sleep(0.5)

    # ── Step 5: No result ──
    if not online_devices:
        await update.message.reply_text(
            "📭 *Internet ရနေသော Device မတွေ့ပါ*\n\n"
            "• Bot ကို same network ထဲ run ရမည်\n"
            "• Network Gateway IP မှန်ကန်စွာ သွင်းထားပါ",
            parse_mode="Markdown"
        )
        return

    # ── Step 6: Success MAC တစ်ခုချင်းစီ တစ်ခါတည်းပို့ ──
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    await update.message.reply_text(
        f"🚨 *Internet ရနေသော MAC — {len(online_devices)} ခု*\n"
        f"{'─'*30}\n"
        f"📶 SSID:   `{ssid}`\n"
        f"📡 Subnet: `{subnet}`\n"
        f"🕐 Time:   `{now}`\n"
        f"{'─'*30}",
        parse_mode="Markdown"
    )

    for i, dev in enumerate(online_devices, 1):
        lat = dev["latency"]

        if lat < 10:
            speed_icon = "⚡"
            speed_label = "Fast"
        elif lat < 50:
            speed_icon = "✅"
            speed_label = "Good"
        else:
            speed_icon = "⚠️"
            speed_label = "Slow"

        is_portal = dev["mac"] == portal_mac
        mark      = "\n   📌 *(Portal Device)*" if is_portal else ""

        mac_msg = (
            f"✅ *MAC #{i}*{mark}\n"
            f"{'─'*25}\n"
            f"🔵 MAC:     `{dev['mac']}`\n"
            f"🌐 IP:      `{dev['ip']}`\n"
            f"🖥 Host:    `{dev['hostname']}`\n"
            f"📶 Speed:   {speed_icon} `{lat}ms` ({speed_label})\n"
            f"🕐 Time:    `{dev['time']}`"
        )

        await update.message.reply_text(mac_msg, parse_mode="Markdown")
        await asyncio.sleep(0.3)

    await update.message.reply_text(
        f"{'─'*30}\n"
        f"💾 `/saved` — MAC list ပြန်ကြည့်ရန်\n"
        f"🗑 `/clear` — List ရှင်းလင်းရန်",
        parse_mode="Markdown"
    )


# ─────────────────────────────────────────
#  Commands
# ─────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 *WiFiDog Auto MAC Scanner*\n\n"
        "📌 *Commands:*\n"
        "`/setup <url>` — Portal URL ပို့ → Auto scan\n"
        "`/saved`       — Internet ရသော MAC list\n"
        "`/clear`       — List ရှင်းလင်းရန်",
        parse_mode="Markdown"
    )


async def cmd_setup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    global scan_running
    if scan_running:
        await update.message.reply_text("⚠️ Scan လုပ်နေဆဲပါ။ ပြီးသည်အထိ စောင့်ပါ။")
        return

    args = ctx.args
    if not args:
        await update.message.reply_text(
            "⚠️ URL မပါပါ\n`/setup <portal_url>`",
            parse_mode="Markdown"
        )
        return

    url = " ".join(args).strip()
    if "mac=" not in url:
        await update.message.reply_text("❌ WiFiDog portal URL မဟုတ်ပါ")
        return

    info = parse_portal_url(url)
    if not info:
        await update.message.reply_text("❌ URL parse မရပါ")
        return

    await auto_scan_from_url(info, update)


async def cmd_saved(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not found_macs:
        await update.message.reply_text(
            "📭 *Saved MAC မရှိသေးပါ*\n"
            "`/setup <url>` ဖြင့် scan ပြုလုပ်ပါ",
            parse_mode="Markdown"
        )
        return

    lines = [
        f"💾 *Saved — Internet ရနေသော MAC ({len(found_macs)} ခု)*",
        f"{'─'*28}"
    ]
    for i, (mac, dev) in enumerate(found_macs.items(), 1):
        lines.append(
            f"\n*{i}.* `{mac}`\n"
            f"   🌐 `{dev['ip']}`\n"
            f"   📶 `{dev['latency']}ms` | 🕐 `{dev['time']}`"
        )
    lines.append(f"\n{'─'*28}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    count = len(found_macs)
    found_macs.clear()
    await update.message.reply_text(
        f"🗑 MAC `{count}` ခု ဖျက်လိုက်သည်",
        parse_mode="Markdown"
    )


async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if "mac=" in text and "gw_id=" in text:
        ctx.args = [text]
        await cmd_setup(update, ctx)
    else:
        await update.message.reply_text(
            "💡 `/setup <url>` ဖြင့် portal URL ပို့ပါ",
            parse_mode="Markdown"
        )


# ─────────────────────────────────────────
#  Main
# ─────────────────────────────────────────

def main():
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("setup",  cmd_setup))
    app.add_handler(CommandHandler("saved",  cmd_saved))
    app.add_handler(CommandHandler("clear",  cmd_clear))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    print("🤖 Bot စတင်နေပါပြီ... (Railway Compatible)")
    app.run_polling()


if __name__ == "__main__":
    main()
