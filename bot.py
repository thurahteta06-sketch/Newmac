#!/usr/bin/env python3
# bot.py - WiFiDog Auto MAC Scanner (Fast ARP, Crash-Free)

import asyncio
import subprocess
import re
import logging
import os
import sys
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# Logging ကို ပိုပြီး အသေးစိတ် ထုတ်မယ်
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Token ကို Environment Variable ကနေ ယူမယ် (ပိုလုံခြုံတယ်)
TOKEN = os.environ.get("BOT_TOKEN")
if not TOKEN:
    logger.error("BOT_TOKEN environment variable not set!")
    sys.exit(1)

found_macs: dict[str, dict] = {}
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
        logger.error(f"Parse error: {e}")
        return None

# ─────────────────────────────────────────
#  Fast ARP Reader (No ping sweep)
# ─────────────────────────────────────────
def get_subnet_from_gw(gw_address: str) -> str:
    match = re.match(r"(\d+\.\d+\.\d+)\.\d+", gw_address)
    return f"{match.group(1)}.0/24" if match else "192.168.10.0/24"

def read_arp_table() -> list[dict]:
    devices = []
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00" and mac != "FF:FF:FF:FF:FF:FF":
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "hostname": "N/A",
                            "vendor": "N/A",
                            "time": datetime.now().strftime("%H:%M:%S")
                        })
    except Exception as e:
        logger.error(f"ARP read error: {e}")
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
#  Core Scan
# ─────────────────────────────────────────
async def auto_scan_from_url(portal_info: dict, update: Update):
    global scan_running, found_macs
    try:
        scan_running = True
        found_macs.clear()

        gw_address = portal_info.get("gw_address", "192.168.10.1")
        subnet     = get_subnet_from_gw(gw_address)
        portal_mac = portal_info.get("mac",    "N/A")
        portal_ip  = portal_info.get("ip",     "N/A")
        ssid       = portal_info.get("ssid",   "N/A")
        ustate     = portal_info.get("ustate", "0")

        net_status = "🔒 Sign into Network" if ustate == "0" else "✅ Authenticated"

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
            f"⏳ ARP Table ဖတ်နေသည်...",
            parse_mode="Markdown"
        )

        loop = asyncio.get_event_loop()
        devices = await loop.run_in_executor(None, read_arp_table)

        if not devices:
            await msg.edit_text(
                "📭 *ARP Table တွင် Device မတွေ့ပါ*\n\n"
                "• Bot ကို Gateway နဲ့ တူညီတဲ့ Network မှာ run ပါ\n"
                "• သို့မဟုတ် `nmap` ပြန်သုံးရန် စဉ်းစားပါ",
                parse_mode="Markdown"
            )
            scan_running = False
            return

        await msg.edit_text(
            f"🔍 *ARP Table မှ Device {len(devices)} ခု တွေ့သည်*\n"
            f"⚡ Internet စစ်ဆေးနေသည်...",
            parse_mode="Markdown"
        )

        online_devices = []
        for i, dev in enumerate(devices):
            latency = await loop.run_in_executor(None, ping_check, dev["ip"])
            dev["latency"] = latency
            if latency > 0:
                online_devices.append(dev)
                found_macs[dev["mac"]] = dev
            await asyncio.sleep(0.05)

        scan_running = False

        if not online_devices:
            await update.message.reply_text(
                "📭 *Internet ရနေသော Device မတွေ့ပါ*",
                parse_mode="Markdown"
            )
            return

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
            speed_icon = "⚡" if lat < 10 else "✅" if lat < 50 else "⚠️"
            speed_label = "Fast" if lat < 10 else "Good" if lat < 50 else "Slow"
            is_portal = dev["mac"] == portal_mac
            mark = "\n   📌 *(Portal Device)*" if is_portal else ""
            mac_msg = (
                f"✅ *MAC #{i}*{mark}\n"
                f"{'─'*25}\n"
                f"🔵 MAC:     `{dev['mac']}`\n"
                f"🌐 IP:      `{dev['ip']}`\n"
                f"📶 Speed:   {speed_icon} `{lat}ms` ({speed_label})\n"
                f"🕐 Time:    `{dev['time']}`"
            )
            await update.message.reply_text(mac_msg, parse_mode="Markdown")
            await asyncio.sleep(0.2)

        await update.message.reply_text(
            f"{'─'*30}\n"
            f"💾 `/saved` — MAC list ပြန်ကြည့်ရန်\n"
            f"🗑 `/clear` — List ရှင်းလင်းရန်",
            parse_mode="Markdown"
        )

    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        await update.message.reply_text(f"❌ Scan လုပ်နေစဉ် Error ဖြစ်သွားတယ်:\n`{e}`", parse_mode="Markdown")
    finally:
        scan_running = False

# ─────────────────────────────────────────
#  Commands
# ─────────────────────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 *WiFiDog Auto MAC Scanner (Fast ARP)*\n\n"
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
        await update.message.reply_text("⚠️ URL မပါပါ\n`/setup <portal_url>`", parse_mode="Markdown")
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
        await update.message.reply_text("📭 *Saved MAC မရှိသေးပါ*", parse_mode="Markdown")
        return
    lines = [f"💾 *Saved — ({len(found_macs)} ခု)*", f"{'─'*28}"]
    for i, (mac, dev) in enumerate(found_macs.items(), 1):
        lines.append(f"\n*{i}.* `{mac}`\n   🌐 `{dev['ip']}`\n   📶 `{dev['latency']}ms` | 🕐 `{dev['time']}`")
    lines.append(f"\n{'─'*28}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    count = len(found_macs)
    found_macs.clear()
    await update.message.reply_text(f"🗑 MAC `{count}` ခု ဖျက်လိုက်သည်", parse_mode="Markdown")

async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if "mac=" in text and "gw_id=" in text:
        ctx.args = [text]
        await cmd_setup(update, ctx)
    else:
        await update.message.reply_text("💡 `/setup <url>` ဖြင့် portal URL ပို့ပါ", parse_mode="Markdown")

def main():
    try:
        logger.info("Bot စတင်နေပါပြီ... (Fast ARP mode)")
        app = ApplicationBuilder().token(TOKEN).build()
        app.add_handler(CommandHandler("start", cmd_start))
        app.add_handler(CommandHandler("setup", cmd_setup))
        app.add_handler(CommandHandler("saved", cmd_saved))
        app.add_handler(CommandHandler("clear", cmd_clear))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
        app.run_polling()
    except Exception as e:
        logger.error(f"Bot crashed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
