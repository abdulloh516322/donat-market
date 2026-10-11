const express = require("express");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());

const mail = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: (process.env.GMAIL_USER || "").trim(),
    pass: (process.env.GMAIL_PASS || "").replace(/\s+/g, ""),
  },
});
console.log("GMAIL_USER set:", !!process.env.GMAIL_USER, "| GMAIL_PASS set:", !!process.env.GMAIL_PASS, "| SECRET set:", !!process.env.SECRET);
const sign = (email, purpose, exp, code) =>
  crypto.createHmac("sha256", process.env.SECRET)
    .update([email, purpose, exp, code].join("|")).digest("hex");

const lastSend = new Map();   // email -> time (1 daqiqada 1 ta kod)
const tries = new Map();      // token -> urinishlar soni

app.post("/api/send-code", async (req, res) => {
  try {
    const { email, purpose } = req.body || {};
    if (!/^[a-z0-9._+-]+@gmail\.com$/.test(email || "") || !["reg", "reset"].includes(purpose)) {
      return res.status(400).json({ error: "bad request" });
    }
    if (Date.now() - (lastSend.get(email) || 0) < 60000) {
      return res.status(429).json({ error: "wait" });
    }
    lastSend.set(email, Date.now());
    const code = String(crypto.randomInt(100000, 1000000));
    const exp = Date.now() + 10 * 60 * 1000;
    await mail.sendMail({
      from: `Donat Market <${process.env.GMAIL_USER}>`,
      to: email,
      subject: `Tasdiqlash kodi: ${code}`,
      text: `Sizning tasdiqlash kodingiz: ${code}\nKod 10 daqiqa amal qiladi.\nAgar buni siz so'ramagan bo'lsangiz, xatni e'tiborsiz qoldiring.`,
    });
    res.json({ token: `${exp}.${sign(email, purpose, exp, code)}` });
  } catch (e) {
    console.error("SEND ERROR:", e.message);
    res.status(500).json({ error: "send failed" });
  }
});

app.post("/api/verify-code", (req, res) => {
  try {
    const { email, code, token, purpose } = req.body || {};
    const [exp, sig] = String(token || "").split(".");
    const n = (tries.get(token) || 0) + 1;
    tries.set(token, n);
    if (n > 5 || !email || !/^\d{6}$/.test(code || "") || !exp || !sig || Date.now() > Number(exp)) {
      return res.json({ ok: false });
    }
    const good = sign(email, purpose, exp, code);
    const ok = sig.length === good.length &&
      crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
    res.json({ ok });
  } catch (e) {
    res.json({ ok: false });
  }
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "site.html")));
app.listen(process.env.PORT || 3000);
