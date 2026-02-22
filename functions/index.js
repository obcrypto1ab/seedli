/**
 * Seedli AI Backend
 * Secure, Scalable, Production-Ready
 */

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const ImageKit = require("imagekit");

admin.initializeApp();
const db = admin.firestore();

// Rate Limiting (In-Memory per instance)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 Hour

const checkRateLimit = (ip, type, limit) => {
  const now = Date.now();
  const key = `${ip}_${type}`;
  const record = rateLimitStore.get(key);

  if (!record) {
    rateLimitStore.set(key, { count: 1, start: now });
    return true;
  }

  if (now - record.start > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(key, { count: 1, start: now });
    return true;
  }

  if (record.count >= limit) {
    return false;
  }

  record.count++;
  return true;
};

// App Setup
const app = express();
app.use(express.json());

// CORS Middleware (Dynamic origin check)
app.use(async (req, res, next) => {
  try {
    const settingsSnap = await db.doc("settings/security").get();
    const allowedOrigins = settingsSnap.exists 
      ? (settingsSnap.data().allowedOrigins || []) 
      : [];
    
    // Allow localhost for testing
    allowedOrigins.push("http://localhost:5000");
    allowedOrigins.push("http://127.0.0.1:5500");

    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    
    if (req.method === "OPTIONS") {
      return res.status(200).end();
    }
    next();
  } catch (error) {
    console.error("CORS Error:", error);
    next();
  }
});

// ---------------------------------------------------------
// 1. AI Assistant Endpoint
// ---------------------------------------------------------
app.post("/ask", async (req, res) => {
  const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
  
  // Rate Limit: 20 req/hour
  if (!checkRateLimit(ip, "ask", 20)) {
    return res.status(429).json({ error: "Rate limit exceeded. Try again in an hour." });
  }

  const { question } = req.body;
  if (!question) return res.status(400).json({ error: "Question required" });

  try {
    // Fetch configuration and context
    const [featuresSnap, sourcesSnap, faqSnap] = await Promise.all([
      db.doc("settings/features").get(),
      db.collection("sources").get(),
      db.collection("faq").get()
    ]);

    const features = featuresSnap.data() || {};
    if (!features.aiEnabled) {
      return res.status(503).json({ error: "AI Assistant is currently disabled." });
    }

    // Build Context
    let context = "Official Sources:\n";
    sourcesSnap.forEach(doc => {
      const d = doc.data();
      context += `- ${d.title} (${d.url})\n`;
    });

    context += "\nFAQs:\n";
    faqSnap.forEach(doc => {
      const d = doc.data();
      context += `Q: ${d.question}\nA: ${d.answer}\n`;
    });

    // Gemini Setup
    const genAI = new GoogleGenerativeAI(functions.config().gemini.key);
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });

    let systemPrompt = `You are the Seedli AI Investor Assistant. 
    Use the provided context to answer the user's question. 
    Be professional, concise, and helpful.
    
    CONTEXT:
    ${context}
    `;

    if (features.strictMode) {
      systemPrompt += `\nSTRICT MODE IS ON. 
      If the answer is NOT in the context provided above, strictly reply with: 
      "I cannot find an answer to that in the official documentation. Please verify with the team."
      Do not hallucinate or use outside knowledge.`;
    } else {
      systemPrompt += `\nIf the answer is not in the context, use general financial knowledge but add a disclaimer that this is general info.`;
    }

    const chat = model.startChat({ history: [] });
    const result = await chat.sendMessage(`${systemPrompt}\n\nUser Question: ${question}`);
    const answer = result.response.text();

    // Logging
    await db.collection("logs").add({
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      question,
      answerLength: answer.length,
      ip
    });

    res.json({ answer });

  } catch (error) {
    console.error("AI Error:", error);
    res.status(500).json({ error: "Internal AI Error" });
  }
});

// ---------------------------------------------------------
// 2. Presale Calculator Endpoint
// ---------------------------------------------------------
app.post("/calc", (req, res) => {
  const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
  
  // Rate Limit: 60 req/hour
  if (!checkRateLimit(ip, "calc", 60)) {
    return res.status(429).json({ error: "Rate limit exceeded." });
  }

  const { investmentAmount } = req.body;
  const amount = parseFloat(investmentAmount);

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: "Invalid amount" });
  }

  const PRICE = 0.02;
  const totalTokens = amount / PRICE;
  const tgeUnlock = totalTokens * 0.10; // 10%
  const remaining = totalTokens * 0.90; // 90%
  const vestingMonths = 6;
  const monthlyVest = remaining / vestingMonths;

  const schedule = [];
  
  // TGE
  schedule.push({
    month: "TGE (Immediate)",
    percent: "10%",
    tokens: tgeUnlock.toFixed(2),
    value: (tgeUnlock * PRICE).toFixed(2)
  });

  // Vesting
  for (let i = 1; i <= vestingMonths; i++) {
    schedule.push({
      month: `Month ${i}`,
      percent: `${(90/6).toFixed(1)}%`,
      tokens: monthlyVest.toFixed(2),
      value: (monthlyVest * PRICE).toFixed(2)
    });
  }

  res.json({
    totalTokens: totalTokens.toFixed(2),
    schedule
  });
});

// ---------------------------------------------------------
// 3. ImageKit Auth Endpoint
// ---------------------------------------------------------
app.post("/imagekit/sign", async (req, res) => {
  // Only allow Admin to upload
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized');
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    
    // Verify admin email
    if (decodedToken.email !== "info@seedlicapital.com") {
        return res.status(403).send('Forbidden');
    }

    const imagekit = new ImageKit({
      publicKey: "dummy_public_key_for_constructor", // Not used for signing
      privateKey: functions.config().imagekit.private,
      urlEndpoint: functions.config().imagekit.url
    });

    const authenticationParameters = imagekit.getAuthenticationParameters();
    
    // Return params to frontend so it can upload directly to ImageKit
    res.json({
        ...authenticationParameters,
        publicKey: functions.config().imagekit.public
    });

  } catch (error) {
    console.error("Auth Error", error);
    res.status(401).send('Unauthorized');
  }
});

exports.api = functions.https.onRequest(app);
