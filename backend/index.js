require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const axios = require('axios');
const serverless = require('serverless-http'); // 🧩 Added for Vercel

// === Initialize Firebase Admin ===
const serviceAccount = require('./serviceAccountKey.json'); // now correct relative path
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY;

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();
const app = express();
app.use(express.json());

// ====== CORS ======
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ====== Helpers ======
function requireString(obj, key) {
  return typeof obj[key] === 'string' && obj[key].trim().length > 0;
}

async function verifyFirebaseToken(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ error: 'Missing/invalid Authorization header.' });
    }
    const decoded = await admin.auth().verifyIdToken(parts[1]);
    req.uid = decoded.uid;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// ====== ROUTES ======

// ---- Signup ----
app.post('/api/signup', async (req, res) => {
  try {
    const { fullName, email, password, phone } = req.body || {};

    if (!requireString(req.body, 'fullName') ||
        !requireString(req.body, 'email') ||
        !requireString(req.body, 'password')) {
      return res.status(400).json({ error: 'fullName, email, and password are required.' });
    }

    const userParams = {
      email: email.trim(),
      password,
      displayName: fullName.trim(),
    };

    if (typeof phone === 'string' && /^\+\d{7,15}$/.test(phone.trim())) {
      userParams.phoneNumber = phone.trim();
    }

    const userRecord = await admin.auth().createUser(userParams);

    const profile = {
      uid: userRecord.uid,
      fullName: fullName.trim(),
      email: email.trim(),
      phone: typeof phone === 'string' ? phone.trim() : null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      role: 'user',
      status: 'active',
    };

    try {
      await db.collection('users').doc(userRecord.uid).set(profile, { merge: true });
    } catch (firestoreErr) {
      await admin.auth().deleteUser(userRecord.uid);
      throw firestoreErr;
    }

    return res.status(201).json({
      message: 'Signup successful.',
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName,
        phoneNumber: userRecord.phoneNumber || null,
      },
    });
  } catch (err) {
    if (err && err.code) {
      switch (err.code) {
        case 'auth/email-already-exists':
          return res.status(409).json({ error: 'Email already in use.' });
        case 'auth/invalid-password':
          return res.status(400).json({ error: 'Invalid password.' });
        case 'auth/invalid-email':
          return res.status(400).json({ error: 'Invalid email format.' });
      }
    }
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ---- Login ----
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!requireString(req.body, 'email') || !requireString(req.body, 'password')) {
      return res.status(400).json({ error: 'email and password are required.' });
    }

    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
    const { data } = await axios.post(url, {
      email: email.trim(),
      password,
      returnSecureToken: true,
    });

    const uid = data.localId;
    const userDoc = await db.collection('users').doc(uid).get();
    const profile = userDoc.exists ? userDoc.data() : null;

    return res.status(200).json({
      message: 'Login successful.',
      auth: {
        uid,
        email: data.email,
        idToken: data.idToken,
        refreshToken: data.refreshToken,
        expiresIn: data.expiresIn,
      },
      profile,
    });
  } catch (err) {
    const code = err?.response?.data?.error?.message;
    if (code) {
      switch (code) {
        case 'EMAIL_NOT_FOUND':
          return res.status(404).json({ error: 'Email not found.' });
        case 'INVALID_PASSWORD':
          return res.status(400).json({ error: 'Invalid password.' });
        case 'USER_DISABLED':
          return res.status(403).json({ error: 'User account disabled.' });
      }
    }
    console.error('Login error:', err?.response?.data || err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ---- Bursary Routes ----
app.post('/api/bursaries/click', verifyFirebaseToken, async (req, res) => {
  const { bursaryId } = req.body || {};
  if (!requireString(req.body, 'bursaryId')) {
    return res.status(400).json({ error: 'bursaryId is required.' });
  }
  try {
    const uid = req.uid;
    await db.collection('users')
      .doc(uid)
      .collection('clickedBursaries')
      .doc(bursaryId.trim())
      .set({ clickedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return res.status(201).json({ message: 'Bursary recorded.' });
  } catch (err) {
    console.error('click save error:', err);
    return res.status(500).json({ error: 'Failed to record bursary.' });
  }
});

app.get('/api/bursaries/click', verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const snap = await db.collection('users')
      .doc(uid)
      .collection('clickedBursaries')
      .get();
    const bursaryIds = snap.docs.map(d => d.id);
    return res.status(200).json({ bursaryIds });
  } catch (err) {
    console.error('click list error:', err);
    return res.status(500).json({ error: 'Failed to fetch bursaries.' });
  }
});

// ---- University Routes ----
app.post('/api/universities/click', verifyFirebaseToken, async (req, res) => {
  const { universityId } = req.body || {};
  if (!requireString(req.body, 'universityId')) {
    return res.status(400).json({ error: 'universityId is required.' });
  }
  try {
    const uid = req.uid;
    await db.collection('users')
      .doc(uid)
      .collection('clickedUniversities')
      .doc(universityId.trim())
      .set({ clickedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return res.status(201).json({ message: 'University recorded.' });
  } catch (err) {
    console.error('university click save error:', err);
    return res.status(500).json({ error: 'Failed to record university.' });
  }
});

app.get('/api/universities/click', verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const snap = await db.collection('users')
      .doc(uid)
      .collection('clickedUniversities')
      .get();
    const universityIds = snap.docs.map(d => d.id);
    return res.status(200).json({ universityIds });
  } catch (err) {
    console.error('university click list error:', err);
    return res.status(500).json({ error: 'Failed to fetch universities.' });
  }
});

app.post('/api/universities/applied', verifyFirebaseToken, async (req, res) => {
  const { universityId } = req.body || {};
  if (!requireString(req.body, 'universityId')) {
    return res.status(400).json({ error: 'universityId is required.' });
  }
  try {
    const uid = req.uid;
    const clickedRef = db.collection('users').doc(uid).collection('clickedUniversities').doc(universityId.trim());
    const appliedRef = db.collection('users').doc(uid).collection('appliedUniversities').doc(universityId.trim());

    const batch = db.batch();
    batch.delete(clickedRef);
    batch.set(appliedRef, { appliedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    await batch.commit();

    return res.status(201).json({ message: 'Applied university recorded and clicked entry removed.' });
  } catch (err) {
    console.error('applied university save error:', err);
    return res.status(500).json({ error: 'Failed to record applied university.' });
  }
});

app.get('/api/universities/applied', verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const snap = await db.collection('users')
      .doc(uid)
      .collection('appliedUniversities')
      .get();
    const appliedIds = snap.docs.map(d => d.id);
    return res.status(200).json({ appliedIds });
  } catch (err) {
    console.error('applied university list error:', err);
    return res.status(500).json({ error: 'Failed to fetch applied universities.' });
  }
});

app.get('/api/universities/applied/details', verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const snap = await db.collection('users')
      .doc(uid)
      .collection('appliedUniversities')
      .get();

    const appliedIds = snap.docs.map(d => d.id);
    if (appliedIds.length === 0) {
      return res.status(200).json({ universities: [] });
    }

    const uniDocPromises = appliedIds.map(id => db.collection('universities').doc(id).get());
    const uniDocs = await Promise.all(uniDocPromises);

    const universities = [];
    const missingIds = [];
    uniDocs.forEach((docSnap, idx) => {
      if (!docSnap.exists) missingIds.push(appliedIds[idx]);
      else universities.push({ id: docSnap.id, ...docSnap.data() });
    });

    return res.status(200).json({ universities, missingIds });
  } catch (err) {
    console.error('applied university details error:', err);
    return res.status(500).json({ error: 'Failed to fetch applied universities details.' });
  }
});

// ====== Serverless Export for Vercel ======
module.exports = app;
module.exports.handler = serverless(app);

// ====== Local Run (optional) ======
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Local server running on http://localhost:${PORT}`));
}
