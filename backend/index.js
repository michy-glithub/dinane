require('dotenv').config(); 
const express = require('express');
const admin = require('firebase-admin');
const axios = require('axios');

const serviceAccount = require('./serviceAccountKey.json'); // your service key in project root

const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY; 

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

const app = express();
app.use(express.json());

// CORS: allow requests from any origin and respond to preflight OPTIONS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');
  // allow preflight
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Helper: basic input check
function requireString(obj, key) {
  return typeof obj[key] === 'string' && obj[key].trim().length > 0;
}

//helper to get the id from the token of the user
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

/**
 * POST /api/signup
 * Body: { fullName, email, password, phone }
 * - Creates Firebase Auth user (email/password, displayName, optional phone if valid E.164)
 * - Creates Firestore profile at users/{uid}
 */
app.post('/api/signup', async (req, res) => {
  try {
    const { fullName, email, password, phone } = req.body || {};

    // Simple validation
    if (!requireString(req.body, 'fullName') ||
        !requireString(req.body, 'email') ||
        !requireString(req.body, 'password')) {
      return res.status(400).json({
        error: 'fullName, email, and password are required.',
      });
    }

    // Create the Auth user
    const userParams = {
      email: email.trim(),
      password: password, // handled/hashed by Firebase Auth — do NOT store in Firestore
      displayName: fullName.trim(),
    };

    // Only set phoneNumber in Auth if it's already E.164 (e.g., +27123456789)
    if (typeof phone === 'string' && /^\+\d{7,15}$/.test(phone.trim())) {
      userParams.phoneNumber = phone.trim();
    }

    const userRecord = await admin.auth().createUser(userParams);

    // Prepare Firestore profile (DO NOT store password)
    const profile = {
      uid: userRecord.uid,
      fullName: fullName.trim(),
      email: email.trim(),
      phone: typeof phone === 'string' ? phone.trim() : null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      // You can add more app-specific fields here:
      role: 'user',
      status: 'active',
    };

    try {
      await db.collection('users').doc(userRecord.uid).set(profile, { merge: true });
    } catch (firestoreErr) {
      // Firestore failed — roll back the Auth user so we don't leave a half-created account
      await admin.auth().deleteUser(userRecord.uid);
      throw firestoreErr;
    }

    // Return safe subset (never return password)
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
    // Nice error mapping for common Firebase Auth errors
    if (err && err.code) {
      switch (err.code) {
        case 'auth/email-already-exists':
          return res.status(409).json({ error: 'Email already in use.' });
        case 'auth/invalid-password':
          return res.status(400).json({ error: 'Invalid password (check length/complexity).' });
        case 'auth/invalid-email':
          return res.status(400).json({ error: 'Invalid email format.' });
        case 'auth/invalid-phone-number':
          return res.status(400).json({ error: 'Invalid phone number (use E.164, e.g., +27123456789).' });
        default:
          // fallthrough to generic
      }
    }
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!requireString(req.body, 'email') || !requireString(req.body, 'password')) {
      return res.status(400).json({ error: 'email and password are required.' });
    }

    // Use Firebase REST API to authenticate
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_WEB_API_KEY}`;
    const { data } = await axios.post(url, {
      email: email.trim(),
      password,
      returnSecureToken: true,
    });

    const uid = data.localId;

    // Fetch Firestore profile
    const userDoc = await db.collection('users').doc(uid).get();
    const profile = userDoc.exists ? userDoc.data() : null;

    return res.status(200).json({
      message: 'Login successful.',
      auth: {
        uid,
        email: data.email,
        idToken: data.idToken,        // client should use this as Bearer token
        refreshToken: data.refreshToken,
        expiresIn: data.expiresIn,    // in seconds
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
        case 'INVALID_LOGIN_CREDENTIALS':
          return res.status(401).json({ error: 'Invalid email or password.' });
        case 'USER_DISABLED':
          return res.status(403).json({ error: 'User account disabled.' });
      }
    }
    console.error('Login error:', err?.response?.data || err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

app.post('/api/bursaries/click', verifyFirebaseToken, async (req, res) => {
  const { bursaryId } = req.body || {};
  if (!requireString(req.body, 'bursaryId')) {
    return res.status(400).json({ error: 'bursaryId is required.' });
  }
  try {
    const uid = req.uid;
    await db
      .collection('users')
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
    const snap = await db
      .collection('users')
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

app.post('/api/universities/click', verifyFirebaseToken, async (req, res) => {
  const { universityId } = req.body || {};
  if (!requireString(req.body, 'universityId')) {
    return res.status(400).json({ error: 'universityId is required.' });
  }
  try {
    const uid = req.uid;
    await db
      .collection('users')
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
    const snap = await db
      .collection('users')
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

// Applied universities: record when a user marks they've applied to a university
app.post('/api/universities/applied', verifyFirebaseToken, async (req, res) => {
  const { universityId } = req.body || {};
  if (!requireString(req.body, 'universityId')) {
    return res.status(400).json({ error: 'universityId is required.' });
  }
  try {
    const uid = req.uid;
    // Move the entry from clickedUniversities -> appliedUniversities atomically
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
    const snap = await db
      .collection('users')
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

// Returns full university documents for the universities the user has applied to
app.get('/api/universities/applied/details', verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const snap = await db
      .collection('users')
      .doc(uid)
      .collection('appliedUniversities')
      .get();

    const appliedIds = snap.docs.map(d => d.id);

    if (appliedIds.length === 0) {
      return res.status(200).json({ universities: [] });
    }

    // Fetch university documents in parallel
    const uniDocPromises = appliedIds.map(id => db.collection('universities').doc(id).get());
    const uniDocs = await Promise.all(uniDocPromises);

    const universities = [];
    const missingIds = [];

    uniDocs.forEach((docSnap, idx) => {
      if (!docSnap.exists) {
        missingIds.push(appliedIds[idx]);
        return;
      }
      universities.push({ id: docSnap.id, ...docSnap.data() });
    });

    return res.status(200).json({ universities, missingIds });
  } catch (err) {
    console.error('applied university details error:', err);
    return res.status(500).json({ error: 'Failed to fetch applied universities details.' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});
