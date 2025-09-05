const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
// Load environment variables from .env if available.  This allows DB_HOST,
// DB_NAME, DB_USER, DB_PASSWORD and other configuration to be specified
// without hard‑coding them in the source.  We resolve the .env file
// relative to this module so deployments can drop their own values in
// the root directory.  If dotenv is not installed, require() will
// simply fail silently and environment variables must be provided
// externally.
try {
  require('dotenv').config({ path: path.join(__dirname, '.env') });
} catch (err) {
  // dotenv is optional.  If not present, environment variables must be set via the host.
}
const crypto = require('crypto');

/*
 * Hearttwin Node.js server without external dependencies.
 *
 * This server implements all required API endpoints using only the built‑in
 * http module.  Static files are served from the public directory.  User
 * data is stored in a JSON file on disk.  Sessions are tracked via a
 * simple cookie mechanism stored in memory.
 */

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
// We no longer store users in a JSON file when a database is
// configured.  The DATA_FILE constant is retained for legacy
// operations and backwards compatibility, but most endpoints now use
// the database wrapper in db.js.
const DATA_FILE = path.join(__dirname, 'users.json');

// Database wrapper.  If the required environment variables (DB_HOST,
// DB_NAME, DB_USER, DB_PASSWORD) are provided, we will persist user
// records to PostgreSQL.  Otherwise the in‑file storage is used as
// fallback.  Note: the init() call is asynchronous and must be
// awaited before processing requests.
const db = require('./db');

// Initialise database if configured.  This call ensures the users
// table exists and an admin account is bootstrapped if necessary.
if (process.env.DB_HOST) {
  db.init().catch(err => {
    console.error('Database initialisation failed:', err);
  });
}

const SMSAPI_TOKEN = 'VynH9qcSPSMHVaRFC0zHWo3Gq4gBWv5i6tCEMtI2';
const OPENAI_TOKEN = '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';

// -----------------------------------------------------------------------------
// Password hashing utilities
//
// To improve security, plain text passwords are never stored directly.  When
// creating a new user or resetting a password, the value is hashed using
// PBKDF2 with a random salt.  The resulting string has the format
// "salt:hash".  During login the provided password is hashed with the
// stored salt and compared to the stored hash.  Old accounts that still
// store plain text passwords are supported: in that case we compare
// directly.

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${derivedKey}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  const parts = stored.split(':');
  if (parts.length !== 2) {
    // Fallback for legacy plain text storage
    return password === stored;
  }
  const [salt, key] = parts;
  const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return key === derivedKey;
}

// -----------------------------------------------------------------------------
// Country group definitions
//
// For matching restrictions, users may only match within predefined
// country groups.  Germany (0049) and Austria (0043) may match each
// other and themselves.  Other countries are restricted to matches
// within their own country.  See README for details.

const COUNTRY_GROUPS = [
  ['0049', '0043'], // Germany & Austria
  ['0041'],        // Switzerland
  ['0033'],        // France
  ['0034'],        // Spain
  ['0046'],        // Sweden
  ['0045'],        // Denmark
  ['0047']         // Norway
];

function inSameCountryGroup(codeA, codeB) {
  return COUNTRY_GROUPS.some(group => group.includes(codeA) && group.includes(codeB));
}

// In‑memory session store: sessionId -> phoneKey
const sessions = {};

// Utility: read JSON body from request
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        const json = JSON.parse(data);
        resolve(json);
      } catch (err) {
        reject(err);
      }
    });
  });
}

// Utility: parse cookies from header
function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const key = parts.shift().trim();
    const value = decodeURIComponent(parts.join('='));
    list[key] = value;
  });
  return list;
}

// Load all users from the configured storage.  When the database is
// available and initialised, this will fetch rows from the users
// table; otherwise it falls back to the JSON file on disk.  The
// admin user is bootstrapped into the database or file if missing.
async function loadUsers() {
  // Attempt DB first
  if (process.env.DB_HOST) {
    try {
      const users = await db.getAllUsers();
      if (users.length === 0) {
        // bootstrap admin user
        const adminUser = {
          countryCode: '0049',
          phone: '112233',
          password: 'AdminHeart123',
          birthDate: '1970-01-01',
          activated: true,
          verificationCode: null,
          resetCode: null,
          locked: false,
          lockedByAdmin: false,
          failedAttempts: 0,
          isAdmin: true,
          profile: null,
          matches: [],
          kiMatches: [],
          chats: {},
          unreadChatCount: {},
          unreadMatches: 0,
          nickname: null,
          nicknameImmutable: false,
          aboutChangedAt: null,
          blocked: [],
          unseenMatches: [],
          unseenKiMatches: [],
          verified: false,
          verificationPending: false,
          paused: false
        };
        await db.createUser(adminUser);
        return [adminUser];
      }
      return users;
    } catch (err) {
      console.error('DB loadUsers error:', err);
      // fall back to file
    }
  }
  // Fallback: file storage
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {
      const adminUser = {
        countryCode: '0049',
        phone: '112233',
        password: 'AdminHeart123',
        birthDate: '1970-01-01',
        activated: true,
        verificationCode: null,
        resetCode: null,
        locked: false,
        lockedByAdmin: false,
        failedAttempts: 0,
        isAdmin: true,
        profile: null,
        matches: [],
        kiMatches: [],
        chats: {},
        unreadChatCount: {},
        unreadMatches: 0,
        nickname: null,
        nicknameImmutable: false,
        aboutChangedAt: null,
        blocked: [],
        unseenMatches: [],
        unseenKiMatches: [],
        verified: false,
        verificationPending: false,
        paused: false
      };
      fs.writeFileSync(DATA_FILE, JSON.stringify([adminUser], null, 2), 'utf8');
      return [adminUser];
    }
    throw err;
  }
}

async function saveUsers(users) {
  // When a database is configured we persist each user record to
  // PostgreSQL.  The database schema uses snake_case column names
  // whereas the rest of the application uses camelCase property
  // names.  To avoid silent failures when inserting/updating we map
  // each camelCase property to its corresponding snake_case key
  // before calling the db helper functions.  If the database is not
  // configured the users.json file is used as a fallback.
  if (process.env.DB_HOST) {
    for (const user of users) {
      // Build a new object with snake_case keys for the database.
      // Undefined fields are preserved as undefined so that
      // db.updateUser() can skip them when constructing the SET clause.
      const dbUser = {
        country_code: user.countryCode,
        phone: user.phone,
        password: user.password,
        birth_date: user.birthDate,
        activated: user.activated,
        verification_code: user.verificationCode,
        reset_code: user.resetCode,
        locked: user.locked,
        locked_by_admin: user.lockedByAdmin,
        failed_attempts: user.failedAttempts,
        is_admin: user.isAdmin,
        profile: user.profile,
        matches: user.matches,
        ki_matches: user.kiMatches,
        chats: user.chats,
        unread_chat_count: user.unreadChatCount,
        unread_matches: user.unreadMatches,
        nickname: user.nickname,
        nickname_immutable: user.nicknameImmutable,
        about_changed_at: user.aboutChangedAt,
        blocked: user.blocked,
        unseen_matches: user.unseenMatches,
        unseen_ki_matches: user.unseenKiMatches,
        verified: user.verified,
        verification_pending: user.verificationPending,
        paused: user.paused,
        // Include created_at if present; if undefined it will be
        // omitted on insert/update and the database default will be used.
        created_at: user.createdAt
      };
      const existing = await db.getUserByPhone(dbUser.country_code, dbUser.phone);
      if (existing) {
        await db.updateUser(dbUser);
      } else {
        await db.createUser(dbUser);
      }
    }
    return;
  }
  // Fallback: write all users to the JSON file on disk.  This path
  // should only be reached when DB_HOST is not defined.  It retains
  // backwards compatibility for installations that do not use
  // PostgreSQL.
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// -----------------------------------------------------------------------------
// Preserve the original saveUsers implementation.
//
// We assign the current value of saveUsers to __originalSaveUsers after the
// function has been defined.  This allows request-scoped overrides in
// handleRequest() to call the original function without triggering
// ReferenceError (temporal dead zone) or recursion.  Do not move this
// declaration above saveUsers.
const __originalSaveUsers = saveUsers;

function generateSmsCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendSms(phoneNumber, message) {
  try {
    let recipient = phoneNumber;
    if (recipient.startsWith('00')) {
      recipient = '+' + recipient.substring(2);
    } else if (!recipient.startsWith('+')) {
      recipient = '+' + recipient;
    }
    // Compose the request body.  Set test=0 to ensure the message is actually
    // sent rather than executed in test mode.  According to the SMSAPI docs
    // parameter `test=1` causes messages to be processed without delivery and
    // without charging any credits.  We explicitly set `test=0` so that
    // messages are delivered and account credits are deducted.  The sender
    // name should be a verified sender name in your SMSAPI account.  If you
    // haven't registered a custom sender, leave it blank and SMSAPI will
    // provide a default sender ID.
    // Compose the request body without a 'from' field.  Many SMSAPI accounts
    // require that you register a sender name before using it in the `from`
    // parameter.  If an unregistered sender name is supplied, the API will
    // return "Invalid from field" and no SMS will be delivered.  By omitting
    // the `from` parameter, SMSAPI will use the default sender ID for your
    // account.  We also set `test=0` to ensure the message is actually sent.
    const params = new url.URLSearchParams({
      to: recipient,
      message,
      test: '0'
    });
    const options = {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${SMSAPI_TOKEN}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    };
    const https = require('https');
    await new Promise((resolve) => {
      const req = https.request('https://api.smsapi.com/sms.do', options, res => {
        res.on('data', () => {});
        res.on('end', resolve);
      });
      req.on('error', (err) => { console.error('SMSAPI Error:', err); resolve(); });
      req.write(params.toString());
      req.end();
    });
  } catch (err) {
    console.error('Fehler beim Senden der SMS:', err);
  }
}

function sendJson(res, status, obj) {
  const data = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(data);
}

function calculateAge(birthDateStr) {
  const today = new Date();
  const birthDate = new Date(birthDateStr);
  let age = today.getFullYear() - birthDate.getFullYear();
  const m = today.getMonth() - birthDate.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age;
}

function generateSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

// global reports list
const reports = [];

// Utility: compute Levenshtein distance similarity
function areWordsSimilar(a, b) {
  a = a.toLowerCase();
  b = b.toLowerCase();
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 2) return false;
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[a.length][b.length] <= 2;
}

// Fallback: computes a rough compatibility score (0–10) based on simple keyword overlap
function fallbackCompatibility(textA, textB) {
  const t1 = (textA || '').toLowerCase();
  const t2 = (textB || '').toLowerCase();
  let count = 0;
  // Religion / Glaube: gemeinsame Erwähnung von Koran/Koranit/Hadith/Hadithe etc.
  const groupRel = /(koran|koranit|quran|hadith|hadithe|sunni|shia|islam)/;
  if (groupRel.test(t1) && groupRel.test(t2)) count++;
  // Natur / Wandern / Berge / Outdoor
  const groupNature = /(wander|wandern|berge|berg|natur|outdoor|hiking)/;
  if (groupNature.test(t1) && groupNature.test(t2)) count++;
  // Musik / Hobbys / Sport (gemeinsame Erwähnung generischer Stichworte)
  const groupHobby = /(musik|sport|hobby|hobbys|hobbys|essen|kochen)/;
  if (groupHobby.test(t1) && groupHobby.test(t2)) count++;
  // Each matched group contributes 4 points; cap at 10
  const score = Math.min(10, count * 4 + 2);
  return score;
}

// Synonym groups to detect additional semantic overlaps between two texts.
// If both texts contain at least one word from the same group, we award a small bonus.
// This helps catch cases where different words convey similar meanings (e.g. "Adrenalin" and "Achterbahn").
// Synonym groups for bonus scoring.
// Each array contains words/phrases that we consider semantically related. When both texts
// contain at least one term from the same group, a bonus point is added to the AI score.
const SYNONYM_GROUPS = [
  // Peace and pacifism
  ['frieden', 'friedlich', 'pazifist', 'pazifismus', 'friedensliebe', 'friedensliebend'],
  // Meat, steaks and burgers
  ['fleisch', 'steak', 'steaks', 'burger', 'hamburger', 'mcdonalds', 'fastfood', 'fleischliebhaber'],
  // Poetry and classical literature
  ['poesie', 'poetry', 'dichtung', 'literatur', 'lyrik', 'gedichte', 'goethe', 'schiller', 'poetisch'],
  // Thrill seeking / adrenaline / speed / roller coasters
  ['adrenalin', 'adrenaline', 'achterbahn', 'achterbahnen', 'thrill', 'schnell', 'autofahren', 'rennwagen', 'racing'],
  // Reading / books
  ['lesen', 'lese', 'leser', 'buch', 'bücher', 'bibliothek'],
  // Plant‑based / organic / healthy eating
  ['obst', 'pflanzlich', 'pflanzliches', 'bio', 'vegan', 'vegetarisch', 'vegetarier', 'vegane', 'früchte'],
  // Sport und Fitness
  ['sport', 'sportarten', 'fitness', 'laufen', 'joggen', 'gym', 'training', 'yoga', 'pilates', 'bodybuilding', 'marathon'],
  // Cooking and food
  ['kochen', 'backen', 'essen', 'rezept', 'rezepte', 'koch', 'küche', 'spaghetti', 'nudeln', 'bolognese', 'lasagne', 'pizza'],
  // Traditional roles and emotional traits
  ['hausfrau', 'hausfrauen', 'familie', 'traditionell', 'traditionelle', 'beziehung', 'beziehungen', 'mitgefühl', 'emotional', 'gefühle', 'gute hausfrau'],
  // Travel and seeing the world
  ['reisen', 'verreisen', 'welt', 'sehen', 'urlaub', 'reise', 'welt sehen']
];

/**
 * Compute a bonus score based on shared synonym groups between two texts.
 * For each defined synonym group, if both texts contain at least one keyword from that group,
 * increment the bonus. The final bonus equals the number of matching groups.
 *
 * @param {string} textA
 * @param {string} textB
 * @returns {number} bonus points to add to the AI score
 */
function computeSynonymBonus(textA, textB) {
  const t1 = (textA || '').toLowerCase();
  const t2 = (textB || '').toLowerCase();
  let bonus = 0;
  for (const group of SYNONYM_GROUPS) {
    let has1 = false;
    let has2 = false;
    for (const word of group) {
      if (!has1 && t1.includes(word)) has1 = true;
      if (!has2 && t2.includes(word)) has2 = true;
      if (has1 && has2) {
        bonus += 1;
        break;
      }
    }
  }
  return bonus;
}

// Main request handler
async function handleRequest(req, res) {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();
  // Load all users once per request.  When a database is configured
  // this call fetches the current snapshot into memory.  We cache
  // this array in the closure and provide helper functions to read
  // and persist changes.
  const users = await loadUsers();
  const getUsers = () => users;
  // In this request scope we operate on the `users` array loaded above.
  // The top-level saveUsers(users) function persists the current array
  // to disk or database.  Because we have updated all call sites to
  // invoke `await saveUsers(users)` directly, we no longer override
  // saveUsers here.  Any modifications to the `users` array should be
  // followed by `await saveUsers(users)` to persist the changes.

  // Attach user from session
  const cookies = parseCookies(req.headers.cookie || '');
  let currentUser = null;
  if (cookies.session && sessions[cookies.session]) {
    const phoneKey = sessions[cookies.session];
    const u = users.find(user => user.countryCode + user.phone === phoneKey);
    if (u) currentUser = u;
  }
  // Helper to set cookie
  function setSessionCookie(sessionId) {
    res.setHeader('Set-Cookie', `session=${sessionId}; HttpOnly; Path=/`);
  }
  // Route: Static files
  if (!pathname.startsWith('/api')) {
    // serve file or fallback to index.html
    let filePath = path.join(PUBLIC_DIR, decodeURIComponent(pathname));
    if (filePath.endsWith('/')) filePath = path.join(filePath, 'index.html');
    // prevent directory traversal
    if (!filePath.startsWith(PUBLIC_DIR)) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }
    fs.stat(filePath, (err, stats) => {
      if (err || !stats.isFile()) {
        // fallback to index.html for SPA
        filePath = path.join(PUBLIC_DIR, 'index.html');
      }
      fs.readFile(filePath, (err2, data) => {
        if (err2) {
          res.writeHead(500);
          res.end('Internal Server Error');
          return;
        }
        const ext = path.extname(filePath).toLowerCase();
        const mimeTypes = {
          '.html': 'text/html',
          '.js': 'application/javascript',
          '.css': 'text/css',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.jpeg': 'image/jpeg',
          '.svg': 'image/svg+xml'
        };
        const contentType = mimeTypes[ext] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
      });
    });
    return;
  }
  // API routes
  if (method === 'POST' && pathname === '/api/register') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone, birthDate, password, confirmPassword, paymentDone, nickname, region } = body;
    if (!countryCode || !phone || !birthDate || !password || !confirmPassword) {
      return sendJson(res, 400, { error: 'Alle Felder müssen ausgefüllt werden.' });
    }
    if (!paymentDone) {
      return sendJson(res, 400, { error: 'Bezahlvorgang nicht abgeschlossen.' });
    }

    // Nickname validation
    if (!nickname || typeof nickname !== 'string' || !nickname.trim()) {
      return sendJson(res, 400, { error: 'Nickname ist erforderlich.' });
    }
    const nick = nickname.trim();
    if (nick.length > 30) {
      return sendJson(res, 400, { error: 'Nickname darf höchstens 30 Zeichen lang sein.' });
    }
    // Permit registration for Germany (0049), Austria (0043), Switzerland (0041), France (0033), Spain (0034), Sweden (0046), Denmark (0045) and Norway (0047)
    if (!['0049','0043','0041','0033','0034','0046','0045','0047'].includes(countryCode)) {
      return sendJson(res, 400, { error: 'Ungültige Vorwahl.' });
    }
    if (!/^\d{6,15}$/.test(phone)) {
      return sendJson(res, 400, { error: 'Ungültige Telefonnummer.' });
    }
    const age = calculateAge(birthDate);
    if (age < 18) {
      return sendJson(res, 400, { error: 'Du bist zu jung, Mindestalter ist 18.' });
    }
    if (password.length < 8 || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      return sendJson(res, 400, { error: 'Passwort muss mindestens 8 Zeichen, einen Großbuchstaben und eine Zahl enthalten.' });
    }
    if (password !== confirmPassword) {
      return sendJson(res, 400, { error: 'Passwörter stimmen nicht überein.' });
    }

    // Validate region (Bundesland/Kanton etc.).  The client must provide a non-empty
    // string identifying the regional subdivision.  Without this, registration
    // cannot proceed.  We trim whitespace to avoid storing accidental spaces.
    if (!region || typeof region !== 'string' || !region.trim()) {
      return sendJson(res, 400, { error: 'Region (Bundesland/Kanton etc.) ist erforderlich.' });
    }
    const regionValue = region.trim();
    const users = getUsers();
    const existing = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (existing) {
      return sendJson(res, 400, { error: 'Diese Telefonnummer ist bereits registriert.' });
    }
    // Prüfe Nickname‑Einzigartigkeit (case‑insensitive)
    const existingNick = users.find(u => u.nickname && u.nickname.toLowerCase() === nick.toLowerCase());
    if (existingNick) {
      return sendJson(res, 400, { error: 'Dieser Nickname ist bereits vergeben.' });
    }
    const verificationCode = generateSmsCode();
    const newUser = {
      countryCode,
      phone,
      // Store hashed password to avoid keeping plain text in storage
      password: hashPassword(password),
      birthDate,
      activated: false,
      verificationCode,
      resetCode: null,
      locked: false,
      failedAttempts: 0,
      isAdmin: false,
      // Save the selected region in the profile so that the user's location
      // is persisted even before they complete their full profile.
      profile: { location: regionValue },
      matches: [],
      kiMatches: [],
      chats: {},
      unreadChatCount: {},
      unreadMatches: 0,
      nickname: nick,
      nicknameImmutable: true,
      aboutChangedAt: null,
      blocked: [],
      unseenMatches: [],
      unseenKiMatches: [],
      verified: false,
      verificationPending: false,
      paused: false
    };
    users.push(newUser);
    await saveUsers(users);
    const fullNumber = `${countryCode}${phone}`;
    await sendSms(fullNumber, `Ihr Hearttwin Bestätigungscode lautet: ${verificationCode}`);
    return sendJson(res, 200, { success: true, message: 'SMS mit Bestätigungscode wurde gesendet.' });
  }
  if (method === 'POST' && pathname === '/api/verify-code') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone, code } = body;
    const users = getUsers();
    const user = users.find(u => u.countryCode === countryCode && u.phone === phone);
    // Wenn kein Benutzer gefunden wurde, antworten wir mit dem gleichen Fehler wie bei falschem Code.
    // Für den Benutzer ist es irrelevant, ob die Nummer oder der Code nicht stimmt.
    if (!user) {
      return sendJson(res, 400, { error: 'Falscher Bestätigungscode.' });
    }
    if (user.activated) return sendJson(res, 400, { error: 'Dieser Account ist bereits aktiviert.' });
    if (user.verificationCode !== code) return sendJson(res, 400, { error: 'Falscher Bestätigungscode.' });
    user.activated = true;
    user.verificationCode = null;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'POST' && pathname === '/api/login') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone, password } = body;
    const users = getUsers();
    const user = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (!user) return sendJson(res, 400, { error: 'Benutzer nicht gefunden.' });
    // Wenn das Konto dauerhaft durch einen Administrator gesperrt wurde,
    // erlauben wir weder Login noch Passwort‑Zurücksetzung.  Für
    // temporäre Sperren aufgrund mehrerer Fehlversuche wird eine
    // entsprechende Fehlermeldung mit Hinweis auf die Reset‑Funktion
    // ausgegeben.
    if (user.locked) {
      if (user.lockedByAdmin) {
        return sendJson(res, 400, { error: 'Konto ist gesperrt. Bitte wende dich an den Support.' });
      }
      return sendJson(res, 400, { error: 'Konto ist gesperrt. Bitte setze dein Passwort über die „Passwort vergessen“-Funktion mit deiner Telefonnummer zurück.' });
    }
    if (!user.activated) return sendJson(res, 400, { error: 'Konto ist noch nicht aktiviert.' });
    // Use constant‑time password verification.  The stored password may be
    // in the legacy plain text format or the new salt:hash format.  The
    // verifyPassword helper handles both cases.  Increase failed attempts
    // and lock the account after too many failures.
    if (!verifyPassword(password, user.password)) {
      user.failedAttempts = (user.failedAttempts || 0) + 1;
      if (user.failedAttempts >= 5) {
        user.locked = true;
      }
      await saveUsers(users);
      return sendJson(res, 400, { error: 'Falsches Passwort.' });
    }
    // Automatically unpause user on successful login
    if (user.paused) {
      user.paused = false;
      // do not save here; will save after resetting failed attempts
    }
    user.failedAttempts = 0;
    await saveUsers(users);
    const sessionId = generateSessionId();
    sessions[sessionId] = user.countryCode + user.phone;
    setSessionCookie(sessionId);
    return sendJson(res, 200, { success: true, isAdmin: user.isAdmin, hasProfile: !!user.profile, verified: user.verified, newMatches: user.unreadMatches });
  }
  if (method === 'POST' && pathname === '/api/logout') {
    if (cookies.session) delete sessions[cookies.session];
    res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/');
    return sendJson(res, 200, { success: true });
  }
  if (method === 'POST' && pathname === '/api/forgot') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone } = body;
    const users = getUsers();
    const user = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (!user) {
      return sendJson(res, 400, { error: 'Benutzer nicht gefunden' });
    }
    // Dauerhaft gesperrte Konten dürfen keine Passwort‑Zurücksetzungen
    // durchführen.
    if (user.lockedByAdmin) {
      return sendJson(res, 400, { error: 'Konto ist gesperrt. Passwort zurücksetzen nicht möglich.' });
    }
    const resetCode = generateSmsCode();
    user.resetCode = resetCode;
    await saveUsers(users);
    const fullNumber = `${user.countryCode}${user.phone}`;
    await sendSms(fullNumber, `Ihr Hearttwin Rücksetzcode lautet: ${resetCode}`);
    return sendJson(res, 200, { success: true });
  }

  // API zum Aktualisieren der Telefonnummer nach der PayPal‑Zahlung, aber vor der Aktivierung.
  // Der Benutzer kann seine Nummer ändern, falls er sie falsch eingegeben hat. Es wird ein neuer
  // Bestätigungscode an die neue Nummer gesendet. Sessions werden entsprechend aktualisiert.
  if (method === 'POST' && pathname === '/api/update-phone') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { oldCountryCode, oldPhone, newCountryCode, newPhone } = body;
    if (!oldCountryCode || !oldPhone || !newCountryCode || !newPhone) {
      return sendJson(res, 400, { error: 'Ungültige Parameter' });
    }
    const users = getUsers();
    const user = users.find(u => u.countryCode === oldCountryCode && u.phone === oldPhone);
    if (!user) return sendJson(res, 400, { error: 'Benutzer nicht gefunden' });
    if (user.activated) return sendJson(res, 400, { error: 'Konto ist bereits aktiviert' });
    // Prüfe, ob die neue Telefonnummer bereits verwendet wird
    const exists = users.find(u => u.countryCode === newCountryCode && u.phone === newPhone);
    if (exists) return sendJson(res, 400, { error: 'Diese Telefonnummer wird bereits verwendet' });
    // Aktualisiere Telefonnummer und Vorwahl
    user.countryCode = newCountryCode;
    user.phone = newPhone;
    // Neuer Bestätigungscode
    const newCode = generateSmsCode();
    user.verificationCode = newCode;
    await saveUsers(users);
    // Aktualisiere Session‑Mapping, damit der Benutzer weiterhin eingeloggt bleibt
    const oldKey = oldCountryCode + oldPhone;
    const newKey = newCountryCode + newPhone;
    for (const sid in sessions) {
      if (sessions[sid] === oldKey) {
        sessions[sid] = newKey;
      }
    }
    const fullNumber = `${newCountryCode}${newPhone}`;
    await sendSms(fullNumber, `Ihr Hearttwin Bestätigungscode lautet: ${newCode}`);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'POST' && pathname === '/api/reset') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone, code, newPassword, confirmPassword } = body;
    const users = getUsers();
    const user = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (!user) return sendJson(res, 400, { error: 'Benutzer nicht gefunden' });
    // Auch bei gültigem Code darf das Passwort nicht zurückgesetzt werden,
    // wenn das Konto dauerhaft durch einen Administrator gesperrt wurde.
    if (user.lockedByAdmin) {
      return sendJson(res, 400, { error: 'Konto ist gesperrt. Passwort zurücksetzen nicht möglich.' });
    }
    if (!user.resetCode || user.resetCode !== code) return sendJson(res, 400, { error: 'Falscher oder abgelaufener Rücksetzcode' });
    if (newPassword.length < 8 || !/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return sendJson(res, 400, { error: 'Neues Passwort erfüllt nicht die Sicherheitsanforderungen' });
    }
    if (newPassword !== confirmPassword) {
      return sendJson(res, 400, { error: 'Passwörter stimmen nicht überein' });
    }
    // Hash the new password so that only the salt:hash is stored
    user.password = hashPassword(newPassword);
    user.resetCode = null;
    // Nur dann entsperren, wenn die Sperre nicht durch einen Administrator
    // veranlasst wurde.  In diesem Fall bleibt `locked` weiterhin wahr.
    if (!user.lockedByAdmin) {
      user.locked = false;
    }
    user.failedAttempts = 0;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'GET' && pathname === '/api/profile') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    if (!currentUser.activated) return sendJson(res, 403, { error: 'Konto nicht aktiviert' });
    return sendJson(res, 200, {
      profile: currentUser.profile,
      verified: currentUser.verified,
      verificationPending: currentUser.verificationPending,
      nickname: currentUser.nickname
    });
  }
  if (method === 'POST' && pathname === '/api/profile') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    if (!currentUser.activated) return sendJson(res, 403, { error: 'Konto nicht aktiviert' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { location, gender, religionGroup, religionSub, interests, about, showInProfile, nickname } = body;
    if (!location || !gender || !religionGroup || !Array.isArray(interests)) {
      return sendJson(res, 400, { error: 'Bitte alle Pflichtfelder ausfüllen.' });
    }
    // Prevent gender change: once a gender has been set, it cannot be changed later
    if (currentUser.profile && currentUser.profile.gender && currentUser.profile.gender !== gender) {
      return sendJson(res, 400, { error: 'Geschlecht kann nicht geändert werden.' });
    }

    // Nickname erforderlich
    if (!nickname || typeof nickname !== 'string' || !nickname.trim()) {
      return sendJson(res, 400, { error: 'Ein Nickname ist erforderlich.' });
    }
    const nick = nickname.trim();
    if (nick.length > 30) {
      return sendJson(res, 400, { error: 'Nickname darf höchstens 30 Zeichen lang sein.' });
    }
    // Prüfe Nickname‑Einzigartigkeit (case‑insensitive)
const users = getUsers();
    // Wenn Benutzer bereits einen Nickname hat und dieser unveränderbar ist, keine Änderung zulassen
    if (currentUser.nickname && currentUser.nicknameImmutable) {
      if (nick.toLowerCase() !== currentUser.nickname.toLowerCase()) {
        return sendJson(res, 400, { error: 'Dein Nickname kann nicht geändert werden.' });
      }
    }
    const existingNick = users.find(u => u.nickname && u.nickname.toLowerCase() === nick.toLowerCase());
    if (existingNick && existingNick.countryCode + existingNick.phone !== currentUser.countryCode + currentUser.phone) {
      return sendJson(res, 400, { error: 'Dieser Nickname ist bereits vergeben.' });
    }
    if (interests.length < 20 || interests.length > 20) {
      return sendJson(res, 400, { error: 'Genau 20 Interessen müssen angegeben werden.' });
    }
    const cleanedInterests = interests.map(i => String(i).trim()).filter(i => i);
    if (cleanedInterests.length !== 20) {
      return sendJson(res, 400, { error: 'Alle 20 Interessen müssen gültig sein.' });
    }
    let aboutText = about || '';
    // Der „Über dich“-Text ist jetzt Pflicht und muss zwischen 20 und 200 Zeichen liegen.
    if (aboutText.length < 20) {
      return sendJson(res, 400, { error: 'Der „Über mich“-Text muss mindestens 20 Zeichen enthalten.' });
    }
    if (aboutText.length > 200) {
      return sendJson(res, 400, { error: 'Der „Über mich“-Text darf maximal 200 Zeichen enthalten.' });
    }
    // 'Über mich' Text darf nur einmal pro Monat geändert werden
    const now = new Date();
    // Determine if about text is changing compared to existing profile
    const prevAbout = currentUser.profile && currentUser.profile.about ? currentUser.profile.about : '';
    const aboutChanging = aboutText !== prevAbout;
    if (aboutChanging) {
      if (currentUser.aboutChangedAt) {
        const lastChanged = new Date(currentUser.aboutChangedAt);
        const diffMs = now - lastChanged;
        const diffDays = diffMs / (1000 * 60 * 60 * 24);
        if (diffDays < 30) {
          return sendJson(res, 400, { error: 'Der „Über mich“-Text kann nur einmal im Monat geändert werden.' });
        }
      }
      // update aboutChangedAt timestamp since it will change
      currentUser.aboutChangedAt = now.toISOString();
    }
    // Set nickname if not set; once set, mark as immutable
    if (!currentUser.nickname) {
      currentUser.nickname = nick;
      currentUser.nicknameImmutable = true;
    }
    // Build profile object
    currentUser.profile = {
      location,
      gender,
      religion: { group: religionGroup, sub: religionSub || null },
      interests: cleanedInterests,
      about: aboutText
      // `showInProfile` wird nicht mehr verwendet, da der Über‑dich‑Text stets angezeigt wird
    };
    currentUser.unreadMatches = 0;
    // save back
    const idx = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    users[idx] = currentUser;
    // Persist the updated users array
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'GET' && pathname === '/api/me') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    return sendJson(res, 200, {
      countryCode: currentUser.countryCode,
      phone: currentUser.phone,
      isAdmin: currentUser.isAdmin,
      hasProfile: !!currentUser.profile,
      verified: currentUser.verified
    });
  }
  if (method === 'GET' && pathname === '/api/birth') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    return sendJson(res, 200, { birthDate: currentUser.birthDate });
  }
  if (method === 'POST' && pathname === '/api/match') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    if (!currentUser.profile) return sendJson(res, 400, { error: 'Profil ist unvollständig' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { verifiedOnly } = body;
    const users = getUsers();
    const myKey = currentUser.countryCode + currentUser.phone;
    const myGender = currentUser.profile.gender;
    const desiredGender = myGender === 'M' ? 'W' : 'M';
    const myInterests = currentUser.profile.interests;
    let newMatches = [];
    for (const other of users) {
      if (other.countryCode + other.phone === myKey) continue;
      if (other.isAdmin) continue;
      // Skip users whose profile is paused
      if (other.paused) continue;
      if (!other.activated || other.locked) continue;
      if (!other.profile) continue;
      if (other.profile.gender !== desiredGender) continue;
      // Restrict matching to the same country group.  Germany and Austria may
      // match each other; all other countries can only match within their own
      // national group.
      if (!inSameCountryGroup(currentUser.countryCode, other.countryCode)) {
        continue;
      }
      if (verifiedOnly && (!currentUser.verified || !other.verified)) continue;
      if (currentUser.matches.includes(other.countryCode + other.phone)) continue;
      // Skip if either side has blocked the other
      if ((currentUser.blocked && currentUser.blocked.includes(other.countryCode + other.phone)) || (other.blocked && other.blocked.includes(myKey))) continue;
      let similarCount = 0;
      for (const myInt of myInterests) {
        for (const oInt of other.profile.interests) {
          if (areWordsSimilar(myInt, oInt)) {
            similarCount++;
            break;
          }
        }
      }
      if (similarCount >= 8) {
        currentUser.matches.push(other.countryCode + other.phone);
        other.matches.push(myKey);
        // Mark as unseen for both users
        if (!currentUser.unseenMatches) currentUser.unseenMatches = [];
        if (!currentUser.unseenMatches.includes(other.countryCode + other.phone)) {
          currentUser.unseenMatches.push(other.countryCode + other.phone);
        }
        if (!other.unseenMatches) other.unseenMatches = [];
        if (!other.unseenMatches.includes(myKey)) {
          other.unseenMatches.push(myKey);
        }
        if (!currentUser.chats[other.countryCode + other.phone]) {
          currentUser.chats[other.countryCode + other.phone] = { messages: [], reported: false };
          currentUser.unreadChatCount[other.countryCode + other.phone] = 0;
        }
        if (!other.chats[myKey]) {
          other.chats[myKey] = { messages: [], reported: false };
          other.unreadChatCount[myKey] = 0;
        }
        newMatches.push({ phone: other.countryCode + other.phone, ki: false, verified: currentUser.verified && other.verified });
      }
    }
    currentUser.unreadMatches += newMatches.length;
    // Update current user in users array before saving
    const meIdx = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    if (meIdx >= 0) users[meIdx] = currentUser;
    // Persist the updated users array after modifying matches
    await saveUsers(users);
    return sendJson(res, 200, { success: true, matches: newMatches });
  }
  if (method === 'POST' && pathname === '/api/ki-match') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    if (!currentUser.profile) return sendJson(res, 400, { error: 'Profil ist unvollständig' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { verifiedOnly } = body;
    if (!currentUser.profile.about || !currentUser.profile.about.trim()) {
      return sendJson(res, 400, { error: 'Du hast keinen Text für das KI‑Matching eingegeben.' });
    }
    const desiredGender = currentUser.profile.gender === 'M' ? 'W' : 'M';
    const users = getUsers();
    const myKey = currentUser.countryCode + currentUser.phone;
    let newMatches = [];
    for (const other of users) {
      if (other.countryCode + other.phone === myKey) continue;
      if (other.isAdmin) continue;
      // Skip users whose profile is paused
      if (other.paused) continue;
      if (!other.activated || other.locked) continue;
      if (!other.profile) continue;
      if (other.profile.gender !== desiredGender) continue;
      // Restrict matching to the same country group as defined in COUNTRY_GROUPS.
      if (!inSameCountryGroup(currentUser.countryCode, other.countryCode)) {
        continue;
      }
      if (verifiedOnly && (!currentUser.verified || !other.verified)) continue;
      if (currentUser.kiMatches.includes(other.countryCode + other.phone)) continue;
      // Skip if either side has blocked the other
      if ((currentUser.blocked && currentUser.blocked.includes(other.countryCode + other.phone)) || (other.blocked && other.blocked.includes(myKey))) continue;
      if (!other.profile.about || !other.profile.about.trim()) continue;
      const messages = [
        {
          role: 'system',
          content:
            'Du bist ein strenger Matching‑Algorithmus (Level 8 von 10) für eine Dating‑Plattform. Du erhältst die Beschreibungen zweier Personen. ' +
            'Analysiere alle Aspekte dieser Beschreibungen – Interessen, Hobbys, Charaktereigenschaften, Werte, Lebensstil, religiöse oder weltanschauliche Überzeugungen, familiäre Rollen, Emotionen sowie Reisen und Freizeit – und ermittle, wie gut die beiden Personen zueinander passen. ' +
            'Eine 10 steht für perfekte Übereinstimmung (sehr viele gemeinsame Interessen, Werte und Lebensziele), 1 bedeutet keine Übereinstimmung. Gib eine 8 oder höher nur bei wirklich großer Ähnlichkeit. ' +
            'Wenn eine oder beide Personen nur wenige Details teilen, bewerte sie streng anhand der vorhandenen Merkmale. Antworte ausschließlich mit einer einzelnen Zahl von 1 bis 10.'
        },
        {
          role: 'user',
          content: `Person A: ${currentUser.profile.about}\nPerson B: ${other.profile.about}\nBewerte ihre Kompatibilität auf einer Skala von 1 bis 10 und antworte nur mit der Zahl.`
        }
      ];
      let aiScore = null;
      try {
        const https = require('https');
        const reqOptions = {
          method: 'POST',
          hostname: 'api.openai.com',
          path: '/v1/chat/completions',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${OPENAI_TOKEN}`
          }
        };
        const respData = await new Promise((resolve) => {
          const r = https.request(reqOptions, res2 => {
            let data = '';
            res2.on('data', chunk => { data += chunk; });
            res2.on('end', () => resolve(data));
          });
          r.on('error', err => { resolve(null); });
          const bodyData = JSON.stringify({ model: 'gpt-3.5-turbo', messages, temperature: 0.2, max_tokens: 10 });
          r.write(bodyData);
          r.end();
        });
        if (respData) {
          const parsed = JSON.parse(respData);
          const content = parsed.choices && parsed.choices[0] && parsed.choices[0].message && parsed.choices[0].message.content;
          const s = parseFloat(content);
          if (!isNaN(s)) aiScore = s;
        }
      } catch (err) {
        // Wenn der Aufruf fehlschlägt, aiScore bleibt null
        console.error('KI‑Match Fehler:', err);
      }
      // Falls keine brauchbare AI‑Bewertung vorliegt, verwende Fallback
      let scoreToUse;
      if (aiScore === null || isNaN(aiScore)) {
        scoreToUse = fallbackCompatibility(currentUser.profile.about, other.profile.about);
      } else {
        scoreToUse = aiScore;
      }
      // Instead of applying per‑category bonuses, apply a constant gentle bonus to every evaluation.
      // This makes the system slightly less strict overall while avoiding hard‑coded synonym groups.
      scoreToUse += 1.5;
      // A match is created if the final score meets or exceeds the threshold.
      if (scoreToUse >= 7) {
        currentUser.kiMatches.push(other.countryCode + other.phone);
        other.kiMatches.push(myKey);
        if (!currentUser.chats[other.countryCode + other.phone]) {
          currentUser.chats[other.countryCode + other.phone] = { messages: [], reported: false };
          currentUser.unreadChatCount[other.countryCode + other.phone] = 0;
        }
        if (!other.chats[myKey]) {
          other.chats[myKey] = { messages: [], reported: false };
          other.unreadChatCount[myKey] = 0;
        }
        // Mark as unseen KI match for both users
        if (!currentUser.unseenKiMatches) currentUser.unseenKiMatches = [];
        if (!currentUser.unseenKiMatches.includes(other.countryCode + other.phone)) {
          currentUser.unseenKiMatches.push(other.countryCode + other.phone);
        }
        if (!other.unseenKiMatches) other.unseenKiMatches = [];
        if (!other.unseenKiMatches.includes(myKey)) {
          other.unseenKiMatches.push(myKey);
        }
        newMatches.push({ phone: other.countryCode + other.phone, ki: true, verified: currentUser.verified && other.verified });
      }
    }
    currentUser.unreadMatches += newMatches.length;
    // Update current user in users array before saving
    const meIdx2 = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    if (meIdx2 >= 0) users[meIdx2] = currentUser;
    await saveUsers(users);
    return sendJson(res, 200, { success: true, matches: newMatches });
  }
  if (method === 'GET' && pathname === '/api/chats') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const chatsSummary = [];
    for (const otherKey in currentUser.chats) {
      const chat = currentUser.chats[otherKey];
      const messages = chat.messages;
      const lastMessage = messages.length > 0 ? messages[messages.length - 1] : null;
      // look up nickname for other user
      let otherNick = null;
      try {
        const users = await loadUsers();
        const otherUser = users.find(u => u.countryCode + u.phone === otherKey);
        otherNick = otherUser && otherUser.nickname ? otherUser.nickname : null;
      } catch (_) {}
      chatsSummary.push({
        phone: otherKey,
        nickname: otherNick,
        unread: currentUser.unreadChatCount[otherKey] || 0,
        last: lastMessage ? { from: lastMessage.from, text: lastMessage.text, timestamp: lastMessage.timestamp } : null
      });
    }
    return sendJson(res, 200, { chats: chatsSummary });
  }
  if (method === 'GET' && pathname.startsWith('/api/chat/')) {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const otherPhone = decodeURIComponent(pathname.substring('/api/chat/'.length));
    const chat = currentUser.chats[otherPhone];
    if (!chat) return sendJson(res, 400, { error: 'Chat nicht gefunden' });
    // Check if chat partner is blocked by either side
    const users = await loadUsers();
    const otherUser = users.find(u => u.countryCode + u.phone === otherPhone);
    if (otherUser) {
      const myKey = currentUser.countryCode + currentUser.phone;
      if ((currentUser.blocked && currentUser.blocked.includes(otherPhone)) || (otherUser.blocked && otherUser.blocked.includes(myKey))) {
        return sendJson(res, 403, { error: 'Dieser Chat ist blockiert' });
      }
    }
    currentUser.unreadChatCount[otherPhone] = 0;
    const idx = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    users[idx] = currentUser;
    await saveUsers(users);
    return sendJson(res, 200, { messages: chat.messages });
  }
  if (method === 'POST' && pathname === '/api/chat/send') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { to, text } = body;
    if (!to || !text) return sendJson(res, 400, { error: 'Ziel oder Nachricht fehlt' });
    const users = await loadUsers();
    const recipient = users.find(u => u.countryCode + u.phone === to);
    if (!recipient) return sendJson(res, 400, { error: 'Empfänger nicht gefunden' });
    const myKey = currentUser.countryCode + currentUser.phone;
    // Check if blocked
    if ((currentUser.blocked && currentUser.blocked.includes(to)) || (recipient.blocked && recipient.blocked.includes(myKey))) {
      return sendJson(res, 403, { error: 'Dieser Chat ist blockiert' });
    }
    if (!currentUser.matches.includes(to) && !currentUser.kiMatches.includes(to)) {
      return sendJson(res, 400, { error: 'Sie sind kein Match mit diesem Nutzer' });
    }
    const timestamp = Date.now();
    const message = { from: currentUser.countryCode + currentUser.phone, text: text, timestamp };
    if (!currentUser.chats[to]) {
      currentUser.chats[to] = { messages: [], reported: false };
      currentUser.unreadChatCount[to] = 0;
    }
    currentUser.chats[to].messages.push({ from: message.from, text: message.text, timestamp: message.timestamp });
    if (!recipient.chats[currentUser.countryCode + currentUser.phone]) {
      recipient.chats[currentUser.countryCode + currentUser.phone] = { messages: [], reported: false };
      recipient.unreadChatCount[currentUser.countryCode + currentUser.phone] = 0;
    }
    recipient.chats[currentUser.countryCode + currentUser.phone].messages.push({ from: message.from, text: message.text, timestamp: message.timestamp });
    recipient.unreadChatCount[currentUser.countryCode + currentUser.phone] = (recipient.unreadChatCount[currentUser.countryCode + currentUser.phone] || 0) + 1;
    const senderIdx = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    users[senderIdx] = currentUser;
    const recipientIdx = users.findIndex(u => u.countryCode === recipient.countryCode && u.phone === recipient.phone);
    users[recipientIdx] = recipient;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'POST' && pathname === '/api/chat/report') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { chatWith } = body;
    if (!chatWith) return sendJson(res, 400, { error: 'Ziel fehlt' });
    const users = await loadUsers();
    const other = users.find(u => u.countryCode + u.phone === chatWith);
    if (!other) return sendJson(res, 400, { error: 'Nutzer nicht gefunden' });
    if (currentUser.chats[chatWith]) currentUser.chats[chatWith].reported = true;
    if (other.chats[currentUser.countryCode + currentUser.phone]) other.chats[currentUser.countryCode + currentUser.phone].reported = true;
    reports.push({ reporter: currentUser.countryCode + currentUser.phone, against: chatWith, timestamp: Date.now() });
    const idxU = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    users[idxU] = currentUser;
    const idxO = users.findIndex(u => u.countryCode === other.countryCode && u.phone === other.phone);
    users[idxO] = other;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }

  // API: Blockiere einen Nutzer (nutzerseitige Blockfunktion)
  if (method === 'POST' && pathname === '/api/block') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { phone } = body;
    if (!phone) return sendJson(res, 400, { error: 'Telefonnummer fehlt' });
    if (!currentUser.blocked) currentUser.blocked = [];
    if (!currentUser.blocked.includes(phone)) {
      currentUser.blocked.push(phone);
    }
    // remove from matches and kiMatches and unseen lists
    currentUser.matches = (currentUser.matches || []).filter(p => p !== phone);
    currentUser.kiMatches = (currentUser.kiMatches || []).filter(p => p !== phone);
    currentUser.unseenMatches = (currentUser.unseenMatches || []).filter(p => p !== phone);
    currentUser.unseenKiMatches = (currentUser.unseenKiMatches || []).filter(p => p !== phone);
    // remove chats and unread counts
    if (currentUser.chats && currentUser.chats[phone]) {
      delete currentUser.chats[phone];
    }
    if (currentUser.unreadChatCount) {
      delete currentUser.unreadChatCount[phone];
    }
    const users = await loadUsers();
    const meIdx = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    if (meIdx >= 0) users[meIdx] = currentUser;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'GET' && pathname === '/api/admin/reports') {
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const users = await loadUsers();
    const detailedReports = reports.map(r => {
      const reporter = users.find(u => u.countryCode + u.phone === r.reporter);
      const accused = users.find(u => u.countryCode + u.phone === r.against);
      const chat = reporter && reporter.chats[r.against] ? reporter.chats[r.against].messages : [];
      return { reporter: r.reporter, against: r.against, messages: chat, timestamp: r.timestamp };
    });
    return sendJson(res, 200, { reports: detailedReports });
  }
  if (method === 'POST' && pathname === '/api/admin/block') {
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { phone } = body;
    if (!phone) return sendJson(res, 400, { error: 'Telefonnummer fehlt' });
    const users = await loadUsers();
    const target = users.find(u => u.countryCode + u.phone === phone);
    if (!target) return sendJson(res, 400, { error: 'Nutzer nicht gefunden' });
    // Kennzeichne das Konto als dauerhaft gesperrt.  Neben dem
    // bestehenden `locked`‑Flag wird ein weiteres Feld `lockedByAdmin`
    // gesetzt.  Dieses Flag verhindert später Passwort‑Zurücksetzungen
    // und hebt die Sperre nicht automatisch beim Zurücksetzen oder
    // Loginversuch auf.
    target.locked = true;
    target.lockedByAdmin = true;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'POST' && pathname === '/api/admin/verify') {
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { phone } = body;
    if (!phone) return sendJson(res, 400, { error: 'Telefonnummer fehlt' });
    const users = await loadUsers();
    const target = users.find(u => u.countryCode + u.phone === phone);
    if (!target) return sendJson(res, 400, { error: 'Nutzer nicht gefunden' });
    target.verified = true;
    target.verificationPending = false;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }
  if (method === 'POST' && pathname === '/api/admin/createFake') {
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone, gender } = body;
    if (!countryCode || !phone) return sendJson(res, 400, { error: 'Vorwahl oder Nummer fehlt' });
    if (!['0049','0041','0043'].includes(countryCode)) return sendJson(res, 400, { error: 'Ungültige Vorwahl' });
    const users = await loadUsers();
    const existing = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (existing) return sendJson(res, 400, { error: 'Nummer bereits registriert' });
    // Validate gender: admin must choose 'M' or 'W'; default random if none provided
    let chosenGender;
    if (gender && (gender === 'M' || gender === 'W')) {
      chosenGender = gender;
    } else {
      chosenGender = Math.random() < 0.5 ? 'M' : 'W';
    }
    const locationsDE = ['Baden-Württemberg','Bayern','Berlin','Brandenburg','Bremen','Hamburg','Hessen','Mecklenburg-Vorpommern','Niedersachsen','Nordrhein-Westfalen','Rheinland-Pfalz','Saarland','Sachsen','Sachsen-Anhalt','Schleswig-Holstein','Thüringen'];
    const locationsCH = ['Aargau','Appenzell Ausserrhoden','Appenzell Innerrhoden','Basel-Landschaft','Basel-Stadt','Bern','Freiburg','Genf','Glarus','Graubünden','Jura','Luzern','Neuenburg','Nidwalden','Obwalden','St. Gallen','Schaffhausen','Schwyz','Solothurn','Thurgau','Tessin','Uri','Waadt','Wallis','Zug','Zürich'];
    const locationsAT = ['Burgenland','Kärnten','Niederösterreich','Oberösterreich','Salzburg','Steiermark','Tirol','Vorarlberg','Wien'];
    let location;
    if (countryCode === '0049') location = locationsDE[Math.floor(Math.random() * locationsDE.length)];
    if (countryCode === '0041') location = locationsCH[Math.floor(Math.random() * locationsCH.length)];
    if (countryCode === '0043') location = locationsAT[Math.floor(Math.random() * locationsAT.length)];
    const religions = [
      { group: 'Islam', sub: 'Sunni' },
      { group: 'Islam', sub: 'Shia' },
      { group: 'Christentum', sub: 'Katholisch' },
      { group: 'Christentum', sub: 'Evangelisch' },
      { group: 'Christentum', sub: 'Orthodox' },
      { group: 'Judentum', sub: 'Orthodox' },
      { group: 'Hindu', sub: null },
      { group: 'Buddhist', sub: null },
      { group: 'Atheist', sub: null }
    ];
    const religion = religions[Math.floor(Math.random() * religions.length)];
    const interestPool = ['Wandern','Helene Fischer','Yoga','konservativ','SPD','Pokemon','Golf','Berge','Lasagne','Kochen','Lesen','Reisen','Radfahren','Kino','Fußball','Schwimmen','Joggen','Backen','Musik','Theater','Politik','Skifahren','Serien','Kunst'];
    const shuffled = interestPool.sort(() => 0.5 - Math.random());
    const interests = shuffled.slice(0, 20);
    const aboutTexts = [
      'Ich liebe die Natur und gehe gerne wandern.',
      'Musik ist mein Leben und ich spiele in einer Band.',
      'In meiner Freizeit koche ich leidenschaftlich gern.',
      'Ich lese gerne Bücher und interessiere mich für Politik.',
      'Sport hält mich fit – besonders Laufen und Yoga.'
    ];
    const about = aboutTexts[Math.floor(Math.random() * aboutTexts.length)];
    const newUser = {
      countryCode,
      phone,
      password: '',
      birthDate: '2000-01-01',
      activated: true,
      verificationCode: null,
      resetCode: generateSmsCode(),
      locked: false,
      failedAttempts: 0,
      isAdmin: false,
      profile: {
        location,
        gender: chosenGender,
        religion,
        interests,
        about,
        showInProfile: false
      },
      matches: [],
      kiMatches: [],
      chats: {},
      unreadChatCount: {},
      unreadMatches: 0,
      verified: false,
      verificationPending: false
      ,paused: false
    };
    users.push(newUser);
    await saveUsers(users);
    const fullNumber = `${countryCode}${phone}`;
    await sendSms(fullNumber, `Ihr Hearttwin Rücksetzcode lautet: ${newUser.resetCode}`);
    return sendJson(res, 200, { success: true });
  }

  // Prüfe, ob eine Telefonnummer zur Registrierung verfügbar ist (wird vor dem Bezahlen aufgerufen)
  if (method === 'POST' && pathname === '/api/check-phone') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone } = body;
    if (!countryCode || !phone) return sendJson(res, 400, { error: 'Vorwahl oder Nummer fehlt' });
    if (!['0049','0041','0043'].includes(countryCode)) return sendJson(res, 400, { error: 'Ungültige Vorwahl' });
    if (!/^\d{6,15}$/.test(phone)) return sendJson(res, 400, { error: 'Ungültige Telefonnummer' });
    const users = await loadUsers();
    const existing = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (existing) {
      if (existing.locked) {
        return sendJson(res, 400, { error: 'Diese Telefonnummer ist gesperrt.' });
      }
      return sendJson(res, 400, { error: 'Diese Telefonnummer ist bereits registriert.' });
    }
    return sendJson(res, 200, { available: true });
  }

  // Admin: create free user with password (no verification necessary)
  if (method === 'POST' && pathname === '/api/admin/createPasswordUser') {
    // only admins can call
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone, password, gender } = body;
    if (!countryCode || !phone || !password) return sendJson(res, 400, { error: 'Vorwahl, Nummer oder Passwort fehlt' });
    if (!['0049','0041','0043'].includes(countryCode)) return sendJson(res, 400, { error: 'Ungültige Vorwahl' });
    if (!/^[0-9]{6,15}$/.test(phone)) return sendJson(res, 400, { error: 'Ungültige Telefonnummer' });
    // Password complexity: min 8 characters with at least one uppercase and one number
    if (password.length < 8 || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      return sendJson(res, 400, { error: 'Passwort muss mindestens 8 Zeichen, einen Großbuchstaben und eine Zahl enthalten' });
    }
    const users = await loadUsers();
    const existing = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (existing) return sendJson(res, 400, { error: 'Nummer bereits registriert' });
    // use a default birthDate of 2000-01-01 so user is >=18
    // Default Profil für neue Passwort‑Nutzer: 25 Jahre, männlich, Islam, Baden-Württemberg und 20 Interessen
    const defaultInterests = [
      'eins','zwei','drei','vier','fünf','sechs','sieben','acht','neun','zehn',
      'elf','zwölf','dreizehn','vierzehn','fünfzehn','sechzehn','siebzehn','achtzehn','neunzehn','zwanzig'
    ];
    // Determine gender for default profile: use provided gender if valid; otherwise default to 'M'
    let defaultGender = 'M';
    if (gender === 'M' || gender === 'W') defaultGender = gender;
    const defaultProfile = {
      location: 'Baden-Württemberg',
      gender: defaultGender,
      religion: { group: 'Islam', sub: null },
      interests: defaultInterests,
      about: '',
      showInProfile: false
    };
    const newUser = {
      countryCode,
      phone,
      password,
      birthDate: '2000-01-01',
      activated: true,
      verificationCode: null,
      resetCode: null,
      locked: false,
      failedAttempts: 0,
      isAdmin: false,
      profile: defaultProfile,
      matches: [],
      kiMatches: [],
      chats: {},
      unreadChatCount: {},
      unreadMatches: 0,
      // Set a default nickname based on the phone so that the user appears with a name until they change it
      nickname: 'User' + phone,
      blocked: [],
      unseenMatches: [],
      unseenKiMatches: [],
      verified: false,
      verificationPending: false,
      adminCreated: true,
      paused: false
    };
    users.push(newUser);
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }

  // Admin: create user with password that still needs SMS verification
  if (method === 'POST' && pathname === '/api/admin/createPasswordUserSms') {
    // only admins can call this
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { countryCode, phone, password, gender } = body;
    if (!countryCode || !phone || !password) return sendJson(res, 400, { error: 'Vorwahl, Nummer oder Passwort fehlt' });
    if (!['0049','0041','0043'].includes(countryCode)) return sendJson(res, 400, { error: 'Ungültige Vorwahl' });
    if (!/^[0-9]{6,15}$/.test(phone)) return sendJson(res, 400, { error: 'Ungültige Telefonnummer' });
    if (password.length < 8 || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      return sendJson(res, 400, { error: 'Passwort muss mindestens 8 Zeichen, einen Großbuchstaben und eine Zahl enthalten' });
    }
    const users = await loadUsers();
    const existing = users.find(u => u.countryCode === countryCode && u.phone === phone);
    if (existing) return sendJson(res, 400, { error: 'Nummer bereits registriert' });
    // Default birthDate 2000-01-01 (volljährig)
    const defaultInterests = [
      'eins','zwei','drei','vier','fünf','sechs','sieben','acht','neun','zehn',
      'elf','zwölf','dreizehn','vierzehn','fünfzehn','sechzehn','siebzehn','achtzehn','neunzehn','zwanzig'
    ];
    // Determine gender for default profile: use provided gender if valid; otherwise default to 'M'
    let defaultGender2 = 'M';
    if (gender === 'M' || gender === 'W') defaultGender2 = gender;
    const defaultProfile = {
      location: 'Baden-Württemberg',
      gender: defaultGender2,
      religion: { group: 'Islam', sub: null },
      interests: defaultInterests,
      about: '',
      showInProfile: false
    };
    const verificationCode = generateSmsCode();
    const newUser = {
      countryCode,
      phone,
      password,
      birthDate: '2000-01-01',
      activated: false,
      verificationCode: verificationCode,
      resetCode: null,
      locked: false,
      failedAttempts: 0,
      isAdmin: false,
      profile: defaultProfile,
      matches: [],
      kiMatches: [],
      chats: {},
      unreadChatCount: {},
      unreadMatches: 0,
      nickname: null,
      nicknameImmutable: false,
      aboutChangedAt: null,
      blocked: [],
      unseenMatches: [],
      unseenKiMatches: [],
      verified: false,
      verificationPending: false,
      adminCreated: true,
      paused: false
    };
    users.push(newUser);
    await saveUsers(users);
    const fullNumber = `${countryCode}${phone}`;
    await sendSms(fullNumber, `Ihr Hearttwin Bestätigungscode lautet: ${verificationCode}`);
    return sendJson(res, 200, { success: true });
  }

  // Admin: Liste aller Nutzer (sanitised)
  if (method === 'GET' && pathname === '/api/admin/users') {
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const users = await loadUsers();
    const list = users.map(u => {
      return {
        countryCode: u.countryCode,
        phone: u.phone,
        nickname: u.nickname,
        birthDate: u.birthDate,
        activated: u.activated,
        verified: u.verified,
        isAdmin: u.isAdmin,
        paused: u.paused,
        matchesCount: Array.isArray(u.matches) ? u.matches.length : 0,
        kiMatchesCount: Array.isArray(u.kiMatches) ? u.kiMatches.length : 0,
        hasProfile: !!u.profile
      };
    });
    return sendJson(res, 200, { users: list });
  }

  // API: Liefert eigene Match-Listen (normale und KI-Matches)
  if (method === 'GET' && pathname === '/api/my-match-lists') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    return sendJson(res, 200, {
      matches: currentUser.matches || [],
      kiMatches: currentUser.kiMatches || []
    });
  }

  // API: Notification counts for nav badges
  if (method === 'GET' && pathname === '/api/notifications') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const unseenMatchesCount = (currentUser.unseenMatches || []).length;
    const unseenKiMatchesCount = (currentUser.unseenKiMatches || []).length;
    // unread chat counts: count non‑KI chats and KI chats separately
    let unreadChatsCount = 0;
    let unreadKiChatsCount = 0;
    for (const key in currentUser.unreadChatCount) {
      const cnt = currentUser.unreadChatCount[key];
      if (cnt > 0) {
        // if this chat partner is part of KI matches list, increment KI counter
        const isKi = currentUser.kiMatches && currentUser.kiMatches.includes(key);
        if (isKi) {
          unreadKiChatsCount++;
        } else {
          // only increment normal chats counter when not KI chat
          unreadChatsCount++;
        }
      }
    }
    return sendJson(res, 200, {
      unseenMatches: unseenMatchesCount,
      unseenKiMatches: unseenKiMatchesCount,
      unreadChats: unreadChatsCount,
      unreadKiChats: unreadKiChatsCount
    });
  }

  // API: Pause the current user's profile (account frozen until next login)
  if (method === 'POST' && pathname === '/api/profile/pause') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    // set paused flag
    currentUser.paused = true;
    const users = await loadUsers();
    const idx = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    if (idx >= 0) users[idx] = currentUser;
    await saveUsers(users);
    // invalidate session
    if (cookies.session) delete sessions[cookies.session];
    res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/');
    return sendJson(res, 200, { success: true });
  }

  // API: Delete the current user's account permanently
  if (method === 'POST' && pathname === '/api/profile/delete') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const users = await loadUsers();
    const myKey = currentUser.countryCode + currentUser.phone;
    // remove references from other users
    for (const u of users) {
      const key = u.countryCode + u.phone;
      if (key === myKey) continue;
      // remove from matches and kiMatches
      if (u.matches) u.matches = u.matches.filter(p => p !== myKey);
      if (u.kiMatches) u.kiMatches = u.kiMatches.filter(p => p !== myKey);
      // remove from unseen lists
      if (u.unseenMatches) u.unseenMatches = u.unseenMatches.filter(p => p !== myKey);
      if (u.unseenKiMatches) u.unseenKiMatches = u.unseenKiMatches.filter(p => p !== myKey);
      // remove chat and unread counts
      if (u.chats && u.chats[myKey]) delete u.chats[myKey];
      if (u.unreadChatCount && Object.prototype.hasOwnProperty.call(u.unreadChatCount, myKey)) {
        delete u.unreadChatCount[myKey];
      }
      // remove from blocked list
      if (u.blocked) u.blocked = u.blocked.filter(p => p !== myKey);
    }
    // filter out current user
    const newUsers = users.filter(u => u.countryCode + u.phone !== myKey);
    await saveUsers(newUsers);
    // invalidate session
    if (cookies.session) delete sessions[cookies.session];
    res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/');
    return sendJson(res, 200, { success: true });
  }

  // API: Liefert das öffentliche Profil eines anderen Nutzers. Zugriff nur für Admins oder wenn bereits gematcht.
  if (method === 'GET' && pathname.startsWith('/api/profile/')) {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const otherKey = decodeURIComponent(pathname.substring('/api/profile/'.length));
    // find user
    const users = await loadUsers();
    const otherUser = users.find(u => u.countryCode + u.phone === otherKey);
    if (!otherUser) return sendJson(res, 400, { error: 'Nutzer nicht gefunden' });
    // Check permission: allow if current user is admin or matched with other or kiMatched
    if (!currentUser.isAdmin && !currentUser.matches.includes(otherKey) && !currentUser.kiMatches.includes(otherKey)) {
      return sendJson(res, 403, { error: 'Kein Zugriff auf dieses Profil' });
    }
    // prepare public profile details
    const profile = otherUser.profile ? { ...otherUser.profile } : null;
    // Über‑dich‑Text immer sichtbar: Die bisherige Option `showInProfile`
    // wird ignoriert. Dadurch wird der Beschreibungstext nicht mehr
    // entfernt und ist für Matches und KI‑Matches stets sichtbar.
    // Build response; include phone only for admin or self
    const result = {
      nickname: otherUser.nickname || null,
      verified: otherUser.verified,
      age: calculateAge(otherUser.birthDate),
      profile: profile
    };
    // include phone and countryCode for admin or if requesting own profile
    const requesterKey = currentUser.countryCode + currentUser.phone;
    if (currentUser.isAdmin || requesterKey === otherKey) {
      result.phone = otherUser.countryCode + otherUser.phone;
      result.countryCode = otherUser.countryCode;
      result.birthDate = otherUser.birthDate;
    }
    return sendJson(res, 200, result);
  }

  // API: Markiere ein Match als gesehen (entfernt es aus den Benachrichtigungen)
  if (method === 'POST' && pathname === '/api/match/seen') {
    if (!currentUser) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return sendJson(res, 400, { error: 'Ungültiges JSON' });
    const { phone, ki } = body;
    if (!phone) return sendJson(res, 400, { error: 'Telefonnummer fehlt' });
    if (ki) {
      if (currentUser.unseenKiMatches) {
        const idx = currentUser.unseenKiMatches.indexOf(phone);
        if (idx >= 0) currentUser.unseenKiMatches.splice(idx, 1);
      }
    } else {
      if (currentUser.unseenMatches) {
        const idx = currentUser.unseenMatches.indexOf(phone);
        if (idx >= 0) currentUser.unseenMatches.splice(idx, 1);
      }
    }
    const users = await loadUsers();
    const meIdx = users.findIndex(u => u.countryCode === currentUser.countryCode && u.phone === currentUser.phone);
    if (meIdx >= 0) users[meIdx] = currentUser;
    await saveUsers(users);
    return sendJson(res, 200, { success: true });
  }

  // Admin: list free users created with password
  if (method === 'GET' && pathname === '/api/admin/passwordUsers') {
    if (!currentUser || !currentUser.isAdmin) return sendJson(res, 403, { error: 'Keine Berechtigung' });
    const users = await loadUsers();
    const pwUsers = users.filter(u => u.adminCreated);
    // return limited fields for security; include profile, but exclude reset codes
    const list = pwUsers.map(u => ({
      countryCode: u.countryCode,
      phone: u.phone,
      password: u.password,
      birthDate: u.birthDate,
      activated: u.activated,
      verified: u.verified,
      profile: u.profile
    }));
    return sendJson(res, 200, { users: list });
  }
  // Fallback for unknown API routes
  return sendJson(res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
  // handle CORS preflight for convenience (optional)
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }
  handleRequest(req, res).catch(err => {
    console.error(err);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal server error' }));
  });
});

server.listen(PORT, () => {
  console.log('Hearttwin server läuft auf Port ' + PORT);
});