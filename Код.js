// ============================================================================
// MOODLE РЭУ ИМ. Г.В. ПЛЕХАНОВА - BACKEND API & TELEGRAM BOT
// ============================================================================

const SCRIPT_PROPS = PropertiesService.getScriptProperties();
const TELEGRAM_TOKEN = SCRIPT_PROPS.getProperty("BOT_TOKEN") || "8847639088:AAEp1Z9Rg16ou3U_Tq7Gn1FEF3CIuU_bWgc";
const MASTER_KEY = SCRIPT_PROPS.getProperty("MASTER_KEY") || "default_fallback_secret_key_2026_rea";
const TELEGRAM_API = `https://api.telegram.org/bot${TELEGRAM_TOKEN}`;
const BASE_URL = "https://study.rea.ru";
const WEB_APP_URL = "https://justed10.github.io/rea-moodle-app/";

// ============================================================================
// 1. АВТОРИЗАЦИЯ И ТОКЕНЫ
// ============================================================================

function validateTelegramInitData(initData) {
  if (!initData || typeof initData !== "string") {
    return { valid: false, error: "Отсутствуют данные initData" };
  }

  try {
    const params = {};
    initData.split("&").forEach(part => {
      const idx = part.indexOf("=");
      if (idx !== -1) {
        const key = part.substring(0, idx);
        const val = part.substring(idx + 1);
        params[key] = decodeURIComponent(val.replace(/\+/g, " "));
      }
    });

    const hash = params.hash;
    delete params.hash;
    if (!hash) return { valid: false, error: "Хеш подписи не найден" };

    const authDate = parseInt(params.auth_date, 10);
    const now = Math.floor(Date.now() / 1000);
    if (isNaN(authDate) || (now - authDate > 172800)) {
      return { valid: false, error: "Сессия initData устарела" };
    }

    const dataCheckString = Object.keys(params)
      .sort()
      .map(k => `${k}=${params[k]}`)
      .join("\n");

    const secretKey = Utilities.computeHmacSha256Signature(TELEGRAM_TOKEN, "WebAppData");
    const signature = Utilities.computeHmacSha256Signature(dataCheckString, secretKey);

    const calculatedHash = signature
      .map(b => ("0" + (b & 0xFF).toString(16)).slice(-2))
      .join("");

    if (calculatedHash !== hash) {
      return { valid: false, error: "Несоответствие подписи Telegram" };
    }

    return { valid: true, user: JSON.parse(params.user || "{}") };
  } catch (err) {
    return { valid: false, error: err.toString() };
  }
}

function generateAuthToken(chatId) {
  const timestamp = Math.floor(Date.now() / 1000);
  const data = `${chatId}:${timestamp}`;
  const sigBytes = Utilities.computeHmacSha256Signature(data, MASTER_KEY);
  const sig = sigBytes.map(b => ("0" + (b & 0xFF).toString(16)).slice(-2)).join("");
  return `${data}:${sig}`;
}

function validateAuthToken(token) {
  if (!token || typeof token !== "string") return { valid: false, error: "Токен пуст" };
  const parts = token.split(":");
  if (parts.length !== 3) return { valid: false, error: "Неверный формат токена" };

  const [chatId, timestampStr, signature] = parts;
  const timestamp = parseInt(timestampStr, 10);
  const now = Math.floor(Date.now() / 1000);

  // Токен действует 1 год, чтобы не сбрасывать вход
  if (isNaN(timestamp) || (now - timestamp > 31536000)) {
    return { valid: false, error: "Токен устарел" };
  }

  const data = `${chatId}:${timestampStr}`;
  const sigBytes = Utilities.computeHmacSha256Signature(data, MASTER_KEY);
  const expectedSig = sigBytes.map(b => ("0" + (b & 0xFF).toString(16)).slice(-2)).join("");

  if (signature !== expectedSig) return { valid: false, error: "Неверная подпись" };
  return { valid: true, user: { id: chatId } };
}

function resolveUser(params) {
  if (params.initData) {
    const vInit = validateTelegramInitData(params.initData);
    if (vInit.valid) return vInit;
  }
  if (params.auth) {
    const vAuth = validateAuthToken(params.auth);
    if (vAuth.valid) return vAuth;
  }
  if (params.userId) {
    return { valid: true, user: { id: String(params.userId) } };
  }
  return { valid: false, error: "Ошибка авторизации" };
}

function encryptSecret(text) {
  if (!text) return "";
  const keyBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, MASTER_KEY);
  const textBytes = Utilities.newBlob(text).getBytes();
  const out = [];
  for (let i = 0; i < textBytes.length; i++) {
    const val = (textBytes[i] ^ keyBytes[i % keyBytes.length]) & 0xFF;
    out.push(val > 127 ? val - 256 : val);
  }
  return Utilities.base64Encode(out);
}

function decryptSecret(cipherBase64) {
  if (!cipherBase64) return "";
  try {
    const keyBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, MASTER_KEY);
    const cipherBytes = Utilities.base64Decode(cipherBase64);
    const out = [];
    for (let i = 0; i < cipherBytes.length; i++) {
      const val = (cipherBytes[i] ^ keyBytes[i % keyBytes.length]) & 0xFF;
      out.push(val > 127 ? val - 256 : val);
    }
    return Utilities.newBlob(out).getDataAsString();
  } catch (e) {
    return "";
  }
}

// ============================================================================
// 2. ВЕЧНОЕ ХРАНЕНИЕ УЧЕТНЫХ ДАННЫХ И СЕССИЙ
// ============================================================================

function getSavedCredentials(chatId) {
  const sp = PropertiesService.getScriptProperties();
  const up = PropertiesService.getUserProperties();

  const login = sp.getProperty(`saved_login_${chatId}`) || up.getProperty(`saved_login_${chatId}`);
  const encPass = sp.getProperty(`saved_pass_enc_${chatId}`) || up.getProperty(`saved_pass_enc_${chatId}`);
  const pass = decryptSecret(encPass);

  return { login: login, pass: pass };
}

function saveCredentials(chatId, login, password) {
  const encPass = encryptSecret(password);
  const data = {
    [`saved_login_${chatId}`]: login,
    [`saved_pass_enc_${chatId}`]: encPass
  };
  PropertiesService.getScriptProperties().setProperties(data);
  PropertiesService.getUserProperties().setProperties(data);
}

function clearCredentials(chatId) {
  const keys = [
    `saved_login_${chatId}`,
    `saved_pass_enc_${chatId}`,
    `cookie_${chatId}`,
    `sesskey_${chatId}`,
    `courses_${chatId}`
  ];
  PropertiesService.getScriptProperties().deleteProperties(keys);
  PropertiesService.getUserProperties().deleteProperties(keys);
  clearMoodleSession(chatId);
}

function getMoodleSession(chatId) {
  const cache = CacheService.getScriptCache();
  let cookie = cache.get(`cookie_${chatId}`);
  let sesskey = cache.get(`sesskey_${chatId}`);

  if (cookie && sesskey) {
    return { cookie: cookie, sesskey: sesskey };
  }

  const props = PropertiesService.getScriptProperties();
  cookie = props.getProperty(`cookie_${chatId}`);
  sesskey = props.getProperty(`sesskey_${chatId}`);

  if (cookie && sesskey) {
    cache.put(`cookie_${chatId}`, cookie, 7200);
    cache.put(`sesskey_${chatId}`, sesskey, 7200);
    return { cookie: cookie, sesskey: sesskey };
  }

  return { cookie: null, sesskey: null };
}

function setMoodleSession(chatId, cookie, sesskey) {
  const cache = CacheService.getScriptCache();
  if (cookie) cache.put(`cookie_${chatId}`, cookie, 7200);
  if (sesskey) cache.put(`sesskey_${chatId}`, sesskey, 7200);

  const props = PropertiesService.getScriptProperties();
  props.setProperties({
    [`cookie_${chatId}`]: cookie || "",
    [`sesskey_${chatId}`]: sesskey || ""
  });
}

function clearMoodleSession(chatId) {
  const cache = CacheService.getScriptCache();
  cache.removeAll([`cookie_${chatId}`, `sesskey_${chatId}`, `courses_${chatId}`]);

  const props = PropertiesService.getScriptProperties();
  props.deleteProperties([`cookie_${chatId}`, `sesskey_${chatId}`, `courses_${chatId}`]);
}

function ensureMoodleSession(chatId) {
  let session = getMoodleSession(chatId);
  if (session.cookie && session.sesskey) {
    return { success: true, cookie: session.cookie, sesskey: session.sesskey };
  }

  const creds = getSavedCredentials(chatId);
  if (!creds.login || !creds.pass) {
    return { success: false, error: "Требуется авторизация" };
  }

  const auth = loginToMoodle(creds.login, creds.pass);
  if (auth.success) {
    setMoodleSession(chatId, auth.cookie, auth.sesskey);
    return { success: true, cookie: auth.cookie, sesskey: auth.sesskey };
  }

  return { success: false, error: auth.error };
}

function registerUser(chatId) {
  const props = PropertiesService.getScriptProperties();
  let list = [];
  try {
    list = JSON.parse(props.getProperty("active_users_list") || "[]");
  } catch (e) {
    list = [];
  }
  if (!list.includes(chatId)) {
    list.push(chatId);
    props.setProperty("active_users_list", JSON.stringify(list));
  }
}

function unregisterUser(chatId) {
  const props = PropertiesService.getScriptProperties();
  try {
    let list = JSON.parse(props.getProperty("active_users_list") || "[]");
    list = list.filter(id => id !== chatId);
    props.setProperty("active_users_list", JSON.stringify(list));
  } catch (e) {}
}

// ============================================================================
// 3. GET API (MINI APP)
// ============================================================================

function doGet(e) {
  if (!e || !e.parameter || !e.parameter.action) {
    return ContentService.createTextOutput("Moodle REU Gateway Active")
      .setMimeType(ContentService.MimeType.TEXT);
  }

  const action = e.parameter.action;
  const authRes = resolveUser(e.parameter);

  if (!authRes.valid) {
    return jsonResponse({ success: false, error: authRes.error });
  }

  const chatId = String(authRes.user.id);

  try {
    if (action === "init") {
      const creds = getSavedCredentials(chatId);
      if (!creds.login) {
        return jsonResponse({ loggedIn: false });
      }

      if (e.parameter.refresh === "1") {
        CacheService.getScriptCache().remove(`courses_${chatId}`);
      }

      registerUser(chatId);

      let sessionRes = ensureMoodleSession(chatId);
      let courses = [];

      if (sessionRes.success) {
        courses = fetchCourses(sessionRes.cookie, sessionRes.sesskey, chatId);
        if (!courses || courses.length === 0) {
          clearMoodleSession(chatId);
          const reauth = ensureMoodleSession(chatId);
          if (reauth.success) {
            courses = fetchCourses(reauth.cookie, reauth.sesskey, chatId);
          }
        }
      }

      if (!courses || courses.length === 0) {
        const cached = CacheService.getScriptCache().get(`courses_${chatId}`);
        if (cached) {
          try { courses = JSON.parse(cached); } catch (err) {}
        }
      }

      const newAuthToken = generateAuthToken(chatId);

      return jsonResponse({
        loggedIn: true,
        login: creds.login,
        courses: courses || [],
        auth: newAuthToken
      });
    }

    if (action === "login") {
      const login = (e.parameter.login || "").trim();
      const password = (e.parameter.password || "").trim();

      if (!login || !password) {
        return jsonResponse({ success: false, error: "Укажи логин и пароль" });
      }

      const auth = loginToMoodle(login, password);
      if (auth.success) {
        saveCredentials(chatId, login, password);
        registerUser(chatId);
        setMoodleSession(chatId, auth.cookie, auth.sesskey);

        const courses = fetchCourses(auth.cookie, auth.sesskey, chatId);
        const newAuthToken = generateAuthToken(chatId);

        return jsonResponse({
          success: true,
          login: login,
          courses: courses || [],
          auth: newAuthToken
        });
      }
      return jsonResponse({ success: false, error: auth.error });
    }

    if (action === "topics") {
      const courseId = e.parameter.courseId;
      let sessionRes = ensureMoodleSession(chatId);
      if (!sessionRes.success) return jsonResponse({ success: false, error: sessionRes.error });

      let topics = fetchCourseTopics(courseId, sessionRes.cookie);
      if (!topics || topics.length === 0) {
        clearMoodleSession(chatId);
        const reauth = ensureMoodleSession(chatId);
        if (reauth.success) {
          topics = fetchCourseTopics(courseId, reauth.cookie);
        }
      }

      return jsonResponse({ success: true, topics: topics || [] });
    }

    if (action === "topic_details") {
      const topicId = e.parameter.topicId;
      const sessionRes = ensureMoodleSession(chatId);
      if (!sessionRes.success) return jsonResponse({ success: false, error: sessionRes.error });

      const details = fetchTopicDetails(topicId, sessionRes.cookie);
      return jsonResponse({ success: true, details: details });
    }

    if (action === "course_grades") {
      const courseId = e.parameter.courseId;
      const sessionRes = ensureMoodleSession(chatId);
      if (!sessionRes.success) return jsonResponse({ success: false, error: sessionRes.error });

      const grades = fetchCourseGrades(courseId, sessionRes.cookie);
      return jsonResponse(grades);
    }

    if (action === "send_file") {
      const fileUrl = e.parameter.fileUrl || "";
      const fileName = e.parameter.fileName || "Задание.pdf";

      if (!fileUrl.startsWith(BASE_URL) && !fileUrl.startsWith("/")) {
        return jsonResponse({ success: false, error: "Недопустимый источник" });
      }

      const sessionRes = ensureMoodleSession(chatId);
      if (!sessionRes.success) return jsonResponse({ success: false, error: sessionRes.error });

      const fileBlob = downloadMoodleFile(fileUrl, fileName, sessionRes.cookie, PropertiesService.getScriptProperties(), chatId);
      if (fileBlob) {
        sendTelegramDocument(chatId, fileBlob, `📄 Материалы: ${fileName}`);
        return jsonResponse({ success: true });
      }
      return jsonResponse({ success: false, error: "Не удалось скачать файл" });
    }

    if (action === "logout") {
      clearCredentials(chatId);
      unregisterUser(chatId);
      return jsonResponse({ success: true });
    }

  } catch (err) {
    return jsonResponse({ success: false, error: err.toString() });
  }

  return jsonResponse({ success: false, error: "Действие не распознано" });
}

function jsonResponse(data) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

// ============================================================================
// 4. POST API (СДАЧА РАБОТ И СТАРТ ЧАТА БЕЗ РЕКУРСИИ)
// ============================================================================

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return HtmlService.createHtmlOutput("empty");
    }

    let payload;
    try {
      payload = JSON.parse(e.postData.contents);
    } catch (parseErr) {
      return HtmlService.createHtmlOutput("bad json");
    }

    if (payload.update_id) {
      const cache = CacheService.getScriptCache();
      const lockKey = `upd_${payload.update_id}`;
      if (cache.get(lockKey)) {
        return HtmlService.createHtmlOutput("ok");
      }
      cache.put(lockKey, "1", 21600);
    }

    if (payload.action === "submit_work") {
      const authRes = resolveUser(payload);
      if (!authRes.valid) {
        return jsonResponse({ success: false, error: authRes.error });
      }

      const chatId = String(authRes.user.id);
      const sessionRes = ensureMoodleSession(chatId);
      if (!sessionRes.success) {
        return jsonResponse({ success: false, error: sessionRes.error });
      }

      const topicId = payload.topicId;
      const messageText = payload.text || "Выполненная работа";
      const fileName = payload.fileName || "work.bin";
      const fileBase64 = payload.fileBase64;

      const replyForm = prepareReplyForm(topicId, sessionRes.cookie);
      if (!replyForm.success) {
        return jsonResponse({ success: false, error: "Форма недоступна: " + replyForm.error });
      }

      const fileBytes = Utilities.base64Decode(fileBase64);
      const fileBlob = Utilities.newBlob(fileBytes, "application/octet-stream", fileName);

      const uploadResult = uploadFileToMoodleDraft(
        fileBlob,
        replyForm.itemid,
        replyForm.repoId,
        sessionRes.sesskey,
        sessionRes.cookie
      );

      if (!uploadResult.success) {
        return jsonResponse({ success: false, error: uploadResult.error });
      }

      const submitResult = submitForumReply(
        replyForm.postid,
        replyForm.subject,
        messageText,
        replyForm.itemid,
        sessionRes.sesskey,
        sessionRes.cookie,
        replyForm.hiddenFields
      );

      if (submitResult.success) {
        sendMessage(chatId, `✅ Работа отправлена в тему: «${replyForm.subject}»\nФайл: ${fileName}`);
        return jsonResponse({ success: true });
      } else {
        return jsonResponse({ success: false, error: submitResult.error });
      }
    }

    if (payload.message) {
      const chatId = String(payload.message.chat.id);
      const text = (payload.message.text || "").trim();

      if (text === "/start" || text === "старт") {
        const authToken = generateAuthToken(chatId);
        const webAppUrl = `${WEB_APP_URL}?auth=${encodeURIComponent(authToken)}`;

        const appLauncherMarkup = {
          keyboard: [
            [{ text: "⚡ Открыть Mini App", web_app: { url: webAppUrl } }]
          ],
          resize_keyboard: true,
          is_persistent: true
        };

        UrlFetchApp.fetch(`${TELEGRAM_API}/sendMessage`, {
          method: "post",
          contentType: "application/json",
          payload: JSON.stringify({
            chat_id: chatId,
            text: "🎓 Твой личный кабинет Moodle РЭУ открывается кнопкой ниже.\n\nВсе предметы, задания, баллы БРС и сдача решений находятся внутри.",
            reply_markup: appLauncherMarkup
          }),
          muteHttpExceptions: true
        });
      }
      return HtmlService.createHtmlOutput("ok");
    }

  } catch (err) {
    Logger.log("doPost Error: " + err);
  }

  return HtmlService.createHtmlOutput("ok");
}

// ============================================================================
// 5. ПАРСИНГ MOODLE (КУРСЫ, ТЕМЫ И БРС)
// ============================================================================

function fetchCourses(cookie, sesskey, chatId) {
  if (!cookie) return [];
  const cache = CacheService.getScriptCache();
  if (chatId) {
    const cached = cache.get(`courses_${chatId}`);
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (parsed && parsed.length > 0) return parsed;
      } catch (e) {}
    }
  }

  if (sesskey) {
    const classifications = ["all", "inprogress", "future", "past"];
    for (let i = 0; i < classifications.length; i++) {
      try {
        const cls = classifications[i];
        const serviceUrl = `${BASE_URL}/lib/ajax/service.php?sesskey=${sesskey}&info=core_course_get_enrolled_courses_by_timeline_classification`;
        const payload = JSON.stringify([{
          index: 0,
          methodname: "core_course_get_enrolled_courses_by_timeline_classification",
          args: { offset: 0, limit: 0, classification: cls, sort: "fullname" }
        }]);

        const resp = UrlFetchApp.fetch(serviceUrl, {
          method: "post",
          contentType: "application/json",
          headers: { "Cookie": cookie },
          payload: payload,
          muteHttpExceptions: true
        });

        const text = resp.getContentText();
        if (text.includes('"error":true') || text.includes('invalidsesskey')) {
          return [];
        }

        const json = JSON.parse(text);
        if (json && json[0] && !json[0].error && json[0].data && json[0].data.courses && json[0].data.courses.length > 0) {
          const list = json[0].data.courses.map(c => ({
            id: String(c.id),
            fullname: c.fullname || c.shortname || `Курс ${c.id}`
          }));
          if (chatId && list.length > 0) cache.put(`courses_${chatId}`, JSON.stringify(list), 1800);
          return list;
        }
      } catch (e) {}
    }
  }

  const pages = [`${BASE_URL}/my/courses.php`, `${BASE_URL}/my/`, `${BASE_URL}/`];
  for (let p = 0; p < pages.length; p++) {
    try {
      const resp = UrlFetchApp.fetch(pages[p], {
        headers: { "Cookie": cookie },
        muteHttpExceptions: true,
        followRedirects: true
      });
      const html = resp.getContentText();
      if (html.includes('name="logintoken"') || html.includes("login/index.php")) {
        return [];
      }
      const list = parseCoursesFromHtml(html);
      if (list.length > 0) {
        if (chatId) cache.put(`courses_${chatId}`, JSON.stringify(list), 1800);
        return list;
      }
    } catch (e) {}
  }
  return [];
}

function parseCoursesFromHtml(html) {
  const courses = [];
  const seen = new Set();
  const regex = /<a[^>]+href="([^"]*\/course\/view\.php\?id=(\d+))"[^>]*>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = regex.exec(html)) !== null) {
    const courseId = match[2];
    if (courseId === "1") continue;

    let rawText = match[3];
    rawText = rawText.replace(/<span[^>]*class="[^"]*sr-only[^"]*"[^>]*>[\s\S]*?<\/span>/gi, "");
    rawText = rawText.replace(/<[^>]+>/g, " ");
    rawText = rawText.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&quot;/g, '"');
    let cleanName = rawText.replace(/\s+/g, " ").trim();
    cleanName = cleanName.replace(/^(?:название\s+курса|course\s+name)\s*:?\s*/i, "");

    const ignoreWords = ["в начало", "домашняя страница", "курсы", "мои курсы", "my courses", "home", "dashboard", "личный кабинет", "все курсы"];
    if (!cleanName || ignoreWords.includes(cleanName.toLowerCase()) || cleanName.length < 3) continue;

    if (!seen.has(courseId)) {
      seen.add(courseId);
      courses.push({ id: courseId, fullname: cleanName });
    }
  }
  return courses;
}

function fetchCourseTopics(courseId, cookie) {
  if (!cookie) return [];

  const courseUrl = `${BASE_URL}/course/view.php?id=${courseId}`;
  let courseHtml = "";

  try {
    const courseResp = UrlFetchApp.fetch(courseUrl, {
      headers: { "Cookie": cookie },
      muteHttpExceptions: true,
      followRedirects: true
    });
    courseHtml = courseResp.getContentText();
  } catch (e) {
    return [];
  }

  const topicsMap = new Map();

  function extractDiscussionsFromHtml(html) {
    const regex = /<a[^>]+href="[^"]*\/mod\/forum\/discuss\.php\?d=(\d+)[^"]*"[^>]*>([\s\S]*?)<\/a>/gi;
    let match;

    while ((match = regex.exec(html)) !== null) {
      const id = match[1];
      let rawName = match[2].replace(/<[^>]+>/g, " ");
      rawName = rawName
        .replace(/&nbsp;/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/\s+/g, " ")
        .trim();

      const lower = rawName.toLowerCase();
      if (
        !rawName ||
        lower.includes("discuss this topic") ||
        lower.includes("обсудить эту тему") ||
        lower.includes("permalink") ||
        lower.includes("постоянная ссылка") ||
        lower.includes("ответить") ||
        lower === "ответов" ||
        lower.startsWith("перейти к")
      ) {
        continue;
      }

      if (!topicsMap.has(id) || (topicsMap.get(id).length < rawName.length)) {
        topicsMap.set(id, rawName);
      }
    }
  }

  extractDiscussionsFromHtml(courseHtml);

  const forumUrls = [];
  const forumRegex = /<a[^>]+href="([^"]*\/mod\/forum\/view\.php\?id=\d+[^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let fMatch;

  while ((fMatch = forumRegex.exec(courseHtml)) !== null) {
    let fUrl = fMatch[1].replace(/&amp;/g, "&");
    if (!fUrl.startsWith("http")) {
      fUrl = BASE_URL + (fUrl.startsWith("/") ? "" : "/") + fUrl;
    }

    const linkText = fMatch[2].replace(/<[^>]+>/g, "").toLowerCase().trim();
    if (linkText.includes("объявлен") || linkText.includes("announc") || linkText.includes("новост")) {
      forumUrls.push(fUrl);
    } else {
      forumUrls.unshift(fUrl);
    }
  }

  const uniqueForumUrls = Array.from(new Set(forumUrls));

  for (let i = 0; i < uniqueForumUrls.length; i++) {
    const fUrl = uniqueForumUrls[i];
    try {
      const fResp = UrlFetchApp.fetch(fUrl, {
        headers: { "Cookie": cookie },
        muteHttpExceptions: true,
        followRedirects: true
      });
      const fHtml = fResp.getContentText();
      extractDiscussionsFromHtml(fHtml);
    } catch (err) {}
  }

  const topics = [];
  topicsMap.forEach((name, id) => {
    topics.push({ id: id, name: name });
  });

  return topics;
}

function fetchCourseGrades(courseId, cookie) {
  try {
    const url = `${BASE_URL}/grade/report/user/index.php?id=${courseId}`;
    const resp = UrlFetchApp.fetch(url, {
      headers: { "Cookie": cookie },
      muteHttpExceptions: true,
      followRedirects: true
    });

    const html = resp.getContentText();
    const items = [];
    let totalGrade = "-";
    let totalRange = "100";

    const rowRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
    let match;

    while ((match = rowRegex.exec(html)) !== null) {
      const row = match[1];
      if (!row.includes("column-itemname")) continue;

      const nameMatch = row.match(/class="[^"]*column-itemname[^"]*"[^>]*>([\s\S]*?)<\/(?:td|th)>/i);
      let name = nameMatch ? nameMatch[1].replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").trim() : "";

      const gradeMatch = row.match(/class="[^"]*column-grade[^"]*"[^>]*>([\s\S]*?)<\/td>/i);
      let grade = gradeMatch ? gradeMatch[1].replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").trim() : "-";

      const rangeMatch = row.match(/class="[^"]*column-range[^"]*"[^>]*>([\s\S]*?)<\/td>/i);
      let range = rangeMatch ? rangeMatch[1].replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").trim() : "";

      const fbMatch = row.match(/class="[^"]*column-feedback[^"]*"[^>]*>([\s\S]*?)<\/td>/i);
      let feedback = fbMatch ? fbMatch[1].replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").trim() : "";

      if (!name) continue;

      const isTotal = row.includes("coursetotal") ||
                      name.toLowerCase().includes("итоговая оценка") ||
                      name.toLowerCase().includes("course total") ||
                      name.toLowerCase().includes("итого за курс");

      if (isTotal) {
        totalGrade = grade;
        totalRange = range || "100";
      } else {
        items.push({
          name: name,
          grade: (grade && grade !== "-") ? grade : "Не оценено",
          range: range,
          feedback: feedback
        });
      }
    }
    return { success: true, total: totalGrade, max: totalRange, items: items };
  } catch (e) {
    return { success: false, error: e.message, total: "-", max: "100", items: [] };
  }
}

function fetchTopicDetails(topicId, cookie) {
  const discussUrl = `${BASE_URL}/mod/forum/discuss.php?d=${topicId}`;
  const resp = UrlFetchApp.fetch(discussUrl, {
    headers: { "Cookie": cookie },
    muteHttpExceptions: true
  });
  const html = resp.getContentText();

  let title = "Обсуждение";
  const titleMatch = html.match(/<h[234][^>]*class="[^"]*discussionname[^"]*"[^>]*>([\s\S]*?)<\/h[234]>/i) ||
                     html.match(/<title>([\s\S]*?)<\/title>/i);
  if (titleMatch) title = titleMatch[1].replace(/<[^>]+>/g, "").trim();

  const files = [];
  const seenUrls = new Set();
  const fileRegex = /<a[^>]+href="([^"]*\/pluginfile\.php\/[^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = fileRegex.exec(html)) !== null) {
    let url = match[1].replace(/&amp;/g, "&");
    let realName = "";
    try {
      const cleanPath = url.split("?")[0];
      const rawFile = cleanPath.substring(cleanPath.lastIndexOf("/") + 1);
      realName = decodeURIComponent(rawFile).trim();
    } catch (e) {}

    const htmlName = match[2].replace(/<[^>]+>/g, "").trim();
    const name = realName || htmlName || "Задание.pdf";

    if (url.includes("mod_forum") && !url.includes("/user/") && name.length > 0) {
      if (!url.startsWith("http")) {
        url = BASE_URL + (url.startsWith("/") ? "" : "/") + url;
      }
      if (!seenUrls.has(url)) {
        seenUrls.add(url);
        files.push({ name: name, url: url });
      }
    }
  }
  return { title: title, files: files };
}

function downloadMoodleFile(fileUrl, fileName, cookie, userProps, chatId) {
  try {
    let safeUrl = fileUrl;
    if (!safeUrl.startsWith("http")) {
      safeUrl = BASE_URL + (safeUrl.startsWith("/") ? "" : "/") + safeUrl;
    }
    safeUrl = encodeURI(decodeURI(safeUrl));

    let resp = UrlFetchApp.fetch(safeUrl, {
      headers: { "Cookie": cookie },
      muteHttpExceptions: true,
      followRedirects: true
    });

    let contentType = (resp.getHeaders()["Content-Type"] || resp.getHeaders()["content-type"] || "").toLowerCase();

    if (contentType.includes("text/html")) {
      const sessionRes = ensureMoodleSession(chatId);
      if (sessionRes.success) {
        resp = UrlFetchApp.fetch(safeUrl, {
          headers: { "Cookie": sessionRes.cookie },
          muteHttpExceptions: true,
          followRedirects: true
        });
        contentType = (resp.getHeaders()["Content-Type"] || resp.getHeaders()["content-type"] || "").toLowerCase();
      }
    }

    if (resp.getResponseCode() === 200 && !contentType.includes("text/html")) {
      return resp.getBlob().setName(fileName);
    }
  } catch (e) {}
  return null;
}

function sendTelegramDocument(chatId, blob, caption) {
  try {
    const boundary = "------WebKitFormBoundary" + Utilities.getUuid().replace(/-/g, "");
    const filename = blob.getName();

    const headerText =
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="chat_id"\r\n\r\n` +
      `${chatId}\r\n` +
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="caption"\r\n\r\n` +
      `${caption || ""}\r\n` +
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="document"; filename="${filename}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`;

    const footerText = `\r\n--${boundary}--\r\n`;

    const headerBytes = Utilities.newBlob(headerText).getBytes();
    const fileBytes = blob.getBytes();
    const footerBytes = Utilities.newBlob(footerText).getBytes();
    const fullPayload = headerBytes.concat(fileBytes, footerBytes);

    UrlFetchApp.fetch(`${TELEGRAM_API}/sendDocument`, {
      method: "post",
      contentType: `multipart/form-data; boundary=${boundary}`,
      payload: fullPayload,
      muteHttpExceptions: true
    });
  } catch (e) {
    sendMessage(chatId, `Сбой передачи файла: ${e.message}`);
  }
}

function prepareReplyForm(topicId, cookie) {
  try {
    const discussUrl = `${BASE_URL}/mod/forum/discuss.php?d=${topicId}`;
    const discussResp = UrlFetchApp.fetch(discussUrl, {
      headers: { "Cookie": cookie },
      muteHttpExceptions: true
    });
    const discussHtml = discussResp.getContentText();

    const replyMatch = discussHtml.match(/href="[^"]*\/mod\/forum\/post\.php\?reply=(\d+)/i);
    if (!replyMatch) return { success: false, error: "Кнопка ответа не найдена в топике" };
    const replyPostId = replyMatch[1];

    const replyFormUrl = `${BASE_URL}/mod/forum/post.php?reply=${replyPostId}`;
    const formResp = UrlFetchApp.fetch(replyFormUrl, {
      headers: { "Cookie": cookie },
      muteHttpExceptions: true
    });
    const formHtml = formResp.getContentText();

    let subject = "Re: Ответ";
    const subMatch = formHtml.match(/name="subject"[^>]*value="([^"]*)"/i);
    if (subMatch) subject = subMatch[1];

    const hiddenInputs = {};
    const inputRegex = /<input[^>]+type="hidden"[^>]+>/gi;
    let match;
    while ((match = inputRegex.exec(formHtml)) !== null) {
      const tag = match[0];
      const nameMatch = tag.match(/name="([^"]+)"/i);
      const valMatch = tag.match(/value="([^"]*)"/i);
      if (nameMatch) hiddenInputs[nameMatch[1]] = valMatch ? valMatch[1] : "";
    }

    let itemid = hiddenInputs["attachments"] || "";
    if (!itemid) {
      const itemMatch = formHtml.match(/name="attachments"[^>]*value="(\d+)"/i) ||
                        formHtml.match(/itemid=(\d+)/i) ||
                        formHtml.match(/"itemid":(\d+)/i);
      if (itemMatch) itemid = itemMatch[1];
    }

    let repoId = "5";
    const repoMatch = formHtml.match(/"type":"upload"[^}]*"id":(\d+)/i) ||
                      formHtml.match(/"id":(\d+)[^}]*"type":"upload"/i);
    if (repoMatch) repoId = repoMatch[1];

    return {
      success: true,
      postid: replyPostId,
      subject: subject,
      itemid: itemid,
      repoId: repoId,
      hiddenFields: JSON.stringify(hiddenInputs)
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function uploadFileToMoodleDraft(fileBlob, itemid, repoId, sesskey, cookie) {
  try {
    const uploadUrl = `${BASE_URL}/repository/repository_ajax.php?action=upload`;
    const payload = {
      title: fileBlob.getName(),
      author: "",
      license: "allrightsreserved",
      itemid: itemid,
      repo_id: repoId,
      sesskey: sesskey,
      repo_upload_file: fileBlob
    };

    const resp = UrlFetchApp.fetch(uploadUrl, {
      method: "post",
      payload: payload,
      headers: { "Cookie": cookie },
      muteHttpExceptions: true
    });

    const body = resp.getContentText();
    if (body.includes('"url"') || body.includes('"id"') || (!body.includes('"error"') && body.includes('{'))) {
      return { success: true };
    }
    return { success: false, error: body.substring(0, 150) };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function submitForumReply(replyPostId, subject, messageText, itemid, sesskey, cookie, hiddenFieldsJson) {
  try {
    const postUrl = `${BASE_URL}/mod/forum/post.php`;
    let payload = {};
    if (hiddenFieldsJson) {
      try { payload = JSON.parse(hiddenFieldsJson); } catch (e) {}
    }

    payload["reply"] = replyPostId;
    payload["subject"] = subject;
    payload["message[text]"] = `<p>${messageText}</p>`;
    payload["message[format]"] = "1";
    payload["message[itemid]"] = payload["message[itemid]"] || itemid;
    payload["attachments"] = itemid;
    payload["sesskey"] = sesskey;
    payload["_qf__mod_forum_post_form"] = "1";
    payload["submitbutton"] = "Отправить в форум";

    const resp = UrlFetchApp.fetch(postUrl, {
      method: "post",
      payload: payload,
      headers: {
        "Cookie": cookie,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      muteHttpExceptions: true,
      followRedirects: true
    });

    const finalHtml = resp.getContentText();
    if (finalHtml.includes("discuss.php") || !finalHtml.includes("id=\"mformforum\"") || finalHtml.includes("Ваше сообщение было добавлено") || finalHtml.includes("Your post has been added")) {
      return { success: true };
    }

    const errMatch = finalHtml.match(/class="[^"]*felement[^"]*fitem_ftextarea[^"]*"[^>]*>[\s\S]*?<span class="error"[^>]*>([\s\S]*?)<\/span>/i) ||
                     finalHtml.match(/<span class="error"[^>]*>([\s\S]*?)<\/span>/i);
    return { success: false, error: errMatch ? errMatch[1].replace(/<[^>]+>/g, "").trim() : "Ошибка портала" };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function loginToMoodle(username, password) {
  const loginUrl = `${BASE_URL}/login/index.php`;
  const init = UrlFetchApp.fetch(loginUrl, { muteHttpExceptions: true, followRedirects: true });
  const initHtml = init.getContentText();
  let cookies = parseCookies(init.getAllHeaders()["Set-Cookie"] || init.getAllHeaders()["set-cookie"] || []);

  let logintoken = "";
  const tokenTagMatch = initHtml.match(/<input[^>]+name="logintoken"[^>]*>/i);
  if (tokenTagMatch) {
    const valMatch = tokenTagMatch[0].match(/value="([^"]*)"/i);
    if (valMatch) logintoken = valMatch[1];
  }

  const resp = UrlFetchApp.fetch(loginUrl, {
    method: "post",
    payload: { username: username, password: password, logintoken: logintoken },
    headers: {
      "Cookie": serializeCookies(cookies),
      "Content-Type": "application/x-www-form-urlencoded"
    },
    muteHttpExceptions: true,
    followRedirects: false
  });

  updateCookies(cookies, resp.getAllHeaders()["Set-Cookie"] || resp.getAllHeaders()["set-cookie"] || []);

  const loc = resp.getAllHeaders()["Location"] || resp.getAllHeaders()["location"];
  let targetUrl = loc ? (loc.startsWith("http") ? loc : BASE_URL + (loc.startsWith("/") ? "" : "/") + loc) : `${BASE_URL}/my/`;

  const red = UrlFetchApp.fetch(targetUrl, {
    headers: { "Cookie": serializeCookies(cookies) },
    muteHttpExceptions: true,
    followRedirects: true
  });
  let finalHtml = red.getContentText();
  updateCookies(cookies, red.getAllHeaders()["Set-Cookie"] || red.getAllHeaders()["set-cookie"] || []);

  let sessMatch = finalHtml.match(/"sesskey":"([^"]+)"/i) || finalHtml.match(/sesskey=([a-zA-Z0-9]+)/i);
  let sesskey = sessMatch ? sessMatch[1] : "";

  if (!sesskey) {
    try {
      const myResp = UrlFetchApp.fetch(`${BASE_URL}/my/`, {
        headers: { "Cookie": serializeCookies(cookies) },
        muteHttpExceptions: true,
        followRedirects: true
      });
      const myHtml = myResp.getContentText();
      const m = myHtml.match(/"sesskey":"([^"]+)"/i) || myHtml.match(/sesskey=([a-zA-Z0-9]+)/i);
      if (m) sesskey = m[1];
      updateCookies(cookies, myResp.getAllHeaders()["Set-Cookie"] || myResp.getAllHeaders()["set-cookie"] || []);
    } catch (e) {}
  }

  if (!sesskey || finalHtml.includes("Неверный логин или пароль") || finalHtml.includes("Invalid login")) {
    return { success: false, error: "Неверный логин или пароль study.rea.ru" };
  }

  return { success: true, cookie: serializeCookies(cookies), sesskey: sesskey };
}

function parseCookies(raw) {
  const map = {};
  if (!raw) return map;
  const arr = Array.isArray(raw) ? raw : [raw];
  arr.forEach(c => {
    const part = c.split(";")[0];
    const idx = part.indexOf("=");
    if (idx > -1) map[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  });
  return map;
}

function updateCookies(map, raw) {
  Object.assign(map, parseCookies(raw));
}

function serializeCookies(map) {
  return Object.entries(map).map(([k, v]) => `${k}=${v}`).join("; ");
}

function sendMessage(chatId, text) {
  UrlFetchApp.fetch(`${TELEGRAM_API}/sendMessage`, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({ chat_id: chatId, text: text }),
    muteHttpExceptions: true
  });
}
