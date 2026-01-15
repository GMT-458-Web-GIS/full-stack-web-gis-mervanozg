// server.js - FINAL (Socket.IO Updated & Structure Preserved)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet'); // 🛡️ Güvenlik: HTTP Header Koruması
const compression = require('compression'); // 🚀 Performans: Gzip Sıkıştırma
const path = require('path');
const fs = require('fs'); // Log klasörü kontrolü için
const http = require('http');
const { Server } = require('socket.io');
const morgan = require('morgan'); // HTTP İstek Loglayıcı
const rateLimit = require('express-rate-limit'); // 🛡️ Güvenlik: Rate Limit
const cookieSession = require('cookie-session');
const { v4: uuidv4 } = require('uuid');
const cron = require('node-cron');
const jwt = require('jsonwebtoken'); // 🔐 Socket.IO güvenlik için gerekli

const pool = require('./db');
const logger = require('./utils/logger'); // ⭐️ Winston Logger
const swaggerDocs = require('./utils/swagger'); // 📘 Swagger Docs


// Middleware'leri içe aktar
const { authMiddleware } = require('./middleware/authMiddleware');

// Rotaları içe aktar
const authRoutes = require('./routes/authRoutes');
const publicRoutes = require('./routes/publicRoutes');
const customerRoutes = require('./routes/customerRoutes');
const adminRoutes = require('./routes/adminRoutes');
const mervanRoutes = require('./routes/mervanRoutes');
const paymentRoutes = require('./routes/paymentRoutes');

const app = express();
const port = process.env.PORT || 5000;
const server = http.createServer(app);

// 🔐 GÜVENLİK: ZORUNLU ENVIRONMENT VARİABLE KONTROLÜ
function validateEnvironmentVariables() {
  const required = ['JWT_SECRET', 'SESSION_SECRET', 'DB_USER', 'DB_HOST', 'DB_DATABASE', 'DB_PASSWORD', 'DB_PORT'];
  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    logger.error(`❌ KRİTİK: Aşağıdaki .env değişkenleri eksik: ${missing.join(', ')}`);
    throw new Error(`Eksik ortam değişkenleri: ${missing.join(', ')}`);
  }

  // Production'da PRODUCTION_ORIGIN zorunlu
  if (process.env.NODE_ENV === 'production' && !process.env.PRODUCTION_ORIGIN) {
    logger.error('❌ KRİTİK: Production modunda PRODUCTION_ORIGIN zorunludur!');
    throw new Error('PRODUCTION_ORIGIN ortam değişkeni production modunda zorunludur');
  }

  logger.info('✅ Tüm gerekli ortam değişkenleri doğrulandı');
}

validateEnvironmentVariables();

// ⭐️ Trust Proxy: Nginx/Heroku arkasında IP'yi doğru almak için şart
// ⭐️ Trust Proxy: Nginx/Heroku arkasında IP'yi doğru almak için şart
app.set('trust proxy', 1);

// 🚀 Performans: Yanıtları sıkıştır
app.use(compression());

// --- 1. LOGLAMA YAPILANDIRMASI ---
const logDirectory = path.join(__dirname, 'logs');
if (!fs.existsSync(logDirectory)) {
  fs.mkdirSync(logDirectory);
}

const accessLogStream = fs.createWriteStream(path.join(logDirectory, 'access.log'), { flags: 'a' });

// Morgan'ı en başa koyuyoruz ki gelen her isteği görebilelim
app.use(morgan('combined', { stream: accessLogStream }));
app.use(morgan('dev')); // Konsolda anlık takip için

// --- 2. TEMEL MIDDLEWARE'LER ---
// 🛡️ Güvenlik: Helmet HTTP Header Koruması
// CSP'yi devre dışı bırakıyoruz (React ve dış kaynaklar için esneklik)
// Cross-Origin Resource Policy ayarı ile dış kaynakların yüklenmesine izin veriyoruz
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// 🛡️ Güvenlik: CORS Yapılandırması - Production'da PRODUCTION_ORIGIN zorunlu
const allowedOrigin = process.env.NODE_ENV === 'production'
  ? process.env.PRODUCTION_ORIGIN  // ✅ Zorunlu, fallback yok!
  : ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:5000', undefined]; // Dev ortamında esneklik ve Swagger için

const corsOptions = {
  origin: allowedOrigin,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"]
};
app.use(cors(corsOptions));
app.use(express.json());

// 🔐 GÜVENLİK: Session Yönetimi
// Production'da 'secure: true' olması için HTTPS şarttır.
app.use(cookieSession({
  name: 'rezit_session', // Çerez adı (Tarayıcıda görünür)
  keys: [process.env.SESSION_SECRET], // 'secret' yerine 'keys' kullanmak daha güvenlidir (rotasyon yapılabilir)

  // Güvenlik Ayarları
  httpOnly: true, // 🛡️ XSS Koruması: JavaScript bu çerezi okuyamaz

  // ⭐️ Production'da HTTPS, Local'de HTTP çalışsın
  secure: process.env.NODE_ENV === 'production',

  // ⭐️ SameSite Ayarı:
  // 'lax': Kullanıcı linke tıkladığında çerez gönderilir (Güvenli ve UX dostu)
  // 'strict': Sadece aynı domain içindeyken gönderilir (Bazen çok katı olabilir)
  sameSite: 'lax',

  // Çerez Ömrü: 24 Saat
  maxAge: 24 * 60 * 60 * 1000,

  // Domain Ayarı (Opsiyonel ama temizlik için iyi):
  // Eğer production'da isen ve domain belliyse, alt domainleri de kapsasın diye ekleyebilirsin.
  // Şimdilik otomatize gerek yok, varsayılan (current domain) kalması en güvenlisidir.
}));

app.use((req, _res, next) => {
  if (!req.session) {
    return next(new Error('Session middleware misconfigured'));
  }
  if (!req.session.clientId) {
    req.session.clientId = uuidv4();
  }
  next();
});

// --- SOCKET.IO YAPILANDIRMASI (Güvenli - Token Doğrulamalı) ---
const io = new Server(server, {
  cors: {
    origin: allowedOrigin,
    credentials: true,
    methods: ["GET", "POST"]
  }
});

// 🔐 Socket.IO Güvenlik Middleware: Token Doğrulaması
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error('Token gerekli'));
    }

    // Blacklist kontrolü
    const blacklistCheck = await pool.query(
      'SELECT 1 FROM token_blacklist WHERE token = $1',
      [token]
    );

    if (blacklistCheck.rowCount > 0) {
      return next(new Error('Token geçersiz'));
    }

    // Token doğrulama
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.scope === 'client' || decoded.scope === 'admin' || decoded.scope === 'mervan') {
      socket.data.user = {
        mekanId: decoded.mekan_id,
        mekanModu: decoded.mekan_modu,
        scope: decoded.scope
      };
      next();
    } else {
      next(new Error('Geçersiz token kapsamı'));
    }
  } catch (error) {
    logger.error(`❌ Socket.IO auth hatası: ${error.message}`);
    next(new Error('Token doğrulama başarısız'));
  }
});

io.on('connection', (socket) => {
  const user = socket.data.user;

  // Sadece geliştirme ortamında log bas, prodüksiyonu kirletme
  if (process.env.NODE_ENV !== 'production') {
    logger.info(`✅ Socket.IO bağlantısı kuruldu: ${socket.id} (Mekan: ${user?.mekanId})`);
  }

  // 🔐 Güvenli Event Join: Sadece kendi mekanına ait eventId'lere katılabilir
  socket.on('joinEvent', async (eventId) => {
    if (!eventId) return;

    try {
      // EventId'nin mekanId ile uyumlu olduğunu kontrol et
      let isValid = false;

      if (eventId.startsWith('T-')) {
        // Slot rezervasyonu: T-{mekanId}-{date}-{time} formatı
        const expectedPrefix = `T-${user.mekanId}-`;
        isValid = eventId.startsWith(expectedPrefix);
      } else {
        // Normal etkinlik: Veritabanından kontrol et
        const eventCheck = await pool.query(
          'SELECT 1 FROM etkinlikler WHERE etkinlik_id = $1 AND mekan_id = $2',
          [eventId, user.mekanId]
        );
        isValid = eventCheck.rowCount > 0;
      }

      if (isValid) {
        socket.join(eventId);
        if (process.env.NODE_ENV !== 'production') {
          // logger.debug(`📌 Socket ${socket.id} etkinlik ${eventId}'e katıldı`);
        }
      } else {
        logger.warn(`⚠️ Socket ${socket.id} geçersiz eventId'ye katılmaya çalıştı: ${eventId} (Mekan: ${user.mekanId})`);
      }
    } catch (error) {
      logger.error(`❌ joinEvent hatası: ${error.message}`);
    }
  });

  socket.on('leaveEvent', (eventId) => {
    if (eventId) {
      socket.leave(eventId);
      if (process.env.NODE_ENV !== 'production') {
        // logger.debug(`📌 Socket ${socket.id} etkinlik ${eventId}'den ayrıldı`);
      }
    }
  });

  socket.on('disconnect', () => {
    if (process.env.NODE_ENV !== 'production') {
      logger.info(`❌ Socket.IO bağlantısı kapatıldı: ${socket.id}`);
    }
  });
});

app.use((req, res, next) => {
  req.io = io;
  next();
});

// --- 3. GÜVENLİK (RATE LIMITING - DİNAMİK) ---

// ⭐️ Ortam Kontrolü: Eğer NODE_ENV 'production' DEĞİLSE, geliştirme modundayız demektir.
const isDev = process.env.NODE_ENV !== 'production';

if (isDev) {
  logger.info('⚠️ Geliştirme Modu (Dev Mode) Aktif: Rate Limitler gevşetildi.');
}

// Genel API Limiti
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  // Geliştirme ortamında 10.000 (sınırsız gibi), Canlıda 300
  max: isDev ? 10000 : 300,
  skip: (req) => req.path.startsWith('/socket.io/'),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Çok fazla istek gönderdiniz, lütfen 15 dakika sonra tekrar deneyin.' },
  handler: (req, res, next, options) => {
    logger.warn(`⚠️ Rate Limit Aşıldı (Genel): IP ${req.ip}`);
    res.status(options.statusCode).send(options.message);
  }
});

// Hassas İşlem Limiti (Login vb.)
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  // Geliştirme ortamında 1000, Canlıda 20 (Brute force koruması)
  max: isDev ? 1000 : 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Çok fazla deneme yaptınız. Lütfen bekleyin.' },
  handler: (req, res, next, options) => {
    logger.warn(`⚠️ Rate Limit Aşıldı (Hassas): IP ${req.ip} - URL: ${req.originalUrl}`);
    res.status(options.statusCode).send(options.message);
  }
});

// Genel limiti /api altındaki her şeye uygula
app.use('/api', apiLimiter);

/* ================================================= */
/* ============= API ROTALARI ====================== */
/* ================================================= */

// 1. Hassas Rotalar (Sıkı Limit Uygulanır)
app.use('/api/admin/login', strictLimiter);
app.use('/api/mervan/login', strictLimiter);
app.use('/api/my-bookings', strictLimiter);
// ⭐️ SECURITY: Rezervasyon ve Ödeme için Bot Koruması
app.use('/api/reserve', strictLimiter);
app.use('/api/seats/hold', strictLimiter);
app.use('/api/seats/release', strictLimiter);
app.use('/api/payments/initialize', strictLimiter);

// 2. Auth ve Public Rotalar
app.use('/api', authRoutes);
app.use('/api/public', publicRoutes);
app.use('/api/payments', paymentRoutes);

// 3. Korumalı Rotalar (JWT Kontrollü)
app.use('/api', authMiddleware, customerRoutes);
app.use('/api/admin', authMiddleware, adminRoutes);
app.use('/api/admin', authMiddleware, mervanRoutes);

/* ================================================= */
/* STATIC DOSYA SERVİSİ (PRODUCTION İÇİN) */
/* ================================================= */

app.use('/assets', express.static(path.join(__dirname, 'assets'), { maxAge: '1d' }));
app.use(express.static(path.join(__dirname, 'client/dist'), { maxAge: '1y' }));

// API dışındaki tüm GET isteklerini React'in index.html'ine yönlendir
// Ancak `/assets` gibi statik dizinleri yakalamamak için hariç tutuyoruz
app.get(/^(?!\/api|\/assets).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'client/dist', 'index.html'));
});

// --- 4. GLOBAL HATA YAKALAMA (En Sona) ---
app.use((err, req, res, next) => {
  logger.error(`🚨 Beklenmeyen Hata: ${err.message} - URL: ${req.originalUrl} - IP: ${req.ip} - Stack: ${err.stack}`);
  res.status(500).json({ error: 'Sunucu tarafında beklenmeyen bir hata oluştu.' });
});

/* ================================================= */
/* ============= SUNUCU BAŞLATMA =================== */
/* ================================================= */

server.listen(port, () => {
  logger.info(`🚀 REZiT Sunucusu ${port} portunda çalışıyor... (Mode: ${process.env.NODE_ENV || 'development'}) (Socket.IO Aktif)`);
  swaggerDocs(app, port);
});

// Geliştirme ortamında terminalde hızlı erişim linkleri göster
if (isDev) {
  const clientOrigin = Array.isArray(allowedOrigin) ? allowedOrigin[0] : allowedOrigin;
  const phoneLink = process.env.CONTACT_PHONE ? `tel:${process.env.CONTACT_PHONE}` : null;
  // Ağ arayüzlerinden kullanılabilir IPv4 adreslerini al
  const os = require('os');
  const nets = os.networkInterfaces();
  const addresses = [];
  Object.keys(nets).forEach((name) => {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        addresses.push(net.address);
      }
    }
  });

  logger.info(`🔗 Dev Links -> Customer: ${clientOrigin} | Admin: ${clientOrigin}/admin | Mervan: ${clientOrigin}/mervan`);

  // Konsolda daha görünür bir blok halinde yaz
  console.log('\n=== REZiT Dev Links ===');
  console.log(`- Customer (localhost): ${clientOrigin}`);
  console.log(`- Admin (localhost):    ${clientOrigin}/admin`);
  console.log(`- Mervan (localhost):   ${clientOrigin}/mervan`);
  if (addresses.length > 0) {
    console.log('\n- Network accessible links:');
    addresses.forEach(addr => {
      console.log(`  - Customer: http://${addr}:5173`);
      console.log(`  - Admin:    http://${addr}:5173/admin`);
      console.log(`  - Mervan:   http://${addr}:5173/mervan`);
    });
  }
  console.log('=======================\n');
}

cron.schedule('0 3 * * *', async () => {
  try {
    await pool.query('DELETE FROM token_blacklist WHERE expires_at < NOW()');
    logger.info('🧹 Token blacklist temizlendi');
  } catch (err) {
    logger.error(`Token blacklist temizleme hatası: ${err.message}`);
  }
});

cron.schedule('*/5 * * * *', async () => {
  try {
    const result = await pool.query(
      `DELETE FROM rezerve_koltuklar
             WHERE hold_expires_at IS NOT NULL
               AND hold_expires_at < NOW()`
    );
    const deleted = result.rowCount || 0;
    if (deleted > 0) {
      logger.info(`🪑 Hold süresi dolmuş ${deleted} koltuk temizlendi.`);
    }
  } catch (err) {
    logger.error(`Hold temizleme cron hatası: ${err.message}`);
  }
});

module.exports = { app, server, pool, io };