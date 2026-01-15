<p align="center">
  <img src="logo.png" alt="REZIT Logo" width="400" />
</p>

<h1 align="center">REZIT • Luxury Reservations</h1>

## Live: http://13.60.187.41/

 Presentation: https://www.canva.com/design/DAG-gYmVLoQ/SJXe9scRjZ0k5S-uEhq8aA/edit?utm_content=DAG-gYmVLoQ&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton

<p align="center">
  <strong>A high-security SaaS reservation platform designed for luxury venues and events, based on visual map interaction.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/React-19-blue?logo=react&style=for-the-badge" alt="React">
  <img src="https://img.shields.io/badge/Node.js-20.x-green?logo=nodedotjs&style=for-the-badge" alt="Node.js">
  <img src="https://img.shields.io/badge/Express-5.x-lightgrey?logo=express&style=for-the-badge" alt="Express">
  <img src="https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql&style=for-the-badge" alt="PostgreSQL">
  <br>
  <img src="https://img.shields.io/badge/Security-Anti--Hoarding-red?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/badge/Protection-Rate_Limiting-orange?style=for-the-badge" alt="Rate Limit">
  <img src="https://img.shields.io/badge/Validation-Express--Validator-yellow?style=for-the-badge" alt="Validation">
</p>

<p align="center">
  <img src="landing_page.png" alt="REZiT Interface" width="100%" style="border-radius: 10px; box-shadow: 0 10px 20px rgba(0,0,0,0.19), 0 6px 6px rgba(0,0,0,0.23);" />
</p>

---

!!Privacy Notice: Due to the proprietary nature of the business logic, only selected modules of the source code are shared in this repository. For full access: mervanozgonul@gmail.com

## 🚀 About the Project

**REZIT** is an advanced reservation platform that goes beyond standard reservation forms by enabling venue owners to offer their customers **interactive table/seat selection via a visual map**.

The project has a **Software as a Service (SaaS)** architecture capable of managing multiple venues (multi-tenant) within a single system. It is equipped with industry-standard security measures such as IP-based protection against **Inventory Hoarding** attacks, **Rate Limiting**, and **Server-Side Validation**.

## ✨ Key Features

* 🗺️ **Interactive Visual Map:** Customers can select their desired table/seat from a top-down venue layout.
* 🛡️ **Advanced Security Shield:**
    * **Anti-Hoarding:** IP-based quota system prevents malicious users from locking the entire venue.
    * **Rate Limiting:** API request throttling against bots and brute-force attacks.
    * **Secure Validation:** Strict server-side data validation (`express-validator`).
    * **Nonce & JWT:** `Nonce` and role-based `JWT` authorization to prevent replay attacks.
* ⚡ **Real-Time Updates:** When a reservation is created or canceled, Admin and Customer panels are updated synchronously.
* 🏢 **SaaS & Multi-Tenant:** Manage unlimited venues with isolated data per venue under a single installation.
* 🎟️ **Flexible Reservation Modes:**
    * **Event Mode:** Date- and time-based events such as concerts and theaters.
    * **Slot Mode:** Daily time-slot reservations for restaurants, taverns, etc.
* 🌐 **i18n Support:** Fully localizable infrastructure (Turkish/English).
* 📱 **Responsive Design:** Seamless experience on mobile and desktop devices.

---

## 🏗️ System Architecture: 3-Tier Panel Structure

The system consists of three main Single Page Applications (SPAs), separated by user roles:

### 1. 👨‍💻 Super Admin (Mervan Panel)
The “Super Administrator Mode” where the platform owner manages the entire ecosystem.
* Create and list new venues.
* **Map Editor:** Upload venue layouts and place interactive seats by clicking on the map.
* Create category and pricing templates.
* Generate encrypted (`bcrypt`) API keys.

<p align="center">
  <img src="super_admin.png" alt="Super Admin Panel" width="90%" style="border-radius: 8px; border: 1px solid #333;" />
</p>

### 2. 👔 Venue Manager (Admin Panel)
The panel where business owners manage their own venues.
* **Live Dashboard:** Monitor occupancy rates and real-time reservations.
* **Reservation Management:** Approve, cancel, or edit incoming requests.
* **Event & Pricing:** Create concerts or update table prices in real time.

<p align="center">
  <img src="admin.png" alt="Venue Manager Panel" width="90%" style="border-radius: 8px; border: 1px solid #333;" />
</p>

### 3. 🎟️ Customer Interface (Reservation Panel)
A modern front-end where end users make reservations.
* Seat selection from a visual map.
* Secure and error-free form input (Input Masking).
* View and cancel reservations via the “My Reservations” screen.

<p align="center">
  <img src="customer.png" alt="Customer Reservation Interface" width="90%" style="border-radius: 8px; border: 1px solid #333;" />
</p>

---

## 🛠️ Technology Stack

| Area | Technology | Description |
| :--- | :--- | :--- |
| **Frontend** | **React 19** | Modern Hooks and component-based architecture. |
| **Build Tool** | **Vite** | Fast development and optimized production builds. |
| **Backend** | **Node.js & Express 5** | High-performance and scalable REST API. |
| **Database** | **PostgreSQL** | Connection pooling (`pg`) and transaction management. |
| **Security** | **Rate Limit & Helmet** | DDOS and brute-force protection. |
| **Validation** | **Express-Validator** | Server-side data integrity checks. |
| **File Management** | **Multer** | For venue maps and image uploads. |
| **Testing** | **Jest & Supertest** | Comprehensive testing for API endpoints. |

## 🛡️ Security 

REZIT applies multiple layered security mechanisms at the HTTP, API, and application levels to ensure data integrity and system resilience.

### 🧱 Helmet (HTTP Security Headers)
`helmet` is used to automatically set secure HTTP headers, protecting the application against common web vulnerabilities:
- **XSS (Cross-Site Scripting)** attacks
- **Clickjacking** via `X-Frame-Options`
- **MIME-type sniffing** via `X-Content-Type-Options`
- **Information leakage** by hiding server technology details

This significantly strengthens the baseline security of all API responses.

### ✅ Express-Validator (Server-Side Validation)
`express-validator` ensures that **all incoming client data is validated on the server**, regardless of front-end controls:
- Email format validation
- Phone number length and character checks
- Date, time, and numeric boundary validation
- Protection against malformed or malicious payloads

Invalid or unsafe requests are rejected **before** reaching business logic or the database layer.

### 🚦 Rate Limiting
API-level rate limiting is applied to prevent:
- Brute-force attacks
- Bot-driven abuse
- Inventory hoarding attempts

Requests exceeding defined thresholds are automatically blocked or throttled.

### 🔐 JWT, Nonce & Replay Protection
- **JWT (JSON Web Tokens)** are used for stateless authentication and role-based authorization.
- **Nonces** are issued per request/session to prevent replay attacks.
- Tokens are verified on every protected endpoint.

### 🧾 Transactional Integrity (ACID)
All critical reservation operations are executed inside a **single database transaction**:
- Customer creation
- Seat locking
- Reservation record
- Payment record

If any step fails, the entire operation is rolled back, ensuring consistency and preventing partial writes.

---

> These mechanisms work together to provide **defense-in-depth**, ensuring REZIT remains secure, scalable, and production-ready.
---

<p align="center"> © 2025 REZIT. All Rights Reserved. </p>


## ✅ Feature Compliance Checklist

### 1. Managing Different User Types (20%)
- [x] **Implemented.** The system strictly separates concerns between `Super Admin`, `Venue Admin`, and `Customer` roles using JWT-based middleware (`authMiddleware.js`).

### 2. CRUD Operations (15%)
- [x] **Implemented.** Full RESTful operations available for:
    - Venues (Create, Read, Update, Delete)
    - Reservations (Book, Cancel, Update)
    - Events & Pricing

### 3. Authentication & Security (15%)
- [x] **Implemented.**
    - **JWT (JSON Web Tokens):** Secure session management.
    - **Role-Based Access Control (RBAC):** Middleware prevents unauthorized access.
    - **Bonus Security Features:**
        - **Rate Limiting:** Protects against DDoS and Brute Force attacks.
        - **Helmet:** Sets secure HTTP headers.
        - **SQL Injection Protection:** Parameterized queries used throughout.

### 4. Performance Testing (25%)
- [x] **Implemented with Artillery.**
    - Conducted **Load**, **Stress**, and **Endurance** tests.
    - **Result:** System handled **20 Req/Sec** with **%0 Error Rate** and **2ms** average latency.
    - **Report:** Detailed graphs and analysis are available in `PERFORMANS_RAPORU.md`.

### 5. API Development (25%)
- [x] **Implemented.**
    - **Swagger UI:** Automated API documentation available at (http://localhost:5000/api-docs).
    - **Postman:** Verified with a comprehensive test suite.
    - **Endpoints:** Includes spatial (venue locations) and non-spatial resources.

### 6. Hosting (20%)
- [x] **Implemented.**
    - The project is designed to be cloud-native and deployable on **AWS (Amazon Web Services)**.
    - Docker-ready architecture support containerized deployment (EC2/ECS).

```
📁 REZIT_PROJESI/
│
├── 🖥️ server.js                # Backend API Sunucusu
├── 📦 package.json              # Backend bağımlılıkları ve script'ler
├── 🧪 server.test.js            # API testleri (Jest + Supertest)
├── 🧩 .gitignore                 # Backend gizli dosyaları
├── 🗃️ db.js                      # Veritabanı (PostgreSQL) bağlantısı
│
├── 🗂️ assets/                    # Yüklenen haritalar, logolar ve arka planlar
│   ├── 🖼️ logo.png                 # REZIT Logosu
│   ├── 🗺️ venue-map.png            # Örnek mekan haritası
│   ├── 🌄 background.jpg          # Müşteri paneli arka planı
│   └── 🌃 mervanbackgr.png       # Mervan paneli arka planı
│
├── 🛣️ routes/                    # API Endpoint Tanımları
│   ├── 🔑 authRoutes.js            # /login, /config rotaları
│   ├── 👤 customerRoutes.js        # Müşteri API rotaları (/reserve, /events)
│   ├── 🛠️ adminRoutes.js           # Admin API rotaları (/admin/bookings)
│   ├── 👑 mervanRoutes.js          # Süper Admin API rotaları (/admin/mekan)
│   └── 🌍 publicRoutes.js          # Herkese açık rotalar (/my-bookings)
│
├── 🧠 controllers/                # API İş Mantığı (Business Logic)
│   ├── 🔑 authController.js        # Login ve config mantığı
│   ├── 👤 customerController.js    # Rezervasyon oluşturma, koltuk alma
│   ├── 🛠️ adminController.js       # Admin panel mantığı (etkinlik, fiyat yönetimi)
│   ├── 👑 mervanController.js      # Süper Admin mantığı (mekan yaratma)
│   └── 🌍 publicController.js      # Rezervasyon sorgulama mantığı
│
├── 🛡️ middleware/                # Ara Katman Yazılımları
│   └── 🔒 authMiddleware.js        # JWT Token doğrulama ve rol (scope) kontrolü
│
├── 🔧 utils/                     # Yardımcı Fonksiyonlar
│   ├── 🗂️ fileUpload.js          # Resim yükleme (Multer) ayarları
│   └── 🏷️ categoryUtils.js       # Koltuk ID'lerine göre kategori atama
│
└── 💻 client/                    # React (Frontend)
    ├── 📦 package.json          # Frontend bağımlılıkları (React, Vite)
    ├── ⚡ vite.config.js         # Vite ayarları ve API proxy yönlendirmesi
    ├── 🧩 .gitignore             # Frontend gizli dosyaları
    ├── 🪟 index.html             # React giriş noktası (root element)
    ├── 📁 public/
    │   └── ✨ vite.svg               # Örnek public asset
    └── 📁 src/                   # React kaynak dosyaları
        ├── 🚀 main.jsx            # React Router tanımlı ana giriş
        ├── 🌍 App.jsx              # Ana Rota kabuğu (Outlet)
        ├── 🎨 styles.css          # Global stiller
        ├── 🌐 i18n.js               # Dil (i18next) yapılandırması
        ├── 📁 components/         # Paylaşılan bileşenler
        │   ├── 🗺️ SeatMap.jsx      # İnteraktif koltuk haritası bileşeni
        │   ├── 🧾 Summary.jsx      # Rezervasyon özeti bileşeni
        │   └── 🔄 LanguageSwitcher.jsx # Dil değiştirici
        ├── 📁 pages/              # Sayfa bileşenleri
        │   ├── 👤 Customer.jsx   # / (Müşteri Paneli)
        │   ├── 🛠️ Admin.jsx      # /admin (Admin Paneli)
        │   └── 👑 Mervan.jsx     # /mervan (Süper Admin Paneli)
        ├── 📁 locales/            # Dil çeviri dosyaları
        │   ├── 📁 en/
        │   │   └── 📜 translation.json
        │   └── 📁 tr/
        
        │       └── 📜 translation.json
        └── 📁 assets/
            └── ✨ react.svg
