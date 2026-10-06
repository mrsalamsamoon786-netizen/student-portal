# Student Portal - Production Online Version

This package converts the existing Student Portal from browser-only storage to a real PostgreSQL-backed online system.

## Included
- Existing portal UI and Admin panel
- PostgreSQL-backed users, sessions, shared content and student progress
- Separate Student and Admin login
- Strong passwords: 10-128 characters, uppercase + lowercase + number + symbol
- Passwords stored as bcrypt hashes, never plain text
- Demo accounts removed
- Student self-registration disabled; Admin creates student accounts
- Admin can create/delete accounts and reset passwords
- Secure HTTP-only session cookies
- Security headers via Helmet
- Login rate limiting
- PostgreSQL session store
- Admin backup download endpoint
- Production environment variables

## Real-system security choices
1. Do not put database credentials in the frontend.
2. Set a random `SESSION_SECRET` of at least 32 characters.
3. Use HTTPS in production.
4. Keep PostgreSQL private to the server when the hosting provider allows it.
5. Create student accounts from Admin instead of allowing public registration.
6. Take regular database backups from the hosting provider.

## Deployment
Use one Node.js web service that serves `frontend/index.html` and connects to PostgreSQL. Render, Railway, or another Node/PostgreSQL provider can be used.

Environment variables:
- `DATABASE_URL`
- `SESSION_SECRET`
- `PORT` (usually supplied by the host)
- `FRONTEND_ORIGIN` (leave blank when frontend and backend use the same domain)
- `CROSS_SITE_COOKIES=false` for same-origin deployment

First launch:
1. Create PostgreSQL database.
2. Set environment variables.
3. Run `npm install` in `backend`.
4. Run `npm start`.
5. Open the website.
6. The first screen creates the single initial Admin account.
7. Admin then creates student accounts and manages portal content.

The server automatically creates the required tables on startup. `database/schema.sql` is included as a reference.
