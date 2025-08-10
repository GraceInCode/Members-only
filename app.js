const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const { body, validationResult } = require('express-validator');
const pool = require('./db')
const app = express();
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const PORT = process.env.PORT || 8000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'your_secret_change_in_production'

// Passport configuration
passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
        try {
            const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (user.rows.length === 0) {
                return done(null, false, { message: 'Incorrect email.' });
            }
            const match = await bcrypt.compare(password, user.rows[0].password);
            if (!match) {
                return done(null, false, { message: 'Incorrect password.' });
            }
            return done(null, user.rows[0]);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [id])
        done(null, user.rows[0]);
    } catch (err) {
        done(err);
    }
})

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.set('trusted proxy', true); // for secure cookies in production
app.use(session({ 
    secret: SESSION_SECRET,
    resave: false, 
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 
    }
}))
app.use(passport.initialize());
app.use(passport.session());
app.use('/styles', express.static('styles'));
app.use((err, req, res, next) => {
  console.error('Uncaught error:', err && err.stack ? err.stack : err);
  res.status(500).send('Internal Server Error (logged)');
});
    

// Sign-up route
app.get('/sign-up' , (req, res) => {
    res.render('sign-up', { errors: [] });
});

app.post('/sign-up', [
    body('firstName').trim().notEmpty().withMessage('First name is required'),
    body('lastName').trim().notEmpty().withMessage('Last name is required'),
    body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 5 }).withMessage('Password must be at least 5 characters long'),
    body('confirmPassword').custom((value, { req }) => value === req.body.password).withMessage('Passwords do not match'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('sign-up', { errors: errors.array() });
    }

    const { firstName, lastName, email, password, isAdmin } = req.body;
    try {
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (user.rows.length > 0) {
            return res.render('sign-up', { errors: [{ msg: 'Email already exists' }] });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (first_name, last_name, email, password, is_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [firstName, lastName, email, hashedPassword, isAdmin === 'on']
        )
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.render('sign-up', { errors: [{ msg: 'An error occurred while signing up' }] });
    }
});

// Ensure user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login'); 
}

// Join-club route
app.get('/join-club', ensureAuthenticated, (req, res) => {
    res.render('join-club', { error: null });
});

app.post('/join-club', ensureAuthenticated, (req, res) => {
    const passcode = process.env.CLUB_PASSCODE || 'defaultpassword'; // TODO: Use env variable for passcode
    if (req.body.passcode === passcode) {
        pool.query('UPDATE users SET is_member = TRUE WHERE ID = $1', [req.user.id], (err) => {
            if (err) console.error(err);
            res.redirect('/');
        });
        } else {
        res.render('join-club', { error: 'Incorrect passcode' });
        }
});

// Login route
app.get('/login', (req, res) => {
    res.render('login', { error: [] });
})

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
}));

// New mwssage route
app.get('/new-message', ensureAuthenticated, (req, res) => {
    res.render('new-message', { errors: [] });
});

app.post('/new-message', ensureAuthenticated, [
    body('title').trim().notEmpty().withMessage('Title is required'),
    body('text').trim().notEmpty().withMessage('Text is required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('new-message', { errors: errors.array() });
    }
    await pool.query(
        'INSERT INTO messages (title, text, user_id) VALUES ($1, $2, $3)',
        [req.body.title, req.body.text, req.user.id]
    );
    res.redirect('/');
});


// Home route
app.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT messages.*, users.first_name, users.last_name
       FROM messages
       JOIN users ON messages.user_id = users.id
       ORDER BY timestamp DESC`
    );

    const data = {
      messages: result.rows || [],
      user: req.user || null,
      dbDown: false
    };

    // use callback to capture render errors
    res.render('index', data, (err, html) => {
      if (err) {
        console.error('EJS render error for / :', err);
        // temporary debugging response — remove or soften in production
        return res.status(500).send(`Template render error: ${err.message}`);
      }
      res.send(html);
    });

  } catch (err) {
    console.error('Handler error for / :', err);
    // safe fallback: render empty page or send simple OK for now
    return res.status(500).send('Server error (see logs).');
  }
});

// Debug route
app.get('/_debug_env', (req, res) => {
  res.json({
    NODE_ENV: process.env.NODE_ENV || null,
    HAS_DATABASE_URL: Boolean(process.env.DATABASE_URL),
    HAS_PORT: Boolean(process.env.PORT)
  });
});

app.get('/me', (req, res) => {
    res.json({
        authenticated: req.isAuthenticated(),
        user: req.user || null,
        sessionID: req.sessionID || null,
    })
})

// Logout route
app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/'))
})

// Delete Route
function ensureAdmin(req, res, next) {
    if (req.user && req.user.is_admin) return next();
    res.status(403).send('Forbidden');
}

app.post('/delete-message/:id', ensureAdmin, async (req, res) => {
    await pool.query('DELETE FROM messages WHERE id = $1', [req.params.id]);
    res.redirect('/')
})

app.listen(PORT, () => {
    console.log(`Server is running on ${PORT}`);
});