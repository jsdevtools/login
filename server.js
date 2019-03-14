require('dotenv').load();
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const cors = require('cors');
const RedisStore = require('connect-redis')(session);
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const { logger } = require('./logger');

const testClientPort = {
  client1: '3001',
  client2: '3002',
};

const db = {
  users: {
    newUser: (userInfo, onSuccess, onFailure) => {
      try {
        onSuccess(userInfo);
      } catch (err) {
        onFailure(err);
      }
    },
  },
};

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.  However, due to the fact that this
// example does not have a database, the complete Facebook profile is serialized
// and deserialized.
passport.serializeUser((user, cb) => {
  logger.info(`serializing ${JSON.stringify(user)}`);
  cb(null, user);
});

passport.deserializeUser((obj, cb) => {
  logger.info(`deserializing ${obj}`);
  cb(null, obj);
});

const app = express();

app.set('port', process.env.PORT || 3000);

app.use(morgan('combined', { stream: logger.stream }));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    store: new RedisStore({
      url: process.env.REDIS_URL,
    }),
    cookie: {
      domain: process.env.SESSION_DOMAIN || undefined,
      sameSite: false,
      secure: false,
    },
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true,
    path: '/',
  })
);

app.set('trust proxy', 1);

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

require('./providers/pass-google').setup(passport, app, db.users);
require('./providers/pass-github').setup(passport, app, db.users);
require('./providers/pass-local').setup(passport, app, db.users);

if (app.get('env') === 'development') {
  // development error handler
  // will print stacktrace
  app.use((err, req, res, _next) => {
    logger.warn(JSON.stringify(err));
    res.status(err.code || 500).json({
      status: 'error',
      message: err,
    });
  });
  app.use((req, res, next) => {
    console.log(`urlIt: ${req.url}`);
    next();
  });
} else {
  // production error handler
  // no stacktraces leaked to user
  app.use((err, req, res, _next) => {
    logger.warn(JSON.stringify(err));
    res.status(err.status || 500).json({
      status: 'error',
      message: err.message,
    });
  });
}

app.use(cors());

const checkAuthentication = (req, res, next) => {
  logger.info(`checking authentication`);
  if (req.isAuthenticated()) {
    logger.info(`isauth`);
    res.redirect(
      `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
        process.env.SESSION_DOMAIN ? req.params.app : ''
      }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`
    );
  } else {
    logger.info(`is not auth'd`);
    // not auth'd, choose provider
    next();
  }
};

app.get('/logout', (req, res) => {
  console.log('>> /logout');
  if (req.session !== undefined) req.session.destroy();
  res.redirect('/');
});

/*
  /login/:app - choose login provider
    auth'd: -> go to /login/:app/:provider
    not auth'd: - choose provider
      login, google, facebook -> then go to /login/:app/:provider
*/
app.get('/login/:app', checkAuthentication, (req, res) => {
  console.log('/login/:app');
  // Redirects back to app if authenticated. If not, prompt for authentication method.
  res.send(`
    <html>
      <body>
      <h1>Login</h1>
        Hello! Choose provider to log into ${req.params.app}.<br />
        <a href="/login/${req.params.app}/github">Github</a><br />
        <a href="/login/${req.params.app}/google">Google</a><br />
        <h3>Local</h3>
        <form action='/login/${req.params.app}/local' method='post'>
          <div>
            <label for='email'>Email:</label><br/>
            <input type='text' name='email' id='email' require>
          </div>
          <br/>
          <div>
            <label for='pass'>Password:(8 characters minimum)</label><br/>
            <input type='password' name='password' id='pass' minlength='8' required>
          </div>
          <br/>
          <input type='submit' value='Login'><br/>
        </form>
      </body>
    </html>
  `);
});

app.post('/login/:app/local', (req, res, next) => {
  console.log('post /login/:app/local');
  passport.authenticate('local', {
    successRedirect: `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
      process.env.SESSION_DOMAIN ? req.params.app : ''
    }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`,
    failureRedirect: `/login/${req.params.app}`,
    passReqToCallback: true,
    session: true,
  })(req, res, next);
});

/*
 /login/:app/:provider - login
 success -> app.jsdevtools.com
 fail -> /login/:app
*/
app.get('/login/:app/:provider', (req, res, next) => {
  console.log('get /login/:app/:provider');
  // if authenticagted, redirect back to app. If not, then authenticate.
  // successful authentication ==> /login/app/provider/return
  logger.info('checking authentication');
  if (req.isAuthenticated()) {
    logger.info(`isauth, app=${req.params.app}, provider:${req.params.provider}`);
    res.redirect(
      `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
        process.env.SESSION_DOMAIN ? req.params.app : ''
      }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`
    );
  } else {
    logger.info(`is not auth'd, try logging in, app=${req.params.app}, provider:${req.params.provider}`);
    passport.authenticate(req.params.provider, {
      callbackURL: `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
        process.env.SESSION_DOMAIN ? 'login' : ''
      }${process.env.SESSION_DOMAIN || 'localhost:3000'}/login/${req.params.app}/${
        req.params.provider
      }/return`,
    })(req, res, next);
  }
});

app.get(
  '/login/:app/:provider/return',
  (req, res, next) =>
    passport.authenticate(req.params.provider, {
      failureRedirect: '/login',
      callbackURL: `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
        process.env.SESSION_DOMAIN ? 'login' : ''
      }${process.env.SESSION_DOMAIN || 'localhost:3000'}/login/${req.params.app}/${
        req.params.provider
      }/return`,
    })(req, res, next),
  (req, res) =>
    req.session.save(() =>
      res.redirect(
        `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
          process.env.SESSION_DOMAIN ? req.params.app : ''
        }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`
      )
    )
);

/*
  / - page with links to apps to log into
    auth'd or not: - choose app
      myapp1, myapp2 -> /login/:app
*/
app.get('*', (req, res, _next) => {
  console.log('get *');
  res.send(`
    <html>
      <body>
        Hello Login! Choose app.<br />
        <a href="/login/client1">Client1</a><br />
        <a href="/login/client2">Client2</a>
      </body>
    </html>
  `);
});

app.listen(app.get('port'), () => {
  console.log(`Node app is running at localhost:${app.get('port')}`);
});
