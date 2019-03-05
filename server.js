require('dotenv').load();
const express = require('express');
const passport = require('passport');
const winston = require('winston');
const { Papertrail } = require('winston-papertrail');

const testClientPort = {
  client1: '3001',
  client2: '3002',
};

const db = {
  users: {
    newUser: (userInfo, onSuccess, onFailure) => {
      try {
        // db.users.push(userInfo);
        onSuccess(userInfo);
      } catch (err) {
        onFailure(err);
      }
    },
  },
};

const ptTransport = new Papertrail({
  host: process.env.PAPERTRAIL_URL,
  port: process.env.PAPERTRAIL_PORT,
  logFormat: (level, message) => {
    return `[${level}] ${message}`;
  },
  timestamp: true,
  hostname: process.env.PAPERTRAIL_HOSTNAME,
  program: process.env.APPNAME,
});
const consoleLogger = new winston.transports.Console({
  level: process.env.LOG_LEVEL,
  timestamp() {
    return new Date().toString();
  },
  colorize: true,
});

// monkey pach papertrail to remove meta from log() args
const { log } = ptTransport;
// eslint-disable-next-line func-names
ptTransport.log = function(level, msg, meta, callback) {
  const cb = callback === undefined ? meta : callback;
  return log.apply(this, [level, msg, cb]);
};

// eslint-disable-next-line new-cap
const logger = new winston.createLogger({
  transports: [ptTransport, consoleLogger],
});

logger.stream = {
  write: (message, _encoding) => {
    logger.info(message);
  },
};

ptTransport.on('error', err => logger && logger.error(err));

ptTransport.on('connect', message => logger && logger.info(message));

const app = express();

app.set('port', process.env.PORT || 3000);
app.use(express.static(`${__dirname}/build`));

app.use(require('morgan')('combined', { stream: logger.stream }));
// app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(
  require('express-session')({
    cookie: {
      domain: process.env.SESSION_DOMAIN || undefined,
      samesite: false,
    },
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true,
  })
);

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

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
  // console.log('serializing', user);
  cb(null, user);
});

passport.deserializeUser((obj, cb) => {
  // console.log('deserializing', obj);
  cb(null, obj);
});

require('./providers/pass-google').setup(passport, app, db.users);
require('./providers/pass-github').setup(passport, app, db.users);

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

const checkAuthentication = (req, res, next) => {
  console.log('checking authentication');
  if (req.isAuthenticated()) {
    console.log('isauth');
    res.redirect(
      `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
        process.env.SESSION_DOMAIN ? req.params.app : ''
      }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`
    );
  } else {
    console.log(`is not auth'd`);
    // not auth'd, choose provider
    next();
  }
};

/*
  /login/:app - choose login provider
    auth'd: -> go to /login/:app/:provider
    not auth'd: - choose provider
      login, google, facebook -> then go to /login/:app/:provider
*/
app.get('/login/:app', checkAuthentication, (req, res) => {
  res.send(`
    <html>
      <body>
        Hello! ${req.params.app}. Choose provider.<br />
        <a href="/login/${req.params.app}/github">Github</a><br />
        <a href="/login/${req.params.app}/google">Google</a>
      </body>
    </html>
  `);
});

/*
  /login/:app/:provider - login
    success -> app.jsdevtools.com
    fail -> /login/:app
*/
app.get('/login/:app/:provider', (req, res, next) => {
  console.log('checking authentication');
  if (req.isAuthenticated()) {
    console.log(`isauth, app=${req.params.app}, provider:${req.params.provider}`);
    res.redirect(
      `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
        process.env.SESSION_DOMAIN ? req.params.app : ''
      }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`
    );
  } else {
    console.log(`is not auth'd, try logging in, app=${req.params.app}, provider:${req.params.provider}`);
    passport.authenticate(req.params.provider, {
      callbackURL: `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
        process.env.SESSION_DOMAIN ? 'login' : ''
      }${process.env.SESSION_DOMAIN || 'localhost:3000'}/login/${req.params.app}/${
        req.params.provider
      }/return`,
    })(req, res, next);
  }
});

app.get('/login/:app/:provider/return', (req, res) => {
  const redirect = `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
    process.env.SESSION_DOMAIN ? req.params.app : ''
  }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`;
  logger.info(`lapr ${redirect}`);
  return res.redirect(redirect);
});

/*
app.get(
  '/login/:app/:provider/return',
  (req, res, next) => {
    const callbackURL = `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
      process.env.SESSION_DOMAIN ? 'login' : ''
    }${process.env.SESSION_DOMAIN || 'localhost:3000'}/login/${req.params.app}/${req.params.provider}/return`;
    logger.info(`/login/:app/:provider/return ${callbackURL}`);
    return passport.authenticate(req.params.provider, {
      failureRedirect: '/login',
      callbackURL,
    })(req, res, next);
  },
  (req, res) => {
    const redirect = `${process.env.SESSION_DOMAIN ? 'https' : 'http'}://${
      process.env.SESSION_DOMAIN ? req.params.app : ''
    }${process.env.SESSION_DOMAIN || `localhost:${testClientPort[req.params.app]}`}`;
    logger.info(`lapr ${redirect}`);
    return res.redirect(redirect);
  }
);
*/

/*
  / - page with links to apps to log into
    auth'd or not: - choose app
      myapp1, myapp2 -> /login/:app
*/
app.get('*', (_req, res, _next) => {
  // console.log('req', _req);
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
