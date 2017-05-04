'use strict';

const bluebird = require('bluebird');
const crypto = bluebird.promisifyAll(require('crypto'));
const nodemailer = require('nodemailer');
//const passport = require('passport');
const Admin = require('../models/Admin');

/**
 * GET /login
 * Login page.
 */
exports.getLogin = (req, res) => {
  if (req.admin) {
    return res.redirect('/admin/profile');
  }
  res.render('admin/login', {
    title: 'Login'
  });
};

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/admin/login');
  }
  const admin = new Admin({
    email: req.body.email,
    password: req.body.password
  });
  Admin.findOne({ email: req.body.email.toLowerCase() }, (err, admin) => {
    if (err) { 
		return next(err);
	}
    if (!admin) {
		req.flash('errors', { msg: `Email ${req.body.email} not found.` });
		return res.redirect('/admin/login');
    }
    admin.comparePassword(req.body.password, (err, isMatch) => {
      if (err) { 
		return next(err);
	  }
      if (isMatch) {
        req.flash('success', { msg: 'Success! You are logged in.' });
		return res.redirect(req.session.returnTo || '/admin/profile');
      }
      req.flash('errors',{ msg: 'Invalid email or password.' });
      return res.redirect('/admin/login');
    });
  });
};

/**
 * GET /logout
 * Log out.
 */
exports.logout = (req, res) => {
  req.logout();
  res.redirect('/admin');
};

/**
 * GET /signup
 * Signup page.
 */
exports.getSignup = (req, res) => {
  if (req.admin) {
    return res.redirect('/admin');
  }
  res.render('admin/signup', {
    title: 'Create Account'
  });
};

/**
 * POST /signup
 * Create a new local account.
 */
exports.postSignup = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/admin/signup');
  }

  const admin = new Admin({
    email: req.body.email,
    password: req.body.password
  });

  Admin.findOne({ email: req.body.email }, (err, existingAdmin) => {
    if (err) { return next(err); }
    if (existingAdmin) {
      req.flash('errors', { msg: 'Account with that email address already exists.' });
      return res.redirect('/admin/signup');
    }
    admin.save((err) => {
      if (err) { return next(err); }
      req.logIn(admin, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect('/admin');
      });
    });
  });
};

/**
 * GET /account
 * Profile page.
 */
exports.getAccount = (req, res) => {
  res.render('admin/profile', {
    title: 'Account Management'
  });
};

/**
 * POST /admin/profile
 * Update profile information.
 */
exports.postUpdateProfile = (req, res, next) => {
  req.assert('email', 'Please enter a valid email address.').isEmail();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/account');
  }

  Admin.findById(req.admin.id, (err, admin) => {
    if (err) { return next(err); }
    admin.email = req.body.email || '';
    admin.profile.name = req.body.name || '';
    admin.profile.gender = req.body.gender || '';
    admin.profile.location = req.body.location || '';
    admin.profile.website = req.body.website || '';
    admin.save((err) => {
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', { msg: 'The email address you have entered is already associated with an account.' });
          return res.redirect('/account');
        }
        return next(err);
      }
      req.flash('success', { msg: 'Profile information has been updated.' });
      res.redirect('/account');
    });
  });
};

/**
 * POST /admin/password
 * Update current password.
 */
exports.postUpdatePassword = (req, res, next) => {
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/account');
  }

  Admin.findById(req.admin.id, (err, admin) => {
    if (err) { return next(err); }
    admin.password = req.body.password;
    admin.save((err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Password has been changed.' });
      res.redirect('/account');
    });
  });
};

/**
 * POST /admin/delete
 * Delete admin account.
 */
exports.postDeleteAccount = (req, res, next) => {
  Admin.remove({ _id: req.admin.id }, (err) => {
    if (err) { return next(err); }
    req.logout();
    req.flash('info', { msg: 'Your account has been deleted.' });
    res.redirect('/');
  });
};

/**
 * GET /admin/unlink/:provider
 * Unlink OAuth provider.
 */
exports.getOauthUnlink = (req, res, next) => {
  const provider = req.params.provider;
  Admin.findById(req.admin.id, (err, admin) => {
    if (err) { return next(err); }
    admin[provider] = undefined;
    admin.tokens = admin.tokens.filter(token => token.kind !== provider);
    admin.save((err) => {
      if (err) { return next(err); }
      req.flash('info', { msg: `${provider} account has been unlinked.` });
      res.redirect('/account');
    });
  });
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.getReset = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  Admin
    .findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires').gt(Date.now())
    .exec((err, admin) => {
      if (err) { return next(err); }
      if (!admin) {
        req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
        return res.redirect('/forgot');
      }
      res.render('admin/reset', {
        title: 'Password Reset'
      });
    });
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postReset = (req, res, next) => {
  req.assert('password', 'Password must be at least 4 characters long.').len(4);
  req.assert('confirm', 'Passwords must match.').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('back');
  }

  const resetPassword = () =>
    Admin
      .findOne({ passwordResetToken: req.params.token })
      .where('passwordResetExpires').gt(Date.now())
      .then((admin) => {
        if (!admin) {
          req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
          return res.redirect('back');
        }
        admin.password = req.body.password;
        admin.passwordResetToken = undefined;
        admin.passwordResetExpires = undefined;
        return admin.save().then(() => new Promise((resolve, reject) => {
          req.logIn(admin, (err) => {
            if (err) { return reject(err); }
            resolve(admin);
          });
        }));
      });

  const sendResetPasswordEmail = (admin) => {
    if (!admin) { return; }
    const transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        admin: process.env.SENDGRID_USER,
        pass: process.env.SENDGRID_PASSWORD
      }
    });
    const mailOptions = {
      to: admin.email,
      from: 'hackathon@starter.com',
      subject: 'Your Hackathon Starter password has been changed',
      text: `Hello,\n\nThis is a confirmation that the password for your account ${admin.email} has just been changed.\n`
    };
    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('success', { msg: 'Success! Your password has been changed.' });    
      });
  };

  resetPassword()
    .then(sendResetPasswordEmail)
    .then(() => { if (!res.finished) res.redirect('/'); })
    .catch(err => next(err));
};

/**
 * GET /forgot
 * Forgot Password page.
 */
exports.getForgot = (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('admin/forgot', {
    title: 'Forgot Password'
  });
};

/**
 * POST /forgot
 * Create a random token, then the send admin an email with a reset link.
 */
exports.postForgot = (req, res, next) => {
  req.assert('email', 'Please enter a valid email address.').isEmail();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/forgot');
  }

  const createRandomToken = crypto
    .randomBytesAsync(16)
    .then(buf => buf.toString('hex'));

  const setRandomToken = token =>
    Admin
      .findOne({ email: req.body.email })
      .then((admin) => {
        if (!admin) {
          req.flash('errors', { msg: 'Account with that email address does not exist.' });
        } else {
          admin.passwordResetToken = token;
          admin.passwordResetExpires = Date.now() + 3600000; // 1 hour
          admin = admin.save();
        }
        return admin;
      });

  const sendForgotPasswordEmail = (admin) => {
    if (!admin) { return; }
    const token = admin.passwordResetToken;
    const transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        admin: process.env.SENDGRID_USER,
        pass: process.env.SENDGRID_PASSWORD
      }
    });
    const mailOptions = {
      to: admin.email,
      from: 'hackathon@starter.com',
      subject: 'Reset your password on Hackathon Starter',
      text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        http://${req.headers.host}/reset/${token}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`
    };
    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('info', { msg: `An e-mail has been sent to ${admin.email} with further instructions.` });
      });
  };

  createRandomToken
    .then(setRandomToken)
    .then(sendForgotPasswordEmail)
    .then(() => res.redirect('/forgot'))
    .catch(next);
};
