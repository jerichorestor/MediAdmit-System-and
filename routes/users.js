const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { requirePermission } = require('../middleware/auth');
const audit = require('../utils/audit');

const router = express.Router();
router.use(requirePermission('manageUsers'));

// ---------- LIST ----------
router.get('/', async (req, res) => {
  const status = req.query.status || '';
  const role = req.query.role || '';
  const q = (req.query.q || '').trim();

  const filter = {};
  if (status) filter.status = status;
  if (role) filter.role = role;
  if (q) {
    const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    filter.$or = [{ firstName: rx }, { lastName: rx }, { email: rx }, { employeeId: rx }];
  }

  const users = await User.find(filter).sort({ status: 1, lastName: 1 });
  const counts = {
    all: await User.countDocuments(),
    pending: await User.countDocuments({ status: 'Pending' }),
  };
  const pendingUsers = await User.find({ status: 'Pending' }).sort({ createdAt: 1 });
  const resetRequests = await User.find({ resetRequestedAt: { $ne: null }, status: 'Active' }).sort({ resetRequestedAt: 1 });

  let selected = null;
  if (req.query.id) selected = await User.findById(req.query.id).catch(() => null);
  if (!selected) selected = users[0] || null;

  // Show a new temporary password only once
  const tempPassword = req.session.tempPassword || null;
  delete req.session.tempPassword;
  req.session.save(() => res.render('users', {
    title: 'Users', users, selected, counts, pendingUsers, resetRequests, status, role, q,
    ROLES: User.ROLES, PERMISSIONS: User.PERMISSIONS, tempPassword,
  }));
});

// ---------- ADD USER (created by admin, active right away) ----------
router.post('/add', async (req, res) => {
  const f = req.body;
  if (!f.firstName || !f.lastName || !f.employeeId || !f.email || !User.ROLES.includes(f.role)) {
    req.session.flash = { type: 'err', text: 'Please fill in all fields for the new user.' };
    return res.redirect('/users');
  }
  const exists = await User.findOne({ $or: [{ email: f.email.toLowerCase() }, { employeeId: f.employeeId }] });
  if (exists) {
    req.session.flash = { type: 'err', text: 'A user with that email or employee ID already exists.' };
    return res.redirect('/users');
  }
  const temp = 'Temp' + Math.random().toString(36).slice(2, 8) + '!';
  const user = await User.create({
    firstName: f.firstName, lastName: f.lastName, employeeId: f.employeeId, email: f.email, role: f.role,
    status: 'Active', permissions: User.ROLE_DEFAULTS[f.role], passwordHash: await bcrypt.hash(temp, 10),
  });
  await audit(req, 'CREATE', 'Users', `Added user ${user.firstName} ${user.lastName} (${user.role})`);
  req.session.tempPassword = { name: `${user.firstName} ${user.lastName}`, password: temp };
  res.redirect(`/users?id=${user._id}`);
});

// ---------- APPROVE / REJECT SIGN-UP ----------
router.post('/:id/approve', async (req, res) => {
  const user = await User.findById(req.params.id);
  if (user && user.status === 'Pending') {
    user.status = 'Active';
    user.permissions = User.ROLE_DEFAULTS[user.role];
    await user.save();
    await audit(req, 'UPDATE', 'Users', `Approved account of ${user.firstName} ${user.lastName} (${user.role})`);
    req.session.flash = { type: 'ok', text: `${user.firstName} ${user.lastName} can now sign in.` };
  }
  res.redirect(`/users?id=${req.params.id}`);
});

router.post('/:id/reject', async (req, res) => {
  const user = await User.findById(req.params.id);
  if (user && user.status === 'Pending') {
    user.status = 'Deactivated';
    await user.save();
    await audit(req, 'UPDATE', 'Users', `Rejected sign-up of ${user.firstName} ${user.lastName}`);
  }
  res.redirect('/users');
});

// ---------- ROLE + PRIVILEGES + STATUS ----------
router.post('/:id/privileges', async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.redirect('/users');

  if (User.ROLES.includes(req.body.role)) user.role = req.body.role;
  for (const key of Object.keys(User.PERMISSIONS)) user.permissions[key] = req.body[key] === 'on';

  // Never let an admin lock themselves out of user management
  if (user._id.equals(req.user._id)) user.permissions.manageUsers = true;

  if (['Active', 'Deactivated'].includes(req.body.status) && !user._id.equals(req.user._id)) user.status = req.body.status;

  await user.save();
  await audit(req, 'UPDATE', 'Users', `Updated role/privileges of ${user.firstName} ${user.lastName}`);
  req.session.flash = { type: 'ok', text: 'User privileges saved.' };
  res.redirect(`/users?id=${user._id}`);
});

router.post('/:id/reset-password', async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.redirect('/users');
  const temp = 'Temp' + Math.random().toString(36).slice(2, 8) + '!';
  user.passwordHash = await bcrypt.hash(temp, 10);
  user.resetRequestedAt = undefined;
  await user.save();
  await audit(req, 'UPDATE', 'Users', `Reset password of ${user.firstName} ${user.lastName}`);
  req.session.tempPassword = { name: `${user.firstName} ${user.lastName}`, password: temp };
  res.redirect(`/users?id=${user._id}`);
});

module.exports = router;
