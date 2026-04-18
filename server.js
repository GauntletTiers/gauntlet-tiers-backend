// ============================================================
// server.js — Gauntlet Tiers Backend
// Node.js + Express + Supabase
// ============================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// ── ENV VARS (set these in Railway or .env) ────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const JWT_SECRET   = process.env.JWT_SECRET || 'change-this-secret';
const PORT         = process.env.PORT || 3000;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── AUTH MIDDLEWARE ────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user.is_admin) return res.status(403).json({ message: 'Admin only' });
  next();
}

// ── REGISTER ───────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ message: 'All fields required' });

  const hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert([{ username, email, password_hash: hash, is_admin: false }])
    .select()
    .single();

  if (error) {
    if (error.code === '23505')
      return res.status(409).json({ message: 'Email or username already in use' });
    return res.status(500).json({ message: error.message });
  }

  const token = jwt.sign({ id: data.id, email: data.email, is_admin: false }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: data.id, username: data.username, email: data.email, is_admin: false } });
});

// ── LOGIN ──────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user)
    return res.status(401).json({ message: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid)
    return res.status(401).json({ message: 'Invalid email or password' });

  const token = jwt.sign(
    { id: user.id, email: user.email, is_admin: user.is_admin },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    token,
    user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin, created_at: user.created_at }
  });
});

// ── GET PLAYERS (public) ───────────────────────────────────
app.get('/api/players', async (req, res) => {
  const mode = req.query.mode || 'overall';
  const MODES = ['sword','mace','axe','uhc','pot','crystal','smp','vanilla'];

  if (mode === 'overall') {
    // Fetch all modes and merge by username
    const { data, error } = await supabase
      .from('player_tiers')
      .select('id, username, region, tier, mode, tier_rank')
      .in('mode', MODES)
      .order('tier_rank', { ascending: true });

    if (error) return res.status(500).json({ message: error.message });

    // Points per tier — higher = better
    const TIER_POINTS = {
      HT1:10, LT1:9, HT2:8, LT2:7,
      HT3:6,  LT3:5, HT4:4, LT4:3,
      HT5:2,  LT5:1
    };

    const map = {};
    (data || []).forEach(row => {
      const pts = TIER_POINTS[row.tier] || 0;
      if (!map[row.username]) {
        map[row.username] = {
          id: row.id,
          username: row.username,
          region: row.region,
          tier: row.tier,       // best tier (for display)
          tier_rank: row.tier_rank,
          mode: 'overall',
          total_points: pts
        };
      } else {
        map[row.username].total_points += pts;
        // Keep best tier for display
        if (row.tier_rank < map[row.username].tier_rank) {
          map[row.username].tier      = row.tier;
          map[row.username].tier_rank = row.tier_rank;
        }
      }
    });

    // Sort by total points descending — more points = higher rank
    const players = Object.values(map).sort((a, b) => b.total_points - a.total_points);
    return res.json({ players });
  }

  // Single mode
  const { data, error } = await supabase
    .from('player_tiers')
    .select('id, username, region, tier, mode')
    .eq('mode', mode)
    .order('tier_rank', { ascending: true });

  if (error) return res.status(500).json({ message: error.message });
  res.json({ players: data });
});

// ── GET SINGLE PLAYER (by username or user id) ────────────
app.get('/api/players/:id', async (req, res) => {
  const param = req.params.id;

  // Try by username first (most common case — admin adds players by IGN)
  let { data, error } = await supabase
    .from('player_tiers')
    .select('*')
    .ilike('username', param);

  // If nothing found by username, try by player_id (UUID)
  if ((!data || data.length === 0) && !error) {
    const res2 = await supabase
      .from('player_tiers')
      .select('*')
      .eq('player_id', param);
    data  = res2.data;
    error = res2.error;
  }

  if (error) return res.status(500).json({ message: error.message });

  // Group tiers by mode
  const tiers = {};
  (data || []).forEach(row => { tiers[row.mode] = row.tier; });
  res.json({ tiers, username: data?.[0]?.username || null });
});

// ── STATS (public) ─────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  const [{ count: players }, { count: users }] = await Promise.all([
    supabase.from('player_tiers').select('*', { count: 'exact', head: true }),
    supabase.from('users').select('*', { count: 'exact', head: true })
  ]);
  res.json({ ranked_players: players, total_users: users, game_modes: 8 });
});

// ── ADMIN: ADD PLAYER ──────────────────────────────────────
app.post('/api/admin/players', auth, adminOnly, async (req, res) => {
  const { username, region, mode, tier } = req.body;
  if (!username || !mode || !tier)
    return res.status(400).json({ message: 'username, mode and tier required' });

  const TIER_RANK = { HT1:1,LT1:2,HT2:3,LT2:4,HT3:5,LT3:6,HT4:7,LT4:8,HT5:9,LT5:10 };

  // Upsert (insert or update if same username+mode)
  const { data, error } = await supabase
    .from('player_tiers')
    .upsert([{ username, region, mode, tier, tier_rank: TIER_RANK[tier] || 99 }],
      { onConflict: 'username,mode' })
    .select()
    .single();

  if (error) return res.status(500).json({ message: error.message });
  res.json({ player: data });
});

// ── ADMIN: UPDATE TIER ─────────────────────────────────────
app.patch('/api/admin/players/:id/tier', auth, adminOnly, async (req, res) => {
  const { mode, tier } = req.body;
  const TIER_RANK = { HT1:1,LT1:2,HT2:3,LT2:4,HT3:5,LT3:6,HT4:7,LT4:8,HT5:9,LT5:10 };

  // Get current tier for history
  const { data: current } = await supabase
    .from('player_tiers')
    .select('tier, username')
    .eq('id', req.params.id)
    .single();

  const { error } = await supabase
    .from('player_tiers')
    .update({ tier, tier_rank: TIER_RANK[tier] || 99 })
    .eq('id', req.params.id)
    .eq('mode', mode);

  if (error) return res.status(500).json({ message: error.message });

  // Save history if tier actually changed
  if (current && current.tier !== tier) {
    await supabase.from('tier_history').insert([{
      username: current.username,
      mode,
      old_tier: current.tier,
      new_tier: tier
    }]);
  }

  res.json({ success: true });
});

// ── ADMIN: DELETE PLAYER ───────────────────────────────────
app.delete('/api/admin/players/:id', auth, adminOnly, async (req, res) => {
  const { error } = await supabase.from('player_tiers').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── ADMIN: GET ALL USERS ───────────────────────────────────
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, username, email, is_admin, created_at')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ message: error.message });
  res.json({ users: data });
});

// ── ADMIN: TOGGLE ADMIN ────────────────────────────────────
app.patch('/api/admin/users/:id/admin', auth, adminOnly, async (req, res) => {
  const { is_admin } = req.body;
  const { error } = await supabase
    .from('users')
    .update({ is_admin })
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── TOURNAMENTS (public GET) ───────────────────────────────
app.get('/api/tournaments', async (req, res) => {
  const { data, error } = await supabase
    .from('tournaments')
    .select('*')
    .order('date', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json({ tournaments: data });
});

// ── TOURNAMENTS (admin POST) ───────────────────────────────
app.post('/api/tournaments', auth, adminOnly, async (req, res) => {
  const { name, mode, date, max_players, status, description, players } = req.body;
  if (!name) return res.status(400).json({ message: 'Name required' });

  const { data, error } = await supabase
    .from('tournaments')
    .insert([{ name, mode, date, max_players, status: status || 'upcoming', description, players: players || [] }])
    .select()
    .single();

  if (error) return res.status(500).json({ message: error.message });
  res.json({ tournament: data });
});

// ── TOURNAMENTS (admin DELETE) ─────────────────────────────
app.delete('/api/tournaments/:id', auth, adminOnly, async (req, res) => {
  const { error } = await supabase.from('tournaments').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── PLAYER TIER HISTORY (public) ───────────────────────────
app.get('/api/players/history', async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ message: 'username required' });

  const { data, error } = await supabase
    .from('tier_history')
    .select('*')
    .eq('username', username)
    .order('changed_at', { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ message: error.message });
  res.json({ history: data });
});

app.listen(PORT, () => console.log(`Gauntlet Tiers backend running on port ${PORT}`));