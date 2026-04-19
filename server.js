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
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ message: error.message });
  res.json({ tournaments: data });
});

// ── TOURNAMENT GET ONE ─────────────────────────────────────
app.get('/api/tournaments/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('tournaments')
    .select('*')
    .eq('id', req.params.id)
    .single();
  if (error) return res.status(500).json({ message: error.message });
  res.json({ tournament: data });
});

// ── TOURNAMENTS (admin POST) ───────────────────────────────
app.post('/api/tournaments', auth, adminOnly, async (req, res) => {
  const { name, mode, date, status, description, players } = req.body;
  if (!name) return res.status(400).json({ message: 'Name required' });

  const { data, error } = await supabase
    .from('tournaments')
    .insert([{
      name, mode, date,
      status: status || 'upcoming',
      description,
      players: players || [],
      bracket: buildBracket(players || [])
    }])
    .select()
    .single();

  if (error) return res.status(500).json({ message: error.message });
  res.json({ tournament: data });
});

// ── TOURNAMENT: ADD PLAYER ─────────────────────────────────
app.patch('/api/tournaments/:id/players/add', auth, adminOnly, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ message: 'username required' });

  const { data: t, error: fetchErr } = await supabase
    .from('tournaments').select('players').eq('id', req.params.id).single();
  if (fetchErr) return res.status(500).json({ message: fetchErr.message });

  const players = t.players || [];
  if (players.includes(username))
    return res.status(409).json({ message: 'Player already in tournament' });

  players.push(username);
  const bracket = buildBracket(players);

  const { error } = await supabase.from('tournaments')
    .update({ players, bracket }).eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ players, bracket });
});

// ── TOURNAMENT: REMOVE PLAYER ──────────────────────────────
app.patch('/api/tournaments/:id/players/remove', auth, adminOnly, async (req, res) => {
  const { username } = req.body;

  const { data: t, error: fetchErr } = await supabase
    .from('tournaments').select('players').eq('id', req.params.id).single();
  if (fetchErr) return res.status(500).json({ message: fetchErr.message });

  const players = (t.players || []).filter(p => p !== username);
  const bracket = buildBracket(players);

  const { error } = await supabase.from('tournaments')
    .update({ players, bracket }).eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ players, bracket });
});

// ── TOURNAMENT: UPDATE STATUS ──────────────────────────────
app.patch('/api/tournaments/:id/status', auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  const updates = { status };
  if (status === 'ongoing') updates.started_at = new Date().toISOString();
  const { error } = await supabase.from('tournaments')
    .update(updates).eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── TOURNAMENT: SET CURRENT MATCH (admin) ─────────────────
app.patch('/api/tournaments/:id/current-match', auth, adminOnly, async (req, res) => {
  const { current_match } = req.body;
  const { error } = await supabase.from('tournaments')
    .update({ current_match }).eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── TOURNAMENT: SUBMIT APPLICATION (public) ────────────────
app.post('/api/tournaments/:id/apply', async (req, res) => {
  const { discord_nick, ign } = req.body;
  if (!discord_nick || !ign)
    return res.status(400).json({ message: 'Discord nick and IGN required' });

  // Check tournament exists and is ongoing
  const { data: t, error: tErr } = await supabase
    .from('tournaments').select('status, applications').eq('id', req.params.id).single();
  if (tErr) return res.status(404).json({ message: 'Tournament not found' });
  if (t.status !== 'ongoing')
    return res.status(400).json({ message: 'This tournament is not open for applications' });

  const apps = t.applications || [];
  if (apps.find(a => a.ign.toLowerCase() === ign.toLowerCase()))
    return res.status(409).json({ message: 'You already applied to this tournament' });

  apps.push({ discord_nick, ign, status: 'pending', applied_at: new Date().toISOString() });

  const { error } = await supabase.from('tournaments')
    .update({ applications: apps }).eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── TOURNAMENT: GET APPLICATIONS (admin sees all, user sees own+count) ──
app.get('/api/tournaments/:id/applications', async (req, res) => {
  const { data: t, error } = await supabase
    .from('tournaments').select('applications, status').eq('id', req.params.id).single();
  if (error) return res.status(500).json({ message: error.message });

  const apps  = t.applications || [];
  const token = req.headers.authorization?.replace('Bearer ', '');
  let isAdmin = false;

  if (token) {
    try {
      const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET || 'change-this-secret');
      isAdmin = decoded.is_admin;
    } catch {}
  }

  if (isAdmin) return res.json({ applications: apps, total: apps.length });

  // Non-admin: return count + pending/approved/rejected counts only
  const pending  = apps.filter(a => a.status === 'pending').length;
  const approved = apps.filter(a => a.status === 'approved').length;
  res.json({ total: apps.length, pending, approved, applications: [] });
});

// ── TOURNAMENT: APPROVE/REJECT APPLICATION (admin) ────────
app.patch('/api/tournaments/:id/applications/:ign', auth, adminOnly, async (req, res) => {
  const { status } = req.body; // 'approved' | 'rejected'
  const { data: t, error: tErr } = await supabase
    .from('tournaments').select('applications').eq('id', req.params.id).single();
  if (tErr) return res.status(500).json({ message: tErr.message });

  const apps = (t.applications || []).map(a =>
    a.ign.toLowerCase() === req.params.ign.toLowerCase() ? { ...a, status } : a
  );

  const { error } = await supabase.from('tournaments')
    .update({ applications: apps }).eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── TOURNAMENTS (admin DELETE) ─────────────────────────────
app.delete('/api/tournaments/:id', auth, adminOnly, async (req, res) => {
  const { error } = await supabase.from('tournaments').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: error.message });
  res.json({ success: true });
});

// ── BRACKET BUILDER ────────────────────────────────────────
function buildBracket(players) {
  const n = players.length;
  if (n < 2) return [];

  // Find next power of 2 >= n
  let slots = 1;
  while (slots < n) slots *= 2;

  // Assign byes: players that skip straight to next round
  // Fill slots with players, rest are 'BYE'
  const seeded = [...players];
  while (seeded.length < slots) seeded.push('BYE');

  // Build rounds
  const rounds = [];
  let current = seeded;

  while (current.length > 1) {
    const matches = [];
    const nextRound = [];

    for (let i = 0; i < current.length; i += 2) {
      const p1 = current[i];
      const p2 = current[i + 1];

      if (p2 === 'BYE') {
        // p1 gets a bye — advances automatically
        matches.push({ p1, p2: 'BYE', winner: p1, bye: true });
        nextRound.push(p1);
      } else if (p1 === 'BYE') {
        matches.push({ p1: 'BYE', p2, winner: p2, bye: true });
        nextRound.push(p2);
      } else {
        matches.push({ p1, p2, winner: null, bye: false });
        nextRound.push('TBD');
      }
    }

    rounds.push(matches);
    current = nextRound;
  }

  return rounds;
}

// ── TOURNAMENT: SET MATCH RESULT (admin) ─────────────────
// body: { round_index, match_index, winner }
app.patch('/api/tournaments/:id/result', auth, adminOnly, async (req, res) => {
  const { round_index, match_index, winner } = req.body;

  const { data: t, error: tErr } = await supabase
    .from('tournaments').select('bracket').eq('id', req.params.id).single();
  if (tErr) return res.status(500).json({ message: tErr.message });

  const bracket = t.bracket || [];

  // Validate round/match indices
  if (!bracket[round_index] || !bracket[round_index][match_index])
    return res.status(400).json({ message: 'Invalid round or match index' });

  const match = bracket[round_index][match_index];

  // Set winner on this match
  match.winner = winner;

  // Advance winner to next round if it exists
  const nextRound = bracket[round_index + 1];
  if (nextRound) {
    // Figure out which slot in next round this match feeds into
    const nextMatchIndex = Math.floor(match_index / 2);
    const isFirstPlayer  = match_index % 2 === 0; // even index = p1 slot, odd = p2 slot

    if (nextRound[nextMatchIndex]) {
      if (isFirstPlayer) {
        nextRound[nextMatchIndex].p1 = winner;
      } else {
        nextRound[nextMatchIndex].p2 = winner;
      }
      // Clear winner of next match if it was already set (re-picking)
      nextRound[nextMatchIndex].winner = null;
    }
  }

  // Check if tournament is complete (all matches in last round have winners)
  const lastRound   = bracket[bracket.length - 1];
  const champion    = lastRound && lastRound.length === 1 && lastRound[0].winner
    ? lastRound[0].winner : null;

  const { error } = await supabase.from('tournaments')
    .update({ bracket, ...(champion ? { champion } : {}) })
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ message: error.message });
  res.json({ bracket, champion });
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