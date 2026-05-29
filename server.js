const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const supabase = createClient(process.env.SUPABASE_URL || '', process.env.SUPABASE_ANON_KEY || '');

app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 300 }));

function hashPass(pass) { return crypto.createHash('sha256').update(pass + 'offside_salt_2024').digest('hex'); }

const SYSTEM_PROMPT = "Eres el Árbitro Oficial de OFFSIDE, la red social de debates futbolísticos. Tu lema: El veredicto es inapelable. Personalidad: directo, justo, con autoridad e ironía futbolística. Neutral: sin equipo favorito. Idioma: español latinoamericano con energía. Responde ÚNICAMENTE con JSON válido (sin backticks, sin texto extra): {\"veredicto\": \"IRREFUTABLE\" | \"SÓLIDO\" | \"POLÉMICO\" | \"OFFSIDE\", \"puntuacion\": <1-100>, \"resumen\": \"<máx 12 palabras>\", \"frase_arbitro\": \"<máx 20 palabras>\", \"puntos_fuertes\": [\"<punto>\", \"<punto>\"], \"puntos_debiles\": [\"<punto>\", \"<punto>\"], \"estadistica_clave\": \"<estadística real>\", \"contexto_historico\": \"<2 oraciones>\", \"contra_argumento\": \"<2 oraciones>\", \"temas_relacionados\": [\"<tema>\", \"<tema>\", \"<tema>\"]} Criterios: 85-100=IRREFUTABLE, 65-84=SÓLIDO, 40-64=POLÉMICO, 1-39=OFFSIDE. NUNCA inventes estadísticas.";

const DUELO_PROMPT = "Eres el Árbitro Oficial de OFFSIDE. Dos usuarios debaten sobre un mismo tema. Analiza AMBOS argumentos y decide quién tiene razón. Responde ÚNICAMENTE con JSON válido (sin backticks): {\"ganador\": \"retador\" | \"retado\" | \"empate\", \"puntuacion_retador\": <1-100>, \"puntuacion_retado\": <1-100>, \"analisis_retador\": \"<análisis en 2 oraciones>\", \"analisis_retado\": \"<análisis en 2 oraciones>\", \"veredicto_final\": \"<frase del árbitro, máx 20 palabras>\"}";

async function llamarArbitro(system, userMsg) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, system, messages: [{ role: 'user', content: userMsg }] }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error?.message || 'Error API');
  return JSON.parse(data.content[0].text.replace(/```json\n?/g,'').replace(/```\n?/g,'').trim());
}

async function updateElo(userId, veredicto) {
  let c = 0;
  if (veredicto === 'IRREFUTABLE') c = 25;
  else if (veredicto === 'SÓLIDO') c = 10;
  else if (veredicto === 'OFFSIDE') c = -15;
  const { data: u } = await supabase.from('usuarios').select('rating_elo, total_debates, irrefutables').eq('id', userId).single();
  if (u) await supabase.from('usuarios').update({
    rating_elo: Math.max(0, u.rating_elo + c), total_debates: u.total_debates + 1,
    irrefutables: u.irrefutables + (veredicto === 'IRREFUTABLE' ? 1 : 0),
  }).eq('id', userId);
}

app.get('/', (_, res) => res.json({ status: 'Offside OK', v: '4.0.0' }));

// ══════ REGISTRO COMPLETO ══════
app.post('/api/auth/registro', async (req, res) => {
  const { email, username, password, nombre_completo, fecha_nacimiento, pais, acepto_terminos } = req.body;
  if (!email || !username || !password || !nombre_completo) return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  if (username.length < 3) return res.status(400).json({ error: 'Username: mínimo 3 caracteres.' });
  if (password.length < 6) return res.status(400).json({ error: 'Contraseña: mínimo 6 caracteres.' });
  if (!acepto_terminos) return res.status(400).json({ error: 'Debes aceptar los términos y condiciones.' });
  if (!fecha_nacimiento) return res.status(400).json({ error: 'Fecha de nacimiento requerida.' });
  if (!nombre_completo || nombre_completo.trim().length < 3) return res.status(400).json({ error: 'Nombre completo requerido.' });

  const { data: e1 } = await supabase.from('usuarios').select('id').eq('username', username.toLowerCase()).single();
  if (e1) return res.status(400).json({ error: 'Ese username ya está en uso.' });
  const { data: e2 } = await supabase.from('usuarios').select('id').eq('email', email.toLowerCase()).single();
  if (e2) return res.status(400).json({ error: 'Ese email ya está registrado.' });

  const { data, error } = await supabase.from('usuarios').insert({
    email: email.toLowerCase().trim(),
    username: username.trim(),
    nombre_completo: nombre_completo.trim(),
    password_hash: hashPass(password),
    fecha_nacimiento,
    pais: pais || '',
    bio: '',
    rating_elo: 1000,
    acepto_terminos: true,
  }).select().single();

  if (error) { console.log('Registro error:', error); return res.status(500).json({ error: 'Error al crear cuenta.' }); }
  // No devolver password_hash al cliente
  delete data.password_hash;
  res.json({ ok: true, usuario: data });
});

// ══════ LOGIN CON PASSWORD ══════
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos.' });

  const { data, error } = await supabase.from('usuarios').select('*').eq('email', email.toLowerCase().trim()).single();
  if (error || !data) return res.status(404).json({ error: 'Usuario no encontrado. Regístrate primero.' });

  if (data.password_hash && data.password_hash !== hashPass(password)) {
    return res.status(401).json({ error: 'Contraseña incorrecta.' });
  }
  // ══════ LOGIN/REGISTRO CON GOOGLE ══════
app.post('/api/auth/google', async (req, res) => {
  const { email, nombre_completo } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requerido.' });

  // Si ya existe, devolver el usuario (sin verificar password)
  const { data: existente } = await supabase.from('usuarios').select('*').eq('email', email.toLowerCase().trim()).single();
  if (existente) {
    delete existente.password_hash;
    return res.json({ ok: true, usuario: existente });
  }

  // Si no existe, crear cuenta nueva
  let username = email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '').substring(0, 15);
  // Asegurar username único
  const { data: userExiste } = await supabase.from('usuarios').select('id').eq('username', username).single();
  if (userExiste) username = username + Math.floor(Math.random() * 1000);

  const { data, error } = await supabase.from('usuarios').insert({
    email: email.toLowerCase().trim(),
    username,
    nombre_completo: nombre_completo || '',
    password_hash: 'google_oauth',
    fecha_nacimiento: '2000-01-01',
    pais: '',
    bio: '',
    rating_elo: 1000,
    acepto_terminos: true,
  }).select().single();

  if (error) { console.log('Google registro error:', error); return res.status(500).json({ error: 'Error al crear cuenta con Google.' }); }
  delete data.password_hash;
  res.json({ ok: true, usuario: data });
});

  delete data.password_hash;
  res.json({ ok: true, usuario: data });
});

// ══════ PERFIL ══════
app.get('/api/perfil/:id', async (req, res) => {
  const { data } = await supabase.from('usuarios').select('id, email, username, nombre_completo, bio, pais, rating_elo, total_debates, irrefutables, fecha_nacimiento, es_publico, avatar_url, created_at').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'No encontrado.' });
  const { count: seguidores } = await supabase.from('seguidores').select('*', { count: 'exact', head: true }).eq('seguido_id', req.params.id);
  const { count: siguiendo } = await supabase.from('seguidores').select('*', { count: 'exact', head: true }).eq('seguidor_id', req.params.id);
  const { data: debates } = await supabase.from('debates').select('id, argumento, veredicto, puntuacion, created_at, respuesta_completa, username').eq('user_id', req.params.id).order('created_at', { ascending: false }).limit(20);
  res.json({ ...data, seguidores: seguidores || 0, siguiendo: siguiendo || 0, debates: debates || [] });
});

app.put('/api/perfil/:id', async (req, res) => {
  const u = {};
  if (req.body.username) u.username = req.body.username;
  if (req.body.bio !== undefined) u.bio = req.body.bio;
  if (req.body.es_publico !== undefined) u.es_publico = req.body.es_publico;
  if (req.body.nombre_completo) u.nombre_completo = req.body.nombre_completo;
  if (req.body.pais) u.pais = req.body.pais;
  if (req.body.avatar_url) u.avatar_url = req.body.avatar_url;
  const { data } = await supabase.from('usuarios').update(u).eq('id', req.params.id).select().single();
  if (data) delete data.password_hash;
  res.json({ ok: true, usuario: data });
});

// ══════ SEGUIR ══════
app.post('/api/seguir', async (req, res) => {
  const { seguidor_id, seguido_id } = req.body;
  if (seguidor_id === seguido_id) return res.status(400).json({ error: 'No puedes seguirte.' });
  const { error } = await supabase.from('seguidores').insert({ seguidor_id, seguido_id });
  if (error) return res.status(400).json({ error: 'Ya sigues a este usuario.' });
  res.json({ ok: true });
});
app.post('/api/dejar-seguir', async (req, res) => {
  await supabase.from('seguidores').delete().eq('seguidor_id', req.body.seguidor_id).eq('seguido_id', req.body.seguido_id);
  res.json({ ok: true });
});
app.get('/api/sigo/:a/:b', async (req, res) => {
  const { data } = await supabase.from('seguidores').select('id').eq('seguidor_id', req.params.a).eq('seguido_id', req.params.b).single();
  res.json({ sigo: !!data });
});
app.get('/api/seguidores/:id', async (req, res) => {
  const { data: rels } = await supabase.from('seguidores').select('seguidor_id').eq('seguido_id', req.params.id);
  if (!rels || !rels.length) return res.json([]);
  const { data } = await supabase.from('usuarios').select('id, username, rating_elo, total_debates, bio').in('id', rels.map(r => r.seguidor_id));
  res.json(data || []);
});
app.get('/api/siguiendo/:id', async (req, res) => {
  const { data: rels } = await supabase.from('seguidores').select('seguido_id').eq('seguidor_id', req.params.id);
  if (!rels || !rels.length) return res.json([]);
  const { data } = await supabase.from('usuarios').select('id, username, rating_elo, total_debates, bio').in('id', rels.map(r => r.seguido_id));
  res.json(data || []);
});

// ══════ DEBATES DE USUARIO ══════
app.get('/api/usuarios/:id/debates', async (req, res) => {
  const { data } = await supabase.from('debates').select('id, argumento, veredicto, puntuacion, votos_favor, votos_contra, created_at, respuesta_completa, username')
    .eq('user_id', req.params.id).order('created_at', { ascending: false }).limit(50);
  res.json(data || []);
});

// ══════ ARBITRAR ══════
app.post('/api/arbitrar', async (req, res) => {
  const { argumento, contexto, user_id, username } = req.body;
  if (!argumento || argumento.trim().length < 10) return res.status(400).json({ error: 'Argumento muy corto.' });
  try {
    console.log('Arbitrando para', username || 'anónimo');
    const resultado = await llamarArbitro(SYSTEM_PROMPT, 'ARGUMENTO: "' + argumento.trim() + '"' + (contexto ? '\nCONTEXTO: ' + contexto.trim() : ''));
    console.log('Veredicto:', resultado.veredicto, resultado.puntuacion);
    const ins = { argumento: argumento.trim(), contexto: contexto || null, veredicto: resultado.veredicto, puntuacion: resultado.puntuacion, respuesta_completa: resultado };
    if (user_id) { ins.user_id = user_id; ins.username = username || 'Anónimo'; }
    const { data: debate } = await supabase.from('debates').insert(ins).select('id').single();
    if (user_id) await updateElo(user_id, resultado.veredicto);
    return res.json({ ok: true, resultado, debate_id: debate?.id });
  } catch (err) { console.log('Error:', err.message); return res.status(500).json({ error: 'Error: ' + err.message }); }
});

// ══════ FEED ══════
app.get('/api/feed', async (req, res) => {
  const { filtro = 'recientes', pagina = 1 } = req.query;
  const limit = 20; const offset = (parseInt(pagina) - 1) * limit;
  const f = 'id, argumento, veredicto, puntuacion, votos_favor, votos_contra, created_at, respuesta_completa, user_id, username';
  let q;
  if (filtro === 'trending') {
    q = supabase.from('debates').select(f).eq('es_publico', true).gte('created_at', new Date(Date.now()-7*24*60*60*1000).toISOString()).order('votos_favor', { ascending: false }).range(0, 19);
  } else if (filtro === 'irrefutables') {
    q = supabase.from('debates').select(f).eq('es_publico', true).eq('veredicto', 'IRREFUTABLE').order('created_at', { ascending: false }).range(offset, offset+limit-1);
  } else {
    q = supabase.from('debates').select(f).eq('es_publico', true).order('created_at', { ascending: false }).range(offset, offset+limit-1);
  }
  const { data } = await q;
  res.json(data || []);
});

// ══════ VOTAR ══════
app.post('/api/debates/:id/votar', async (req, res) => {
  const { tipo, user_id } = req.body;
  if (!['favor','contra'].includes(tipo)) return res.status(400).json({ error: 'Tipo inválido.' });
  if (user_id) {
    const { data: yv } = await supabase.from('votos_usuario').select('id, tipo').eq('debate_id', req.params.id).eq('user_id', user_id).single();
    if (yv) {
      if (yv.tipo === tipo) return res.status(400).json({ error: 'Ya votaste.' });
      await supabase.from('votos_usuario').update({ tipo }).eq('id', yv.id);
      const oC = yv.tipo === 'favor' ? 'votos_favor' : 'votos_contra';
      const nC = tipo === 'favor' ? 'votos_favor' : 'votos_contra';
      const { data: d } = await supabase.from('debates').select('votos_favor, votos_contra').eq('id', req.params.id).single();
      if (d) await supabase.from('debates').update({ [oC]: Math.max(0,(d[oC]||0)-1), [nC]: (d[nC]||0)+1 }).eq('id', req.params.id);
      return res.json({ ok: true });
    }
    await supabase.from('votos_usuario').insert({ debate_id: req.params.id, user_id, tipo });
  }
  const campo = tipo === 'favor' ? 'votos_favor' : 'votos_contra';
  const { data } = await supabase.from('debates').select(campo).eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'No encontrado.' });
  await supabase.from('debates').update({ [campo]: (data[campo]||0)+1 }).eq('id', req.params.id);
  res.json({ ok: true });
});
app.get('/api/debates/:id/mi-voto/:userId', async (req, res) => {
  const { data } = await supabase.from('votos_usuario').select('tipo').eq('debate_id', req.params.id).eq('user_id', req.params.userId).single();
  res.json({ voto: data?.tipo || null });
});

// ══════ COMENTARIOS ══════
app.get('/api/debates/:id/comentarios', async (req, res) => {
  const { data } = await supabase.from('comentarios').select('*').eq('debate_id', req.params.id).order('created_at', { ascending: true });
  res.json(data || []);
});
app.post('/api/debates/:id/comentarios', async (req, res) => {
  const { user_id, username, texto } = req.body;
  if (!texto || texto.trim().length < 2) return res.status(400).json({ error: 'Muy corto.' });
  const { data } = await supabase.from('comentarios').insert({ debate_id: req.params.id, user_id, username: username || 'Anónimo', texto: texto.trim() }).select().single();
  res.json({ ok: true, comentario: data });
});

// ══════ REBATIR ══════
app.post('/api/debates/:id/rebatir', async (req, res) => {
  const { argumento, user_id, username } = req.body;
  if (!argumento || argumento.trim().length < 10) return res.status(400).json({ error: 'Muy corto.' });
  const { data: orig } = await supabase.from('debates').select('argumento, veredicto, puntuacion').eq('id', req.params.id).single();
  if (!orig) return res.status(404).json({ error: 'No encontrado.' });
  try {
    const resultado = await llamarArbitro(SYSTEM_PROMPT, 'ARGUMENTO ORIGINAL: "' + orig.argumento + '" (' + orig.veredicto + ' ' + orig.puntuacion + '/100)\nCONTRA-ARGUMENTO: "' + argumento.trim() + '"');
    await supabase.from('rebatidas').insert({ debate_original_id: req.params.id, user_id: user_id || null, username: username || 'Anónimo', argumento: argumento.trim(), veredicto: resultado.veredicto, puntuacion: resultado.puntuacion, respuesta_completa: resultado });
    if (user_id) await updateElo(user_id, resultado.veredicto);
    return res.json({ ok: true, resultado });
  } catch (err) { return res.status(500).json({ error: 'Error: ' + err.message }); }
});
app.get('/api/debates/:id/rebatidas', async (req, res) => {
  const { data } = await supabase.from('rebatidas').select('*').eq('debate_original_id', req.params.id).order('created_at', { ascending: true });
  res.json(data || []);
});

// ══════ DESAFÍOS 1v1 ══════
app.post('/api/desafios', async (req, res) => {
  const { retador_id, retador_username, retado_id, retado_username, tema } = req.body;
  if (!tema || tema.trim().length < 5) return res.status(400).json({ error: 'Tema muy corto.' });
  if (retador_id === retado_id) return res.status(400).json({ error: 'No puedes desafiarte.' });
  const { data: p } = await supabase.from('desafios').select('id')
    .or('and(retador_id.eq.' + retador_id + ',retado_id.eq.' + retado_id + '),and(retador_id.eq.' + retado_id + ',retado_id.eq.' + retador_id + ')')
    .in('estado', ['pendiente','aceptado','en_curso']).limit(1);
  if (p && p.length) return res.status(400).json({ error: 'Ya hay un desafío pendiente.' });
  const { data } = await supabase.from('desafios').insert({ retador_id, retador_username, retado_id, retado_username, tema: tema.trim() }).select().single();
  res.json({ ok: true, desafio: data });
});
app.put('/api/desafios/:id/responder', async (req, res) => {
  if (!['aceptado','rechazado'].includes(req.body.estado)) return res.status(400).json({ error: 'Inválido.' });
  const { data } = await supabase.from('desafios').update({ estado: req.body.estado, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  res.json({ ok: true, desafio: data });
});
app.put('/api/desafios/:id/argumentar', async (req, res) => {
  const { user_id, argumento } = req.body;
  if (!argumento || argumento.trim().length < 10) return res.status(400).json({ error: 'Muy corto.' });
  const { data: d } = await supabase.from('desafios').select('*').eq('id', req.params.id).single();
  if (!d) return res.status(404).json({ error: 'No encontrado.' });
  if (d.estado !== 'aceptado' && d.estado !== 'en_curso') return res.status(400).json({ error: 'No activo.' });
  const upd = { estado: 'en_curso', updated_at: new Date().toISOString() };
  if (user_id === d.retador_id) upd.argumento_retador = argumento.trim();
  else if (user_id === d.retado_id) upd.argumento_retado = argumento.trim();
  else return res.status(400).json({ error: 'No eres parte.' });
  await supabase.from('desafios').update(upd).eq('id', req.params.id);
  const { data: u } = await supabase.from('desafios').select('*').eq('id', req.params.id).single();
  if (u.argumento_retador && u.argumento_retado) {
    try {
      const r = await llamarArbitro(DUELO_PROMPT, 'TEMA: "' + u.tema + '"\nRETADOR (' + u.retador_username + '): "' + u.argumento_retador + '"\nRETADO (' + u.retado_username + '): "' + u.argumento_retado + '"');
      const gId = r.ganador === 'retador' ? u.retador_id : r.ganador === 'retado' ? u.retado_id : null;
      const gN = r.ganador === 'retador' ? u.retador_username : r.ganador === 'retado' ? u.retado_username : 'Empate';
      await supabase.from('desafios').update({ estado: 'finalizado', veredicto_retador: { puntuacion: r.puntuacion_retador, analisis: r.analisis_retador }, veredicto_retado: { puntuacion: r.puntuacion_retado, analisis: r.analisis_retado }, ganador_id: gId, ganador_username: gN, updated_at: new Date().toISOString() }).eq('id', req.params.id);
      if (r.ganador !== 'empate') {
        const wId = r.ganador === 'retador' ? u.retador_id : u.retado_id;
        const lId = r.ganador === 'retador' ? u.retado_id : u.retador_id;
        const { data: w } = await supabase.from('usuarios').select('rating_elo').eq('id', wId).single();
        const { data: l } = await supabase.from('usuarios').select('rating_elo').eq('id', lId).single();
        if (w) await supabase.from('usuarios').update({ rating_elo: w.rating_elo + 20 }).eq('id', wId);
        if (l) await supabase.from('usuarios').update({ rating_elo: Math.max(0, l.rating_elo - 20) }).eq('id', lId);
      }
    } catch (e) { console.log('Error duelo:', e.message); }
  }
  const { data: fin } = await supabase.from('desafios').select('*').eq('id', req.params.id).single();
  res.json({ ok: true, desafio: fin });
});
app.get('/api/desafios/usuario/:id', async (req, res) => {
  const { data } = await supabase.from('desafios').select('*')
    .or('retador_id.eq.' + req.params.id + ',retado_id.eq.' + req.params.id)
    .order('created_at', { ascending: false }).limit(20);
  res.json(data || []);
});

// ══════ RANKING + DETALLE ══════
app.get('/api/ranking', async (_, res) => {
  const { data } = await supabase.from('usuarios').select('id, username, nombre_completo, rating_elo, total_debates, irrefutables').order('rating_elo', { ascending: false }).limit(50);
  res.json(data || []);
});
app.get('/api/debates/:id', async (req, res) => {
  const { data } = await supabase.from('debates').select('*').eq('id', req.params.id).single();
  if (!data) return res.status(404).json({ error: 'No encontrado.' });
  res.json(data);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('\n⚽  OFFSIDE v4.0 en http://localhost:' + PORT);
  console.log('   API Key: ' + (process.env.ANTHROPIC_API_KEY ? 'OK' : 'FALTA'));
  console.log('   Supabase: ' + (process.env.SUPABASE_URL ? 'OK' : 'FALTA'));
  console.log('   Auth: Password hash + registro completo\n');
});