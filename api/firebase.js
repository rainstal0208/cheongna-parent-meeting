import crypto from 'node:crypto';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { FieldValue, getFirestore } from 'firebase-admin/firestore';
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://prpkkohciadbmpcmoise.supabase.co';
const FIREBASE_PROJECT_ID = 'cheongna-parent-meeting';

function getDb() {
  if (!getApps().length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT 환경변수가 없습니다.');
    const serviceAccount = JSON.parse(raw);
    initializeApp({ credential: cert(serviceAccount), projectId: FIREBASE_PROJECT_ID });
  }
  return getFirestore();
}

function getSupabase() {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!key) return null;
  return createClient(SUPABASE_URL, key, { auth: { persistSession: false } });
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}

function safeEqualHex(a, b) {
  try {
    const aa = Buffer.from(String(a), 'hex');
    const bb = Buffer.from(String(b), 'hex');
    return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}

function configRef(db, year) {
  return db.collection('app_config').doc(String(year));
}

function normalizeResources(items) {
  return Array.isArray(items)
    ? items.map((x, i) => ({
        id: String(x?.id ?? `${Date.now()}-${i}`),
        title: x?.title || '',
        dept: '',
        type: 'link',
        url: x?.url || '',
        embed_url: null,
        storage_path: null,
        file_name: null,
        mime: null,
        sort_order: Number.isFinite(Number(x?.sort_order)) ? Number(x.sort_order) : i
      })).filter(x => x.url)
    : [];
}

async function verifyAdmin(db, password) {
  if (!password) return false;
  const ref = db.collection('_system').doc('admin');
  const snap = await ref.get();
  const incoming = sha256(password);
  if (snap.exists && snap.data()?.passwordHash) {
    return safeEqualHex(incoming, snap.data().passwordHash);
  }

  // 최초 1회만 기존 Supabase 관리자 비밀번호를 검증하여 Firebase로 이전한다.
  const supabase = getSupabase();
  if (!supabase) return false;
  const { data, error } = await supabase.rpc('verify_parent_meeting_admin', { p_password: password });
  if (error || !data) return false;
  await ref.set({ passwordHash: incoming, migratedAt: FieldValue.serverTimestamp() }, { merge: true });
  return true;
}

async function migratePublicStateIfNeeded(db, year) {
  const ref = configRef(db, year);
  const existing = await ref.get();
  if (existing.exists) return existing.data();

  const supabase = getSupabase();
  if (!supabase) return null;
  const { data, error } = await supabase.rpc('get_parent_meeting_public_state', { p_event_year: year });
  if (error || !data || !data.has_config) return null;

  const migrated = {
    settings: data.settings || {},
    teachers: data.teachers || {},
    resources: normalizeResources(data.resources),
    layout: null,
    migratedFromSupabase: true,
    updatedAt: FieldValue.serverTimestamp()
  };
  await ref.set(migrated, { merge: true });
  const fresh = await ref.get();
  return fresh.data();
}

async function getPublicState(db, year) {
  const data = await migratePublicStateIfNeeded(db, year);
  return {
    has_config: !!data,
    settings: data?.settings || null,
    teachers: data?.teachers || null,
    resources: normalizeResources(data?.resources),
    layout: null
  };
}

async function migrateOneRegistrationFromSupabase(db, year, deviceId, registrationId) {
  const supabase = getSupabase();
  if (!supabase || registrationId == null) return null;
  const { data: row, error } = await supabase
    .from('parent_meeting_registrations')
    .select('id,event_year,parent_name,signature,device_id,consent,created_at')
    .eq('id', registrationId)
    .eq('event_year', year)
    .maybeSingle();
  if (error || !row) return null;
  if (row.device_id && String(row.device_id) !== String(deviceId)) return null;

  const { data: children = [] } = await supabase
    .from('parent_meeting_children')
    .select('id,registration_id,grade,class_no,student_name')
    .eq('registration_id', row.id)
    .order('id');

  const docId = `legacy_${row.id}`;
  const doc = {
    legacyId: row.id,
    eventYear: Number(row.event_year),
    parentName: row.parent_name || '',
    signature: row.signature || '',
    deviceId: row.device_id || deviceId || '',
    consent: !!row.consent,
    createdAt: row.created_at || new Date().toISOString(),
    children: (children || []).map(c => ({
      id: c.id,
      grade: Number(c.grade),
      classNo: Number(c.class_no),
      studentName: c.student_name || ''
    }))
  };
  await db.collection('registrations').doc(docId).set(doc, { merge: true });
  return { id: docId, ...doc };
}

async function ensureAllRegistrationsMigrated(db) {
  const marker = db.collection('_system').doc('registrations_migration');
  const markerSnap = await marker.get();
  if (markerSnap.exists && markerSnap.data()?.done) return;

  const supabase = getSupabase();
  if (!supabase) return;
  const { data: regs, error: regsError } = await supabase
    .from('parent_meeting_registrations')
    .select('id,event_year,parent_name,signature,device_id,consent,created_at')
    .order('id');
  if (regsError) throw regsError;
  const { data: children, error: childError } = await supabase
    .from('parent_meeting_children')
    .select('id,registration_id,grade,class_no,student_name')
    .order('id');
  if (childError) throw childError;

  const childMap = new Map();
  for (const c of children || []) {
    const key = String(c.registration_id);
    if (!childMap.has(key)) childMap.set(key, []);
    childMap.get(key).push({
      id: c.id,
      grade: Number(c.grade),
      classNo: Number(c.class_no),
      studentName: c.student_name || ''
    });
  }

  let batch = db.batch();
  let count = 0;
  for (const r of regs || []) {
    const ref = db.collection('registrations').doc(`legacy_${r.id}`);
    batch.set(ref, {
      legacyId: r.id,
      eventYear: Number(r.event_year),
      parentName: r.parent_name || '',
      signature: r.signature || '',
      deviceId: r.device_id || '',
      consent: !!r.consent,
      createdAt: r.created_at || new Date().toISOString(),
      children: childMap.get(String(r.id)) || []
    }, { merge: true });
    count++;
    if (count % 400 === 0) {
      await batch.commit();
      batch = db.batch();
    }
  }
  if (count % 400 !== 0) await batch.commit();
  await marker.set({ done: true, count, finishedAt: FieldValue.serverTimestamp() }, { merge: true });
}

function registrationPayload(doc) {
  if (!doc) return null;
  return {
    registration_id: doc.id,
    event_year: doc.eventYear,
    parent_name: doc.parentName || '',
    signature: doc.signature || '',
    consent: !!doc.consent,
    created_at: doc.createdAt || null,
    children: (doc.children || []).map(c => ({
      child_id: c.id ?? null,
      grade: Number(c.grade),
      class_no: Number(c.classNo),
      student_name: c.studentName || ''
    }))
  };
}

async function findDeviceRegistration(db, year, deviceId, registrationId) {
  if (registrationId) {
    const candidates = [String(registrationId)];
    if (!String(registrationId).startsWith('legacy_')) candidates.push(`legacy_${registrationId}`);
    for (const id of candidates) {
      const snap = await db.collection('registrations').doc(id).get();
      if (snap.exists) {
        const data = { id: snap.id, ...snap.data() };
        if (Number(data.eventYear) === Number(year) && (!data.deviceId || String(data.deviceId) === String(deviceId))) return data;
      }
    }
    const migrated = await migrateOneRegistrationFromSupabase(db, year, deviceId, registrationId);
    if (migrated) return migrated;
  }

  const deterministicId = `r_${year}_${sha256(deviceId).slice(0, 32)}`;
  const snap = await db.collection('registrations').doc(deterministicId).get();
  if (snap.exists) return { id: snap.id, ...snap.data() };
  return null;
}

async function deleteQueryInBatches(db, query) {
  let deleted = 0;
  while (true) {
    const snap = await query.limit(400).get();
    if (snap.empty) break;
    const batch = db.batch();
    snap.docs.forEach(doc => batch.delete(doc.ref));
    await batch.commit();
    deleted += snap.size;
    if (snap.size < 400) break;
  }
  return deleted;
}

async function handleRpc(db, name, p) {
  switch (name) {
    case 'get_parent_meeting_public_state': {
      return getPublicState(db, Number(p.p_event_year));
    }
    case 'verify_parent_meeting_admin': {
      return verifyAdmin(db, p.p_password);
    }
    case 'save_parent_meeting_config': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      const year = Number(p.p_event_year);
      await configRef(db, year).set({
        settings: p.p_settings || {},
        teachers: p.p_teachers || {},
        updatedAt: FieldValue.serverTimestamp()
      }, { merge: true });
      return true;
    }
    case 'save_parent_meeting_event_info': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      const year = Number(p.p_event_year);
      const ref = configRef(db, year);
      const snap = await ref.get();
      const settings = { ...(snap.data()?.settings || {}) };
      settings.eventDate = p.p_event_date || settings.eventDate || '';
      settings.startTime = p.p_start_time || settings.startTime || '13:00';
      settings['1'] = p.p_dest1 || '';
      settings['2'] = p.p_dest2 || '';
      settings['3'] = p.p_dest3 || '';
      await ref.set({ settings, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
      return true;
    }
    case 'save_parent_meeting_resource': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      const year = Number(p.p_event_year);
      const ref = configRef(db, year);
      const snap = await ref.get();
      const items = normalizeResources(snap.data()?.resources);
      const id = `${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      items.push({ id, title: '', dept: '', type: 'link', url: p.p_url || '', sort_order: items.length });
      await ref.set({ resources: items, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
      return id;
    }
    case 'delete_parent_meeting_resource': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      const id = String(p.p_resource_id);
      const configs = await db.collection('app_config').get();
      let changed = false;
      for (const doc of configs.docs) {
        const items = normalizeResources(doc.data()?.resources);
        const next = items.filter(x => String(x.id) !== id);
        if (next.length !== items.length) {
          await doc.ref.set({ resources: next.map((x, i) => ({ ...x, sort_order: i })), updatedAt: FieldValue.serverTimestamp() }, { merge: true });
          changed = true;
        }
      }
      return changed;
    }
    case 'reorder_parent_meeting_resources': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      const year = Number(p.p_event_year);
      const ref = configRef(db, year);
      const snap = await ref.get();
      const items = normalizeResources(snap.data()?.resources);
      const order = (p.p_ids || []).map(String);
      const map = new Map(items.map(x => [String(x.id), x]));
      const ordered = order.map(id => map.get(id)).filter(Boolean);
      for (const x of items) if (!order.includes(String(x.id))) ordered.push(x);
      await ref.set({ resources: ordered.map((x, i) => ({ ...x, sort_order: i })), updatedAt: FieldValue.serverTimestamp() }, { merge: true });
      return true;
    }
    case 'save_parent_meeting_layout': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      // Firebase Storage를 사용하지 않으므로 배치도는 GitHub/Vercel 정적 이미지로 고정.
      return true;
    }
    case 'submit_parent_meeting_registration': {
      const year = Number(p.p_event_year);
      const deviceId = String(p.p_device_id || '').trim();
      const parentName = String(p.p_parent_name || '').trim();
      const signature = String(p.p_signature || '');
      const children = Array.isArray(p.p_children) ? p.p_children : [];
      if (!year || !deviceId || !parentName || !signature || !children.length) {
        throw Object.assign(new Error('등록 필수 정보가 빠져 있습니다.'), { status: 400 });
      }
      if (signature.length > 900000) {
        throw Object.assign(new Error('서명 이미지가 너무 큽니다. 페이지를 새로고침한 뒤 다시 서명해 주세요.'), { status: 413 });
      }
      const id = `r_${year}_${sha256(deviceId).slice(0, 32)}`;
      const ref = db.collection('registrations').doc(id);
      const doc = {
        eventYear: year,
        parentName,
        signature,
        deviceId,
        consent: !!p.p_consent,
        createdAt: new Date().toISOString(),
        children: children.map((c, i) => ({
          id: `${i + 1}`,
          grade: Number(c.grade),
          classNo: Number(c.class_no),
          studentName: String(c.student_name || '').trim()
        }))
      };
      await db.runTransaction(async tx => {
        const snap = await tx.get(ref);
        if (snap.exists) throw Object.assign(new Error('duplicate registration'), { status: 409 });
        tx.set(ref, doc);
      });
      return id;
    }
    case 'get_parent_meeting_device_registration': {
      const found = await findDeviceRegistration(db, Number(p.p_event_year), String(p.p_device_id || ''), p.p_registration_id);
      return found ? registrationPayload(found) : null;
    }
    case 'delete_parent_meeting_device_registration': {
      const found = await findDeviceRegistration(db, Number(p.p_event_year), String(p.p_device_id || ''), p.p_registration_id);
      if (!found) return false;
      await db.collection('registrations').doc(found.id).delete();
      return true;
    }
    case 'get_parent_meeting_registrations_v2': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      await ensureAllRegistrationsMigrated(db);
      let q = db.collection('registrations');
      if (p.p_event_year != null) q = q.where('eventYear', '==', Number(p.p_event_year));
      const snap = await q.get();
      let rows = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      if (p.p_grade != null) rows = rows.filter(r => (r.children || []).some(c => Number(c.grade) === Number(p.p_grade)));
      if (p.p_class_no != null) rows = rows.filter(r => (r.children || []).some(c => Number(c.classNo) === Number(p.p_class_no)));
      rows.sort((a, b) => String(a.createdAt || '').localeCompare(String(b.createdAt || '')));
      return rows.map(registrationPayload);
    }
    case 'reset_parent_meeting_registrations': {
      if (!(await verifyAdmin(db, p.p_password))) throw Object.assign(new Error('관리자 비밀번호가 올바르지 않습니다.'), { status: 401 });
      const year = Number(p.p_event_year);
      const q = db.collection('registrations').where('eventYear', '==', year);
      return deleteQueryInBatches(db, q);
    }
    default:
      throw Object.assign(new Error(`지원하지 않는 작업입니다: ${name}`), { status: 400 });
  }
}

export default async function handler(req, res) {
  if (req.method === 'GET' && String(req.query?.health || '') === '1') {
    try {
      const db = getDb();
      await db.collection('_system').doc('healthcheck').get();
      return res.status(200).json({ ok: true, firestore: true, projectId: FIREBASE_PROJECT_ID });
    } catch (e) {
      console.error('Firebase health check failed:', e);
      return res.status(500).json({ ok: false, error: e?.message || String(e) });
    }
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  try {
    let payload=req.body || {};
    if(typeof payload === 'string'){ try{ payload=JSON.parse(payload); }catch{} }
    const { name, params = {} } = payload;
    if (!name) return res.status(400).json({ error: '작업 이름이 없습니다.' });
    const db = getDb();
    const data = await handleRpc(db, name, params);
    return res.status(200).json({ data });
  } catch (e) {
    console.error('Firebase request failed:', e);
    return res.status(e?.status || 500).json({ error: e?.message || String(e), code: e?.code || null });
  }
}
