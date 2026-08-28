import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://prpkkohciadbmpcmoise.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_3zgIGY7acSXZ-99BvkxxFg_CGzBEPUV';
const BUCKET = 'parent-meeting-assets';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST only' });
  }

  try {
    const { password, action, path } = req.body || {};

    if (!password || !path) {
      return res.status(400).json({
        error: '필수 값이 없습니다.'
      });
    }

    const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!serviceKey) {
      return res.status(500).json({
        error: 'Vercel의 SUPABASE_SERVICE_ROLE_KEY 환경변수가 설정되지 않았습니다.'
      });
    }

    const anon = createClient(
      SUPABASE_URL,
      SUPABASE_PUBLISHABLE_KEY,
      {
        auth: {
          persistSession: false
        }
      }
    );

    const {
      data: ok,
      error: verifyError
    } = await anon.rpc(
      'verify_parent_meeting_admin',
      {
        p_password: password
      }
    );

    if (verifyError) {
      throw verifyError;
    }

    if (!ok) {
      return res.status(401).json({
        error: '관리자 비밀번호가 올바르지 않습니다.'
      });
    }

    const admin = createClient(
      SUPABASE_URL,
      serviceKey,
      {
        auth: {
          persistSession: false
        }
      }
    );

    if (action === 'upload') {
      const {
        data,
        error
      } = await admin.storage
        .from(BUCKET)
        .createSignedUploadUrl(path);

      if (error) {
        throw error;
      }

      return res.status(200).json({
        path: data.path,
        token: data.token
      });
    }

    if (action === 'delete') {
      const { error } = await admin.storage
        .from(BUCKET)
        .remove([path]);

      if (error) {
        throw error;
      }

      return res.status(200).json({
        ok: true
      });
    }

    return res.status(400).json({
      error: '지원하지 않는 작업입니다.'
    });

  } catch (e) {
    console.error(e);

    return res.status(500).json({
      error: e?.message || String(e)
    });
  }
}
