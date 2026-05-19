/**
 * storage.js
 */

// --- 내부 헬퍼: 현재 로그인한 유저 ID 가져오기 ---
async function getUserId() {
  if (!window.supabase) return null
  const {
    data: { user },
  } = await window.supabase.auth.getUser()
  return user?.id || null
}

async function recordHash(hash, domain) {
  const userId = await getUserId()
  if (!userId || !hash || !domain) return

  // .upsert()를 사용하여 중복 조건(user_id, hash, domain) 발생 시 업데이트만 수행합니다.
  const { error } = await window.supabase.from('password_analytics').upsert(
    {
      user_id: userId,
      password_hash: hash,
      domain: domain,
      last_seen: new Date().toISOString(), // 마지막 확인 시간 갱신
    },
    {
      // 중복 판정의 기준이 되는 컬럼들을 지정합니다.
      onConflict: 'user_id, password_hash, domain',
    },
  )

  if (error) {
    console.error('[PwGuard] Supabase 기록 오류:', error.message)
  }
}

async function checkReuse(hash, currentDomain) {
  const userId = await getUserId()
  if (!userId || !hash) {
    return { isReused: false, otherSites: [], reuseCount: 0, daysSinceFirst: 0 }
  }

  const { data, error } = await window.supabase
    .from('password_analytics')
    .select('domain, first_seen')
    .eq('user_id', userId)
    .eq('password_hash', hash)

  if (error || !data || data.length === 0) {
    return { isReused: false, otherSites: [], reuseCount: 0, daysSinceFirst: 0 }
  }

  const otherSites = data
    .filter((s) => s.domain !== currentDomain)
    .map((s) => s.domain)

  const allFirstSeen = data.map((s) => new Date(s.first_seen).getTime())
  const earliest = Math.min(...allFirstSeen)
  const daysSinceFirst = Math.floor(
    (Date.now() - earliest) / (1000 * 60 * 60 * 24),
  )

  return {
    isReused: otherSites.length > 0,
    otherSites,
    reuseCount: otherSites.length,
    daysSinceFirst,
  }
}

async function getDaysUsedOnSite(hash, currentDomain) {
  const userId = await getUserId()
  if (!userId || !hash || !currentDomain) return 0

  const { data, error } = await window.supabase
    .from('password_analytics')
    .select('first_seen')
    .eq('user_id', userId)
    .eq('password_hash', hash)
    .eq('domain', currentDomain)

  if (error || !data || data.length === 0) return 0

  const firstSeen = new Date(data[0].first_seen).getTime()
  return Math.floor((Date.now() - firstSeen) / (1000 * 60 * 60 * 24))
}

const { error } = await window.supabase.from('password_analytics').upsert(
  {
    user_id: userId,
    password_hash: hash,
    domain: domain,
    last_seen: new Date().toISOString(),
  },
  {
    // 위에서 SQL로 설정한 기준 컬럼들과 정확히 일치해야 합니다.
    onConflict: 'user_id, password_hash, domain',
  },
)